#!/usr/bin/env node
import { createHash, randomBytes } from "node:crypto";
import { link, lstat, open, readFile, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { inspectWindowsVmRoot } from "./windows-vm.mjs";
const USER = /^[A-Za-z][A-Za-z0-9_-]{0,19}$/;
const KEY = /^ssh-(ed25519|rsa) [A-Za-z0-9+/=]{32,8192}(?: [^\r\n]{1,128})?$/;
function fail(message) { throw new Error(message); }
function xml(value) { return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&apos;"); }
function count(source, pattern) { return (source.match(pattern) || []).length; }
function validateDiskLayout(template) {
  const compact = template.replace(/>\s+</g, "><");
  if (count(compact, /<Disk(?:\s|>)/g) !== 1 || count(compact, /<\/Disk>/g) !== 1) fail("Windows unattended template must contain exactly one disk.");
  if (count(compact, /<CreatePartition(?:\s|>)/g) !== 3 || count(compact, /<\/CreatePartition>/g) !== 3) fail("Windows unattended template must contain exactly three create-partition entries.");
  if (count(compact, /<ModifyPartition(?:\s|>)/g) !== 2 || count(compact, /<\/ModifyPartition>/g) !== 2) fail("Windows unattended template must contain exactly two modify-partition entries.");
  const disk = compact.match(/<Disk wcm:action="add">.*?<\/Disk>/s)?.[0];
  const expected = /^<Disk wcm:action="add"><DiskID>0<\/DiskID><WillWipeDisk>true<\/WillWipeDisk><CreatePartitions><CreatePartition wcm:action="add"><Order>1<\/Order><Type>EFI<\/Type><Size>100<\/Size><\/CreatePartition><CreatePartition wcm:action="add"><Order>2<\/Order><Type>MSR<\/Type><Size>16<\/Size><\/CreatePartition><CreatePartition wcm:action="add"><Order>3<\/Order><Type>Primary<\/Type><Extend>true<\/Extend><\/CreatePartition><\/CreatePartitions><ModifyPartitions><ModifyPartition wcm:action="add"><Order>1<\/Order><PartitionID>1<\/PartitionID><Format>FAT32<\/Format><Label>System<\/Label><\/ModifyPartition><ModifyPartition wcm:action="add"><Order>2<\/Order><PartitionID>3<\/PartitionID><Format>NTFS<\/Format><Label>Windows<\/Label><Letter>C<\/Letter><\/ModifyPartition><\/ModifyPartitions><\/Disk>$/;
  if (!disk || !expected.test(disk)) fail("Windows unattended template disk layout does not match the reviewed disk 0 partition structure.");
  const install = "<InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo>";
  if (count(compact, /<InstallTo(?:\s|>)/g) !== 1 || count(compact, /<\/InstallTo>/g) !== 1 || !compact.includes(install)) fail("Windows unattended template must install exactly to disk 0 partition 3.");
}
async function privateRegular(file, label) {
  const info = await lstat(file, { bigint: true });
  if (info.isSymbolicLink() || !info.isFile() || info.uid !== BigInt(process.getuid()) || Number(info.mode & 0o777n) !== 0o600) fail(`${label} must be a current-user-owned regular file with mode 0600.`);
  if (info.size < 2n || info.size > 16384n) fail(`${label} has an invalid size.`);
}
async function exclusive(file, bytes) {
  const temporary = `${file}.partial-${randomBytes(8).toString("hex")}`;
  let handle;
  try {
    handle = await open(temporary, "wx", 0o600); await handle.writeFile(bytes); await handle.sync(); await handle.close(); handle = undefined;
    await link(temporary, file); await rm(temporary);
  } catch (error) { if (handle) await handle.close().catch(() => {}); await rm(temporary, { force: true }).catch(() => {}); throw error; }
}
export async function generateWindowsUnattend(root, inputFile, templatesRoot) {
  await inspectWindowsVmRoot(root); await privateRegular(inputFile, "Windows provisioning input");
  const input = JSON.parse(await readFile(inputFile, "utf8"));
  const keys = Object.keys(input || {}).sort().join("\n");
  if (keys !== ["account", "password", "sshPublicKey"].sort().join("\n")) fail("Windows provisioning input fields do not match schema 1.");
  if (!USER.test(input.account) || input.account.toLowerCase() === "administrator") fail("Windows test account is invalid.");
  if (typeof input.password !== "string" || input.password.length < 16 || input.password.length > 128 || /[\u0000-\u001f]/.test(input.password)) fail("Windows one-time password is invalid.");
  if (typeof input.sshPublicKey !== "string" || !KEY.test(input.sshPublicKey)) fail("Windows SSH public key is invalid.");
  const xmlTemplate = await readFile(path.join(templatesRoot, "autounattend.xml.template"), "utf8");
  const psTemplate = await readFile(path.join(templatesRoot, "provision.ps1.template"), "utf8");
  if ((xmlTemplate.match(/__ACCOUNT_XML__/g) || []).length !== 2 || (xmlTemplate.match(/__PASSWORD_XML__/g) || []).length !== 2 || (xmlTemplate.match(/__PROVISION_SHA256__/g) || []).length !== 1 || (psTemplate.match(/__SSH_PUBLIC_KEY_BASE64__/g) || []).length !== 1) fail("Windows unattended templates do not have the reviewed placeholder shape.");
  validateDiskLayout(xmlTemplate);
  const provision = psTemplate.replace("__SSH_PUBLIC_KEY_BASE64__", Buffer.from(input.sshPublicKey, "utf8").toString("base64"));
  const provisionSha256 = createHash("sha256").update(provision, "utf8").digest("hex");
  const answer = xmlTemplate.replaceAll("__ACCOUNT_XML__", xml(input.account)).replaceAll("__PASSWORD_XML__", xml(input.password)).replace("__PROVISION_SHA256__", provisionSha256);
  const generated = path.join(root, "generated");
  await exclusive(path.join(generated, "autounattend.xml"), answer);
  try { await exclusive(path.join(generated, "provision.ps1"), provision); } catch (error) { await rm(path.join(generated, "autounattend.xml"), { force: true }); throw error; }
  return { schemaVersion: 1, status: "generated", files: ["generated/autounattend.xml", "generated/provision.ps1"] };
}
function repositoryRoot() { return path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."); }
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 4 || process.argv[2] !== "generate") fail("Usage: scripts/windows-unattend.mjs generate INPUT.json");
    const repo = repositoryRoot(); process.stdout.write(JSON.stringify(await generateWindowsUnattend(path.join(repo, "local-inputs", "windows-vm"), path.resolve(process.argv[3]), path.join(repo, "templates", "windows")), null, 2) + "\n");
  } catch (error) { process.stderr.write(String(error?.message || error) + "\n"); process.exitCode = 1; }
}
