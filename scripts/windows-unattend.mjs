#!/usr/bin/env node
import { randomBytes } from "node:crypto";
import { link, lstat, open, readFile, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { inspectWindowsVmRoot } from "./windows-vm.mjs";
const USER = /^[A-Za-z][A-Za-z0-9_-]{0,19}$/;
const KEY = /^ssh-(ed25519|rsa) [A-Za-z0-9+/=]{32,8192}(?: [^\r\n]{1,128})?$/;
function fail(message) { throw new Error(message); }
function xml(value) { return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&apos;"); }
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
  if ((xmlTemplate.match(/__ACCOUNT_XML__/g) || []).length !== 2 || (xmlTemplate.match(/__PASSWORD_XML__/g) || []).length !== 2 || (psTemplate.match(/__SSH_PUBLIC_KEY_BASE64__/g) || []).length !== 1) fail("Windows unattended templates do not have the reviewed placeholder shape.");
  const answer = xmlTemplate.replaceAll("__ACCOUNT_XML__", xml(input.account)).replaceAll("__PASSWORD_XML__", xml(input.password));
  const provision = psTemplate.replace("__SSH_PUBLIC_KEY_BASE64__", Buffer.from(input.sshPublicKey, "utf8").toString("base64"));
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
