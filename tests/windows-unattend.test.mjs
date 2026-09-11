import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { initializeWindowsVmRoot } from "../scripts/windows-vm.mjs";
import { generateWindowsUnattend } from "../scripts/windows-unattend.mjs";
const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const templates = path.join(repo, "templates", "windows");
const valid = { account: "opemostest", password: "local-onetime-A9!", sshPublicKey: `ssh-ed25519 ${Buffer.alloc(32, 7).toString("base64")} opemos-test` };
async function fixture() { const parent = await mkdtemp(path.join(os.tmpdir(), "opemos-unattend-")); const root = path.join(parent, "windows-vm"); await initializeWindowsVmRoot(root); const input = path.join(root, "runtime", "provision-input.json"); await writeFile(input, JSON.stringify(valid), { mode: 0o600 }); return { parent, root, input }; }
test("unattend generation injects local secret and public key only into ignored private output", async () => {
  const f = await fixture();
  try {
    const result = await generateWindowsUnattend(f.root, f.input, templates); assert.equal(result.status, "generated");
    const answer = await readFile(path.join(f.root, "generated", "autounattend.xml"), "utf8");
    const provision = await readFile(path.join(f.root, "generated", "provision.ps1"), "utf8");
    assert.match(answer, /<LogonCount>1<\/LogonCount>/); assert.equal((answer.match(/local-onetime-A9!/g) || []).length, 2);
    assert.match(answer, /<settings pass="windowsPE">/);
    assert.match(answer, /<DiskID>0<\/DiskID><WillWipeDisk>true<\/WillWipeDisk>/);
    assert.match(answer, /<Type>EFI<\/Type><Size>100<\/Size>/);
    assert.match(answer, /<Type>MSR<\/Type><Size>16<\/Size>/);
    assert.match(answer, /<Type>Primary<\/Type><Extend>true<\/Extend>/);
    assert.match(answer, /<PartitionID>1<\/PartitionID><Format>FAT32<\/Format>/);
    assert.match(answer, /<PartitionID>3<\/PartitionID><Format>NTFS<\/Format>/);
    assert.match(answer, /<InstallTo><DiskID>0<\/DiskID><PartitionID>3<\/PartitionID><\/InstallTo>/);
    assert.equal((answer.match(/<DiskID>0<\/DiskID>/g) || []).length, 2);
    assert.equal((answer.match(/<WillWipeDisk>true<\/WillWipeDisk>/g) || []).length, 1);
    assert.doesNotMatch(answer, /<DiskID>[1-9]/);
    assert.doesNotMatch(provision, /local-onetime-A9!/); assert.match(provision, /PasswordAuthentication no/);
    const provisionSha256 = createHash("sha256").update(provision, "utf8").digest("hex");
    assert.match(answer, new RegExp(provisionSha256)); assert.doesNotMatch(answer, /__PROVISION_SHA256__/);
    assert.match(provision, new RegExp(Buffer.from(valid.sshPublicKey).toString("base64")));
    assert.doesNotMatch(await readFile(path.join(templates, "autounattend.xml.template"), "utf8"), /local-onetime-A9!/);
  } finally { await rm(f.parent, { recursive: true, force: true }); }
});
test("unattend generation rejects unsafe inputs before output", async () => {
  for (const patch of [{ account: "Administrator" }, { password: "short" }, { sshPublicKey: "ssh-ed25519 bad" }, { extra: true }]) {
    const f = await fixture();
    try { await writeFile(f.input, JSON.stringify({ ...valid, ...patch }), { mode: 0o600 }); await assert.rejects(generateWindowsUnattend(f.root, f.input, templates)); await assert.rejects(readFile(path.join(f.root, "generated", "autounattend.xml"))); }
    finally { await rm(f.parent, { recursive: true, force: true }); }
  }
});
test("unattend generation is create-only and cleans its own partial pair", async () => {
  const f = await fixture();
  try {
    await writeFile(path.join(f.root, "generated", "provision.ps1"), "existing", { mode: 0o600 });
    await assert.rejects(generateWindowsUnattend(f.root, f.input, templates), /EEXIST/);
    await assert.rejects(readFile(path.join(f.root, "generated", "autounattend.xml")));
    assert.equal(await readFile(path.join(f.root, "generated", "provision.ps1"), "utf8"), "existing");
    await chmod(f.input, 0o644); await assert.rejects(generateWindowsUnattend(f.root, f.input, templates), /mode 0600/);
  } finally { await rm(f.parent, { recursive: true, force: true }); }
});
test("reviewed provisioning template preserves security and SSH safety controls", async () => {
  const script = await readFile(path.join(templates, "provision.ps1.template"), "utf8");
  for (const required of ["OpenSSH.Server~~~~0.0.1.0", "StartupType Automatic", "PasswordAuthentication no", "administrators_authorized_keys", "provisioned-v1.json"]) assert.match(script, new RegExp(required.replaceAll("~", "\\~")));
  assert.doesNotMatch(script, /0\.0\.0\.0|Remove-WindowsCapability|Disable-WindowsOptionalFeature|Set-MpPreference/);
});
