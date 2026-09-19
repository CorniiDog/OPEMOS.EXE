import test from "node:test";
import assert from "node:assert/strict";
import { chmod, lstat, mkdir, mkdtemp, readFile, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import {
  allowedGuestControlCommands, prepareEphemeralGuestControl,
  restrictedQemuNetworkArguments, verifyAndRemoveEphemeralGuestControl,
} from "../scripts/windows-full-guest-control.mjs";

const digest = bytes => createHash("sha256").update(bytes).digest("hex");
async function fixture() {
  const root = await mkdtemp(path.join(tmpdir(), "opemos-full-control-"));
  const image = path.join(root, "virtual-usb-32g.raw"); await writeFile(image, "retained-image");
  const bin = path.join(root, "runtime"); await mkdir(bin);
  const keygen = path.join(bin, "ssh-keygen");
  await writeFile(keygen, `#!/bin/sh
set -eu
out=
while [ "$#" -gt 0 ]; do if [ "$1" = -f ]; then out=$2; shift 2; else shift; fi; done
printf '%s' private > "$out"
printf '%s\\n' 'ssh-ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= opemos-full-${"b".repeat(40)}' > "$out.pub"
`, { mode: 0o700 }); await chmod(keygen, 0o700);
  const identity = { schemaVersion: 1, kind: "opemos-full-ephemeral-guest-control", ownedRoot: root,
    exeCommit: "b".repeat(40), exeSha256: "c".repeat(64), retainedImagePath: image,
    retainedImageSha256: digest("retained-image"), sshKeygenPath: keygen,
    sshKeygenSha256: digest(await readFile(keygen)) };
  return { root, image, keygen, identity };
}

test("generates fresh forced-command-only material and removes it after an unchanged image proof", async () => {
  const { identity, image } = await fixture();
  const prepared = await prepareEphemeralGuestControl(identity);
  assert.equal(prepared.hostPublicKeySha256, digest(await readFile(prepared.hostPublicKey)));
  const authorized = await readFile(path.join(prepared.material, "authorized_keys"), "utf8");
  assert.match(authorized, /^restrict,command="\/usr\/lib\/opemos-full-test\/opemos-full-control" ssh-ed25519 /);
  const controller = await readFile(path.join(prepared.material, "opemos-full-control"), "utf8");
  for (const command of allowedGuestControlCommands) assert.ok(controller.includes(`  ${command})`));
  assert.match(controller, /Refused command/);
  const sshd = await readFile(path.join(prepared.material, "sshd_config"), "utf8");
  for (const line of ["PasswordAuthentication no", "PermitRootLogin no", "PermitTTY no", "AllowAgentForwarding no", "AllowTcpForwarding no", "X11Forwarding no", "GatewayPorts no"]) assert.ok(sshd.includes(line));
  const result = await verifyAndRemoveEphemeralGuestControl(identity, prepared.material);
  assert.deepEqual(result, { schemaVersion: 1, status: "passed", retainedImageSha256: identity.retainedImageSha256, credentialsRemoved: true });
  await assert.rejects(lstat(prepared.material), { code: "ENOENT" });
  assert.equal(digest(await readFile(image)), identity.retainedImageSha256);
});

test("QEMU networking is loopback-only and outbound-restricted", () => {
  const args = restrictedQemuNetworkArguments(22022);
  assert.deepEqual(args, ["-netdev", "user,id=opemos-full-control,restrict=on,hostfwd=tcp:127.0.0.1:22022-:22", "-device", "virtio-net-pci,netdev=opemos-full-control"]);
  assert.doesNotMatch(args.join(" "), /bridge|tap|0\.0\.0\.0|hostfwd=tcp::/);
  for (const value of [22, 0, 65536, 22022.5]) assert.throws(() => restrictedQemuNetworkArguments(value), /invalid/);
});

test("refuses credential reuse and retained-image identity drift", async () => {
  const { identity, image } = await fixture();
  const prepared = await prepareEphemeralGuestControl(identity);
  await assert.rejects(prepareEphemeralGuestControl(identity), /refusing credential reuse/);
  await writeFile(image, "changed");
  await assert.rejects(verifyAndRemoveEphemeralGuestControl(identity, prepared.material), /changed during guest control/);
  assert.ok((await lstat(prepared.material)).isDirectory(), "failed proof must preserve evidence");
});

test("refuses redirected retained media before generating credentials", async () => {
  const { root, identity } = await fixture();
  const outside = await mkdtemp(path.join(tmpdir(), "opemos-full-control-outside-"));
  await writeFile(path.join(outside, "image.raw"), "retained-image");
  const redirect = path.join(root, "redirect"); await symlink(outside, redirect, "dir");
  identity.retainedImagePath = path.join(redirect, "image.raw");
  await assert.rejects(prepareEphemeralGuestControl(identity), /beneath the exact owned/);
  await assert.rejects(lstat(path.join(root, "ephemeral-guest-control")), { code: "ENOENT" });
});
