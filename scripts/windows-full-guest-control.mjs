#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { createReadStream } from "node:fs";
import { chmod, lstat, mkdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import path from "node:path";

const IDENTITY_KEYS = new Set([
  "schemaVersion", "kind", "ownedRoot", "exeCommit", "exeSha256",
  "retainedImagePath", "retainedImageSha256", "sshKeygenPath", "sshKeygenSha256",
]);
const COMMANDS = new Set(["ready", "inventory", "install", "reinstall", "receipt", "shutdown"]);
const MATERIAL_NAMES = Object.freeze([
  "client", "client.pub", "host", "host.pub", "authorized_keys", "sshd_config",
  "opemos-full-control", "identity.json",
]);

function fail(message) { throw new Error(message); }
function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== expected.size || Object.keys(value).some(key => !expected.has(key))) {
    fail(`${label} fields are not closed.`);
  }
}
async function sha256(file) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}
async function realFile(file, label) {
  const info = await lstat(file);
  if (info.isSymbolicLink() || !info.isFile()) fail(`${label} must be a real file.`);
  return realpath(file);
}
async function realDirectory(directory, label) {
  const info = await lstat(directory);
  if (info.isSymbolicLink() || !info.isDirectory()) fail(`${label} must be a real directory.`);
  return realpath(directory);
}
function inside(root, value, label) {
  const relative = path.relative(root, value);
  if (!relative || relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    fail(`${label} must be beneath the exact owned full-run root.`);
  }
}
function validateDigest(value, label) {
  if (!/^[0-9a-f]{64}$/.test(value || "")) fail(`${label} must be an exact SHA-256 digest.`);
}
function validateCommit(value) {
  if (!/^[0-9a-f]{40}$/.test(value || "")) fail("EXE commit must be an exact immutable commit.");
}
function run(executable, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { shell: false, windowsHide: true, stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", chunk => { if (stderr.length < 8192) stderr += chunk; });
    child.once("error", reject);
    child.once("exit", code => code === 0 ? resolve() : reject(new Error(`Ephemeral key generation exited ${code}: ${stderr.trim()}`)));
  });
}

export function restrictedQemuNetworkArguments(port) {
  if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) fail("Guest-control forwarded port is invalid.");
  return [
    "-netdev", `user,id=opemos-full-control,restrict=on,hostfwd=tcp:127.0.0.1:${port}-:22`,
    "-device", "virtio-net-pci,netdev=opemos-full-control",
  ];
}

function controller() {
  return `#!/bin/sh
set -eu
case \"\${SSH_ORIGINAL_COMMAND-}\" in
  ready) printf '%s\\n' OPEMOS_FULL_READY ;;
  inventory) exec /usr/lib/opemos-full-test/inventory ;;
  install) exec /usr/lib/opemos-full-test/install ;;
  reinstall) exec /usr/lib/opemos-full-test/reinstall ;;
  receipt) exec /usr/lib/opemos-full-test/receipt ;;
  shutdown) exec /usr/lib/opemos-full-test/shutdown ;;
  *) printf '%s\\n' 'Refused command.' >&2; exit 64 ;;
esac
`;
}

export async function prepareEphemeralGuestControl(identity) {
  exactKeys(identity, IDENTITY_KEYS, "Guest-control identity");
  if (identity.schemaVersion !== 1 || identity.kind !== "opemos-full-ephemeral-guest-control") {
    fail("Guest-control identity is invalid.");
  }
  validateCommit(identity.exeCommit);
  validateDigest(identity.exeSha256, "EXE identity");
  validateDigest(identity.retainedImageSha256, "Retained-image identity");
  validateDigest(identity.sshKeygenSha256, "ssh-keygen identity");
  const root = await realDirectory(path.resolve(identity.ownedRoot), "Owned full-run root");
  const retained = await realFile(identity.retainedImagePath, "Retained virtual-USB image");
  const keygen = await realFile(identity.sshKeygenPath, "Bundled ssh-keygen");
  inside(root, retained, "Retained virtual-USB image");
  inside(root, keygen, "Bundled ssh-keygen");
  if (await sha256(retained) !== identity.retainedImageSha256) fail("Retained virtual-USB image identity changed.");
  if (await sha256(keygen) !== identity.sshKeygenSha256) fail("Bundled ssh-keygen identity changed.");

  const material = path.join(root, "ephemeral-guest-control");
  try { await mkdir(material, { mode: 0o700 }); }
  catch (error) {
    if (error?.code === "EEXIST") fail("Ephemeral guest-control material already exists; refusing credential reuse.");
    throw error;
  }
  const client = path.join(material, "client");
  const host = path.join(material, "host");
  try {
    await run(keygen, ["-q", "-t", "ed25519", "-N", "", "-C", `opemos-full-${identity.exeCommit}`, "-f", client]);
    await run(keygen, ["-q", "-t", "ed25519", "-N", "", "-C", `opemos-full-host-${identity.exeCommit}`, "-f", host]);
    const publicKey = (await readFile(`${client}.pub`, "utf8")).trim();
    if (!/^ssh-ed25519 [A-Za-z0-9+/]+={0,2} opemos-full-[0-9a-f]{40}$/.test(publicKey)) fail("Generated client public key is malformed.");
    const forced = 'restrict,command="/usr/lib/opemos-full-test/opemos-full-control"';
    await writeFile(path.join(material, "authorized_keys"), `${forced} ${publicKey}\n`, { mode: 0o600, flag: "wx" });
    await writeFile(path.join(material, "opemos-full-control"), controller(), { mode: 0o700, flag: "wx" });
    await writeFile(path.join(material, "sshd_config"), [
      "PasswordAuthentication no", "PermitRootLogin no", "PermitTTY no",
      "AllowAgentForwarding no", "AllowTcpForwarding no", "X11Forwarding no",
      "PermitTunnel no", "GatewayPorts no", "AuthenticationMethods publickey",
      "AllowUsers opemos-full-test", "AuthorizedKeysFile /etc/ssh/opemos-full-authorized_keys",
      "HostKey /etc/ssh/opemos-full-host-key", "ForceCommand /usr/lib/opemos-full-test/opemos-full-control",
      "", ].join("\n"), { mode: 0o600, flag: "wx" });
    const recorded = { ...identity, ownedRoot: root, retainedImagePath: retained, sshKeygenPath: keygen };
    await writeFile(path.join(material, "identity.json"), `${JSON.stringify(recorded)}\n`, { mode: 0o600, flag: "wx" });
    for (const name of ["client", "host", "authorized_keys", "sshd_config", "identity.json"]) await chmod(path.join(material, name), 0o600);
    await chmod(path.join(material, "opemos-full-control"), 0o700);
    return { material, clientKey: client, hostPublicKey: `${host}.pub`,
      hostPublicKeySha256: await sha256(`${host}.pub`),
      injectionFiles: MATERIAL_NAMES.filter(name => name !== "client" && name !== "identity.json") };
  } catch (error) {
    await rm(material, { recursive: true, force: true });
    throw error;
  }
}

export async function verifyAndRemoveEphemeralGuestControl(identity, material) {
  exactKeys(identity, IDENTITY_KEYS, "Guest-control identity");
  if (identity.schemaVersion !== 1 || identity.kind !== "opemos-full-ephemeral-guest-control") {
    fail("Guest-control identity is invalid.");
  }
  const root = await realDirectory(path.resolve(identity.ownedRoot), "Owned full-run root");
  const canonicalMaterial = await realDirectory(material, "Ephemeral guest-control directory");
  inside(root, canonicalMaterial, "Ephemeral guest-control directory");
  if (canonicalMaterial !== path.join(root, "ephemeral-guest-control")) fail("Ephemeral guest-control directory identity changed.");
  const recorded = JSON.parse(await readFile(path.join(canonicalMaterial, "identity.json"), "utf8"));
  if (JSON.stringify(recorded) !== JSON.stringify({ ...identity, ownedRoot: root,
    retainedImagePath: await realFile(identity.retainedImagePath, "Retained virtual-USB image"),
    sshKeygenPath: await realFile(identity.sshKeygenPath, "Bundled ssh-keygen") })) fail("Ephemeral guest-control identity record changed.");
  if (await sha256(recorded.retainedImagePath) !== identity.retainedImageSha256) fail("Retained virtual-USB image changed during guest control.");
  await rm(canonicalMaterial, { recursive: true });
  try { await lstat(canonicalMaterial); fail("Ephemeral guest-control material survived cleanup."); }
  catch (error) { if (error?.code !== "ENOENT") throw error; }
  return { schemaVersion: 1, status: "passed", retainedImageSha256: identity.retainedImageSha256, credentialsRemoved: true };
}

export const allowedGuestControlCommands = Object.freeze([...COMMANDS]);
