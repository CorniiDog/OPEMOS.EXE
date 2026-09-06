import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import test from "node:test";

const scriptUrl = new URL("../builder/appliance/build_linux.sh", import.meta.url);
const run = (...args) => execFileSync("bash", [scriptUrl.pathname, ...args], {
  encoding: "utf8",
  env: { PATH: process.env.PATH },
});

test("Linux appliance builder resolves pinned native and explicit architectures without downloads", () => {
  const native = JSON.parse(run("--resolve-only"));
  assert.equal(native.schemaVersion, 1);
  assert.equal(native.status, "ready");
  assert.equal(native.appliance.hostArchitecture, process.arch === "x64" ? "x86_64" : "aarch64");
  assert.equal(native.appliance.applianceArchitecture, native.appliance.hostArchitecture);
  assert.equal(native.appliance.fedoraRelease, "44");
  assert.equal(native.appliance.fedoraCompose, "1.7");
  assert.match(native.appliance.imageUrl, /^https:\/\/download\.fedoraproject\.org\//);
  assert.match(native.appliance.outputPath, /fedora-builder\.qcow2$/);

  const explicit = JSON.parse(run("--architecture", "x86_64", "--resolve-only"));
  assert.equal(explicit.appliance.applianceArchitecture, "x86_64");
  assert.match(explicit.appliance.outputPath, /fedora-builder-x86_64\.qcow2$/);
});

test("Linux appliance builder rejects malformed architecture and missing option values", () => {
  for (const args of [["--architecture", "amd64"], ["--architecture"], ["--output"], ["--unknown"]]) {
    const result = spawnSync("bash", [scriptUrl.pathname, ...args], {
      encoding: "utf8",
      env: { PATH: process.env.PATH },
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /ERROR:/);
  }
});

test("Linux appliance preparation requires authenticated checksums and atomic output replacement", async () => {
  const script = await readFile(scriptUrl, "utf8");
  assert.match(script, /command -v "\$tool"[\s\S]*Required tool not found/);
  assert.match(script, /gpgv[\s\S]*--keyring "\$GPG_PATH"[\s\S]*--output "\$VERIFIED_CHECKSUM"/);
  assert.match(script, /grep "\$IMAGE_NAME" "\$VERIFIED_CHECKSUM"[\s\S]*sha256sum -c -/);
  assert.doesNotMatch(script, /Falling back|without signature validation/);
  assert.match(script, /OUTPUT_TEMP="\$\{OUTPUT_IMAGE\}\.partial"[\s\S]*trap cleanup_partial_outputs EXIT/);
  assert.match(script, /qemu-img check "\$OUTPUT_TEMP"[\s\S]*mv "\$OUTPUT_TEMP" "\$OUTPUT_IMAGE"[\s\S]*mv "\$METADATA_TEMP" "\$METADATA_PATH"/);
  assert.match(script, /"checksumSignatureVerified": signature_verified == "1"/);
});
