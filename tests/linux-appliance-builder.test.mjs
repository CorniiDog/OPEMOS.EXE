import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, cp, mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
  assert.match(script, /gpgv[\s\S]*CHECKSUM_LINE_PREFIX[\s\S]*EXPECTED_IMAGE_SHA256/);
  assert.doesNotMatch(script, /Falling back|without signature validation/);
  assert.match(script, /OUTPUT_TEMP="\$\{OUTPUT_IMAGE\}\.partial"[\s\S]*trap cleanup_partial_outputs EXIT/);
  assert.match(script, /qemu-img check "\$OUTPUT_TEMP"[\s\S]*mv "\$OUTPUT_TEMP" "\$OUTPUT_IMAGE"[\s\S]*mv "\$METADATA_TEMP" "\$METADATA_PATH"/);
  assert.match(script, /"checksumSignatureVerified": signature_verified == "1"/);
});


const prepareFakeEnvironment = async (imageBytes) => {
  const root = await mkdtemp(join(tmpdir(), "opemos-linux-appliance-cache-"));
  const applianceDir = join(root, "builder", "appliance");
  const fakeBin = join(root, "bin");
  const fixtures = join(root, "fixtures");
  await mkdir(applianceDir, { recursive: true });
  await mkdir(fakeBin);
  await mkdir(fixtures);
  await cp(scriptUrl, join(applianceDir, "build_linux.sh"));
  const image = join(fixtures, "image.qcow2");
  const checksum = join(fixtures, "checksum");
  const keyring = join(fixtures, "fedora.gpg");
  const digest = createHash("sha256").update(imageBytes).digest("hex");
  await writeFile(image, imageBytes);
  await writeFile(checksum, `SHA256 (Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2) = ${digest}\n`);
  await writeFile(keyring, "bounded test keyring\n");
  const tools = {
    uname: `#!/bin/sh\n[ "$1" = "-s" ] && echo Linux || echo x86_64\n`,
    curl: `#!/bin/sh\nout=\nurl=\nwhile [ "$#" -gt 0 ]; do\n  case "$1" in\n    --output) out=$2; shift 2 ;;\n    --fail|--location|--progress-bar|--silent|--show-error) shift ;;\n    *) url=$1; shift ;;\n  esac\ndone\ncase "$url" in\n  *-CHECKSUM) cp "$FIXTURE_CHECKSUM" "$out" ;;\n  *fedora.gpg) cp "$FIXTURE_KEYRING" "$out" ;;\n  *.qcow2) cp "$FIXTURE_IMAGE" "$out" ;;\n  *) exit 91 ;;\nesac\n`,
    gpgv: `#!/bin/sh\nout=\ninput=\nwhile [ "$#" -gt 0 ]; do\n  case "$1" in\n    --keyring) shift 2 ;;\n    --output) out=$2; shift 2 ;;\n    *) input=$1; shift ;;\n  esac\ndone\ncp "$input" "$out"\n`,
    "qemu-img": "#!/bin/sh\n[ \"$1\" = check ]\n",
  };
  await Promise.all(Object.entries(tools).map(async ([name, body]) => {
    const path = join(fakeBin, name);
    await writeFile(path, body);
    await chmod(path, 0o755);
  }));
  return {
    root,
    applianceDir,
    image,
    checksum,
    keyring,
    digest,
    env: {
      ...process.env,
      PATH: `${fakeBin}:/usr/bin:/bin`,
      FIXTURE_IMAGE: image,
      FIXTURE_CHECKSUM: checksum,
      FIXTURE_KEYRING: keyring,
    },
  };
};

test("corrupt cached appliance is replaced only after authenticated verification", async () => {
  const fixture = await prepareFakeEnvironment(Buffer.from("authenticated Fedora image\n"));
  const cache = join(fixture.applianceDir, "work", "Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2");
  const output = join(fixture.root, "result.qcow2");
  await mkdir(join(fixture.applianceDir, "work"));
  await writeFile(cache, "corrupt cache\n");
  const result = spawnSync("bash", [join(fixture.applianceDir, "build_linux.sh"), "--output", output], {
    encoding: "utf8",
    env: fixture.env,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Cached Fedora Cloud image is invalid; downloading an authenticated replacement/);
  assert.deepEqual(await readFile(cache), await readFile(fixture.image));
  assert.deepEqual(await readFile(output), await readFile(fixture.image));
  const metadata = JSON.parse(await readFile(`${output}.metadata.json`, "utf8"));
  assert.equal(metadata.fedora.imageSha256, fixture.digest);
  assert.equal(metadata.fedora.checksumSignatureVerified, true);
});

test("failed authenticated replacement preserves the prior corrupt cache", async () => {
  const fixture = await prepareFakeEnvironment(Buffer.from("downloaded but unauthenticated\n"));
  await writeFile(
    fixture.checksum,
    `SHA256 (Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2) = ${"0".repeat(64)}\n`,
  );
  const work = join(fixture.applianceDir, "work");
  const cache = join(work, "Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2");
  const output = join(fixture.root, "result.qcow2");
  const original = Buffer.from("preserve this corrupt cache\n");
  await mkdir(work);
  await writeFile(cache, original);
  const result = spawnSync("bash", [join(fixture.applianceDir, "build_linux.sh"), "--output", output], {
    encoding: "utf8",
    env: fixture.env,
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /did not match the signed checksum/);
  assert.deepEqual(await readFile(cache), original);
  await assert.rejects(readFile(`${cache}.download.partial`));
  await assert.rejects(readFile(output));
});


test("termination during authenticated replacement download preserves cache and removes partial bytes", async () => {
  const fixture = await prepareFakeEnvironment(Buffer.from("replacement image\n"));
  const work = join(fixture.applianceDir, "work");
  const cache = join(work, "Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2");
  const partial = `${cache}.download.partial`;
  const marker = join(fixture.root, "download-started");
  const original = Buffer.from("existing corrupt cache\n");
  await mkdir(work);
  await writeFile(cache, original);
  const curlPath = join(fixture.root, "bin", "curl");
  await writeFile(curlPath, `#!/bin/sh
out=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) out=$2; shift 2 ;;
    --fail|--location|--progress-bar|--silent|--show-error) shift ;;
    *) url=$1; shift ;;
  esac
done
case "$url" in
  *-CHECKSUM) cp "$FIXTURE_CHECKSUM" "$out" ;;
  *fedora.gpg) cp "$FIXTURE_KEYRING" "$out" ;;
  *.qcow2)
    printf partial > "$out"
    : > "$DOWNLOAD_STARTED_MARKER"
    sleep 30
    ;;
  *) exit 91 ;;
esac
`);
  await chmod(curlPath, 0o755);
  const child = spawn("bash", [join(fixture.applianceDir, "build_linux.sh")], {
    detached: true,
    env: { ...fixture.env, DOWNLOAD_STARTED_MARKER: marker },
    stdio: "ignore",
  });
  const deadline = Date.now() + 5000;
  while (true) {
    try {
      await readFile(marker);
      break;
    } catch (error) {
      if (error.code !== "ENOENT" || Date.now() >= deadline) throw error;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
  }
  process.kill(-child.pid, "SIGTERM");
  const status = await new Promise((resolve) => child.once("close", (code, signal) => resolve({ code, signal })));
  assert.notEqual(status.code, 0);
  assert.deepEqual(await readFile(cache), original);
  await assert.rejects(readFile(partial));
});

test("failed replacement download preserves cache and removes partial bytes", async () => {
  const fixture = await prepareFakeEnvironment(Buffer.from("unused replacement\n"));
  const work = join(fixture.applianceDir, "work");
  const cache = join(work, "Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2");
  const original = Buffer.from("existing corrupt cache\n");
  await mkdir(work);
  await writeFile(cache, original);
  const curlPath = join(fixture.root, "bin", "curl");
  await writeFile(curlPath, `#!/bin/sh
out=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) out=$2; shift 2 ;;
    --fail|--location|--progress-bar|--silent|--show-error) shift ;;
    *) url=$1; shift ;;
  esac
done
case "$url" in
  *-CHECKSUM) cp "$FIXTURE_CHECKSUM" "$out" ;;
  *fedora.gpg) cp "$FIXTURE_KEYRING" "$out" ;;
  *.qcow2) printf partial > "$out"; exit 22 ;;
  *) exit 91 ;;
esac
`);
  await chmod(curlPath, 0o755);
  const result = spawnSync("bash", [join(fixture.applianceDir, "build_linux.sh")], {
    encoding: "utf8",
    env: fixture.env,
  });
  assert.notEqual(result.status, 0);
  assert.deepEqual(await readFile(cache), original);
  await assert.rejects(readFile(`${cache}.download.partial`));
});
