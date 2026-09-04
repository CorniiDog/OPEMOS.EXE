import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const script = fileURLToPath(new URL('../scripts/check_linux_host.sh', import.meta.url));
const binaries = ['qemu-system-x86_64', 'qemu-img', 'genisoimage', 'ssh', 'ssh-keygen', 'python3'];
function fixture(t, options = {}) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'opemos-linux-doctor-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const bin = path.join(root, 'bin with spaces');
  const firmware = path.join(root, 'firmware with spaces');
  mkdirSync(bin); mkdirSync(firmware);
  for (const binary of binaries.filter(name => name !== options.missing)) {
    // Any accidental execution fails; doctor must only inspect commands.
    writeFileSync(path.join(bin, binary), '#!/bin/sh\nexit 99\n', { mode: 0o700 });
  }
  writeFileSync(path.join(root, 'os-release'), options.release ?? 'ID="ubuntu"\nVERSION_ID="24.04"\n');
  for (const name of options.firmware ?? ['OVMF_CODE_4M.fd', 'OVMF_VARS_4M.fd']) {
    writeFileSync(path.join(firmware, name), 'fixture');
  }
  return (overrides = {}) => spawnSync('/bin/bash', [script], {
    encoding: 'utf8', timeout: 2000,
    env: { PATH: bin, OPEMOS_DOCTOR_OS_RELEASE: path.join(root, 'os-release'),
      OPEMOS_DOCTOR_FIRMWARE_ROOT: firmware, OPEMOS_DOCTOR_ARCH: 'x86_64',
      OPEMOS_EXPERIMENTAL_LINUX: '1', OPEMOS_LINUX_ACCEL: 'tcg', ...overrides },
  });
}
test('doctor inventories explicit TCG without executing tools or promising readiness', t => {
  const result = fixture(t)();
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /matched firmware pair:.*OVMF_CODE_4M.fd/);
  assert.match(result.stdout, /usability|runtime checks/);
  assert.match(result.stdout, /Physical USB writing is unsupported/);
});
test('doctor accepts Debian and a complete legacy firmware pair', t => {
  const result = fixture(t, { release: 'ID=debian\nVERSION_ID="12"\n',
    firmware: ['OVMF_CODE.fd', 'OVMF_VARS.fd'] })();
  assert.equal(result.status, 0);
  assert.match(result.stdout, /Host: debian 12/);
});
test('doctor rejects missing tools and mixed firmware generations', t => {
  const result = fixture(t, { missing: 'qemu-img', firmware: ['OVMF_CODE_4M.fd', 'OVMF_VARS.fd'] })();
  assert.equal(result.status, 1);
  assert.match(result.stdout, /MISSING: qemu-img/);
  assert.match(result.stdout, /matched OVMF/);
});
test('doctor rejects absent opt-in, unsupported architecture and invalid accelerator', t => {
  const result = fixture(t)({ OPEMOS_EXPERIMENTAL_LINUX: '', OPEMOS_DOCTOR_ARCH: 'aarch64', OPEMOS_LINUX_ACCEL: 'auto' });
  assert.equal(result.status, 1);
  assert.match(result.stdout, /opt in explicitly/);
  assert.match(result.stdout, /Only Ubuntu\/Debian x86_64/);
  assert.match(result.stdout, /no automatic fallback/);
});
test('doctor treats os-release as data and never accepts an ID_LIKE substitute', t => {
  const result = fixture(t, { release: 'ID=other\nID_LIKE=ubuntu\nVERSION_ID="$(exit 91)"\n' })();
  assert.equal(result.status, 1);
  assert.match(result.stdout, /\$\(exit 91\)/);
  assert.match(result.stdout, /Only Ubuntu\/Debian x86_64/);
});
test('KVM diagnostics never equate access with usability', t => {
  const result = fixture(t)({ OPEMOS_LINUX_ACCEL: 'kvm' });
  assert.ok([0, 1].includes(result.status));
  assert.match(result.stdout, /usability is NOT verified|KVM device access unavailable/);
});

test('doctor rejects duplicate distribution IDs even when both are allowed', t => {
  const result = fixture(t, { release: 'ID=ubuntu\nID=debian\n' })();
  assert.equal(result.status, 1);
  assert.match(result.stderr, /duplicate ID/);
});
test('doctor rejects oversized and invalid UTF-8 distribution files', t => {
  const oversized = fixture(t, { release: 'ID=ubuntu\n#' + 'x'.repeat(65536) })();
  assert.equal(oversized.status, 1);
  assert.match(oversized.stderr, /exceeds 65536 bytes/);
  const invalid = fixture(t, { release: Buffer.concat([Buffer.from('ID=ubuntu\n#'), Buffer.from([0xff])]) })();
  assert.equal(invalid.status, 1);
  assert.match(invalid.stdout, /bounded UTF-8 os-release/);
});
test('doctor accepts the size boundary and a final line without a newline', t => {
  const prefix = 'ID=ubuntu\n#';
  const result = fixture(t, { release: prefix + 'x'.repeat(65536 - Buffer.byteLength(prefix)) })();
  assert.equal(result.status, 0, result.stderr);
  const finalLine = fixture(t, { release: 'VERSION_ID=24.04\nID=ubuntu' })();
  assert.equal(finalLine.status, 0, finalLine.stderr);
});
