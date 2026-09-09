import test from 'node:test';
import assert from 'node:assert/strict';
import { presentHostEnvironment } from '../src/host-status.js';

test('Linux readiness is explicitly experimental and exposes unavailable USB writing', () => {
  const value = presentHostEnvironment({ host_os: 'linux', host_arch: 'x86_64', experimental: true, ready: true, acceleration: 'tcg' });
  assert.equal(value.ready, true);
  assert.equal(value.status, 'Experimental');
  assert.match(value.message, /Physical USB writing is unavailable/);
  assert.match(value.details, /tcg/);
});
test('Unsupported, unverified, or disabled hosts do not enable build controls', () => {
  for (const environment of [
    { host_os: 'linux', ready: true },
    { host_os: 'windows', host_arch: 'aarch64', ready: true },
    { host_os: 'linux', experimental: true, ready: 'true' },
    { host_os: 'linux', experimental: true, ready: false, message: 'KVM unavailable' },
  ]) assert.equal(presentHostEnvironment(environment).ready, false);
  assert.equal(presentHostEnvironment({ host_os: 'linux', experimental: true, ready: false, message: 'KVM unavailable' }).message, 'KVM unavailable');
});
test('macOS presentation retains its normal readiness and does not claim Linux status', () => {
  const value = presentHostEnvironment({ host_os: 'macos', ready: true, experimental: false });
  assert.equal(value.title, 'Ready to build');
  assert.equal(value.status, 'Available');
  assert.match(value.message, /start automatically/);
});

test('Windows x86_64 readiness reflects verified backend status', () => {
  const value = presentHostEnvironment({ host_os: 'windows', host_arch: 'x86_64', ready: true, acceleration: 'whpx', qemu_version: 'QEMU 10' });
  assert.equal(value.ready, true); assert.equal(value.title, 'Windows host ready'); assert.match(value.details, /windows · x86_64 · whpx/);
  const unavailable = presentHostEnvironment({ host_os: 'windows', host_arch: 'x86_64', ready: false, message: 'WHPX unavailable' });
  assert.equal(unavailable.ready, false); assert.equal(unavailable.title, 'Windows host unavailable'); assert.equal(unavailable.message, 'WHPX unavailable');
});
