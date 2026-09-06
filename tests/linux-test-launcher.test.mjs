import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { linuxTestEnvironment, linuxTestPlan } from "../scripts/linux-test.mjs";

const valid = { platform: "linux", arch: "x64", args: ["build"],
  env: { OPEMOS_EXPERIMENTAL_LINUX: "1", OPEMOS_LINUX_ACCEL: "tcg" } };

test("Linux test packaging is debug-only and needs no graphical session", () => {
  const args = linuxTestPlan(valid);
  assert.deepEqual(args.slice(0, 4), ["build", "--debug", "--bundles", "deb,appimage"]);
  assert.equal(args[4], "--config");
  assert.ok(args[5].endsWith("/src-tauri/tauri.linux-test.conf.json"));
  assert.deepEqual(linuxTestPlan({ ...valid, env: { ...valid.env, OPEMOS_LINUX_ACCEL: "kvm" } }), args);
});

test("Debian 12 packaging selects only the pinned Debian dependency config", () => {
  const args = linuxTestPlan({ ...valid, args: ["build-debian12"] });
  assert.deepEqual(args.slice(0, 4), ["build", "--debug", "--bundles", "deb,appimage"]);
  assert.ok(args[5].endsWith("/src-tauri/tauri.linux-debian12-test.conf.json"));
});

test("Linux launcher rejects unsupported hosts, implicit opt-ins and CLI overrides", () => {
  for (const changes of [{ platform: "darwin" }, { platform: "win32" }, { arch: "arm64" },
    { args: [] }, { args: ["build", "--release"] }, { args: ["dev", "--config", "other.json"] },
    { args: ["bundle"] }, { args: ["build-debian13"] }]) {
    assert.throws(() => linuxTestPlan({ ...valid, ...changes }));
  }
  for (const optin of [undefined, "", "true", "01", "1 "]) {
    assert.throws(() => linuxTestPlan({ ...valid, env: { ...valid.env, OPEMOS_EXPERIMENTAL_LINUX: optin } }));
  }
  for (const mode of [undefined, "", "auto", "TCG", "tcg ", "kvm;echo bad"]) {
    assert.throws(() => linuxTestPlan({ ...valid, env: { ...valid.env, OPEMOS_LINUX_ACCEL: mode } }));
  }
});

test("Development launch requires a nonempty X11 or Wayland session", () => {
  for (const display of [{}, { DISPLAY: "  ", WAYLAND_DISPLAY: "" }]) {
    assert.throws(() => linuxTestPlan({ ...valid, args: ["dev"], env: { ...valid.env, ...display } }), /graphical desktop/);
  }
  for (const display of [{ DISPLAY: ":0" }, { WAYLAND_DISPLAY: "wayland-0" }]) {
    const args = linuxTestPlan({ ...valid, args: ["dev"], env: { ...valid.env, ...display } });
    assert.equal(args[0], "dev");
    assert.equal(args[1], "--config");
  }
});

test("Linux tests force the capture-compatible WebKit renderer without mutating input", () => {
  for (const existing of [undefined, "", "0", "unexpected"]) {
    const env = { KEEP: "value", WEBKIT_DISABLE_DMABUF_RENDERER: existing };
    const planned = linuxTestEnvironment(env);
    assert.equal(planned.WEBKIT_DISABLE_DMABUF_RENDERER, "1");
    assert.equal(planned.KEEP, "value");
    assert.equal(env.WEBKIT_DISABLE_DMABUF_RENDERER, existing);
  }
});

test("Linux test window replaces Mac glass settings and isolates app identity", async () => {
  const read = async (file) => JSON.parse(await readFile(new URL(file, import.meta.url)));
  const base = await read("../src-tauri/tauri.conf.json");
  const linux = await read("../src-tauri/tauri.linux-test.conf.json");
  assert.notEqual(linux.identifier, base.identifier);
  assert.deepEqual(base.bundle.targets, ["app", "dmg"]);
  assert.deepEqual(linux.bundle.targets, ["deb", "appimage"]);
  assert.ok(linux.bundle.linux.deb.depends.includes("libc6 (>= 2.39)"));
  assert.ok(linux.bundle.linux.deb.depends.includes("libssl3t64 | libssl3"));
  assert.ok(linux.bundle.linux.deb.depends.includes("liblzma5"));
  assert.equal(linux.app.windows.length, 1);
  const window = linux.app.windows[0];
  assert.equal(window.label, "main");
  assert.equal(window.transparent, false);
  assert.equal(window.backgroundColor[3], 255);
  assert.equal(window.visible, false);
  assert.equal(window.windowEffects, undefined);
  assert.equal(window.titleBarStyle, undefined);
  assert.equal(linux.app.security, undefined);
  // Tauri rewrites Cargo features from this flag; inherit the macOS feature.
  assert.equal(linux.app.macOSPrivateApi, undefined);
});


test("Debian 12 config changes dependencies without drifting the Linux test window", async () => {
  const read = async (file) => JSON.parse(await readFile(new URL(file, import.meta.url)));
  const ubuntu = await read("../src-tauri/tauri.linux-test.conf.json");
  const debian = await read("../src-tauri/tauri.linux-debian12-test.conf.json");
  assert.deepEqual(debian.app, ubuntu.app);
  assert.equal(debian.productName, ubuntu.productName);
  assert.equal(debian.identifier, ubuntu.identifier);
  assert.equal(debian.bundle.shortDescription, ubuntu.bundle.shortDescription);
  assert.deepEqual(debian.bundle.targets, ubuntu.bundle.targets);
  assert.deepEqual(debian.bundle.linux.deb.depends,
    ["libc6 (>= 2.36)", "libssl3", "liblzma5", "libgcc-s1"]);
});
