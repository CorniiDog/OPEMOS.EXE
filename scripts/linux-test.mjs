import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = fileURLToPath(new URL("../", import.meta.url));

// This is host launch configuration only. Runtime host and Core trust checks
// remain authoritative; opting into this launcher cannot authorize a build.
export function linuxTestPlan({ platform, arch, env, args }) {
  if (platform !== "linux" || arch !== "x64") {
    throw new Error("Experimental Linux testing requires an x86_64 Linux host.");
  }
  if (env.OPEMOS_EXPERIMENTAL_LINUX !== "1") {
    throw new Error("Set OPEMOS_EXPERIMENTAL_LINUX=1 explicitly before Linux testing.");
  }
  if (!["kvm", "tcg"].includes(env.OPEMOS_LINUX_ACCEL)) {
    throw new Error("Select OPEMOS_LINUX_ACCEL=kvm or tcg explicitly; there is no automatic fallback.");
  }
  if (args.length !== 1 || !["dev", "build"].includes(args[0])) {
    throw new Error("Usage: linux-test.mjs dev|build (additional CLI overrides are unsupported).");
  }
  if (args[0] === "dev" && !env.DISPLAY?.trim() && !env.WAYLAND_DISPLAY?.trim()) {
    throw new Error("Launch development windows from an X11 or Wayland graphical desktop session.");
  }
  return [args[0], ...(args[0] === "build" ? ["--debug", "--bundles", "deb"] : []),
    "--config", path.join(root, "src-tauri/tauri.linux-test.conf.json")];
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = linuxTestPlan({ platform: process.platform, arch: process.arch,
      env: process.env, args: process.argv.slice(2) });
    console.error("Experimental Linux test build. Use the scheduler heavy.sh wrapper on the coordinated host.");
    const result = spawnSync(process.execPath,
      [path.join(root, "node_modules/@tauri-apps/cli/tauri.js"), ...args],
      { cwd: root, env: process.env, stdio: "inherit" });
    if (result.error) throw result.error;
    if (result.signal) {
      console.error(`Linux testing command terminated by ${result.signal}.`);
      process.exitCode = 1;
    } else {
      process.exitCode = result.status ?? 1;
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
