import { spawn } from "node:child_process";
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

// One isolated process group keeps launcher-only termination from stranding
// Tauri/Cargo/application children. This does not handle SIGKILL of the launcher
// or descendants that deliberately leave the group.
export function runLinuxTestCommand(executable, args, { cwd = root, env = process.env, graceMs = 5000 } = {}) {
  if (process.platform !== "linux" || !Number.isInteger(graceMs) || graceMs < 1 || graceMs > 5000) {
    return Promise.reject(new Error("Invalid Linux command lifecycle configuration."));
  }
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { cwd, env, stdio: "inherit", detached: true });
    let timer;
    let stopSignal;
    let signalError;
    const signalGroup = (signal) => {
      if (!Number.isSafeInteger(child.pid) || child.pid <= 1) return;
      try { process.kill(-child.pid, signal); }
      catch (error) { if (error.code !== "ESRCH") signalError = error; }
    };
    const stop = (signal) => {
      if (stopSignal) return;
      stopSignal = signal;
      signalGroup(signal);
      timer = setTimeout(() => signalGroup("SIGKILL"), graceMs);
    };
    const interrupt = () => stop("SIGINT");
    const terminate = () => stop("SIGTERM");
    process.on("SIGINT", interrupt);
    process.on("SIGTERM", terminate);
    const cleanup = () => {
      clearTimeout(timer);
      process.off("SIGINT", interrupt);
      process.off("SIGTERM", terminate);
    };
    child.once("error", (error) => { cleanup(); reject(error); });
    child.once("exit", (code, signal) => {
      // A finished leader must not leave background children holding the job.
      signalGroup("SIGKILL");
      cleanup();
      if (signalError) { reject(signalError); return; }
      resolve({ code, signal: stopSignal ?? signal });
    });
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = linuxTestPlan({ platform: process.platform, arch: process.arch,
      env: process.env, args: process.argv.slice(2) });
    console.error("Experimental Linux test build. Use the scheduler heavy.sh wrapper on the coordinated host.");
    const result = await runLinuxTestCommand(process.execPath,
      [path.join(root, "node_modules/@tauri-apps/cli/tauri.js"), ...args]);
    if (result.signal) {
      console.error(`Linux testing command terminated by ${result.signal}.`);
      process.exitCode = 1;
    } else {
      process.exitCode = result.code ?? 1;
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
