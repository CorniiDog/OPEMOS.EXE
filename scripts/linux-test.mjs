import { spawn } from "node:child_process";
import { chmod, lstat, mkdir, readFile, rm, rmdir, writeFile } from "node:fs/promises";
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

// Tauri may normalize Cargo.toml and generate a platform capability schema.
// Snapshot only these known source paths and restore their exact pre-launch state.
async function snapshotRestoredFile(file) {
  try {
    const metadata = await lstat(file);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error(`Refusing to snapshot non-regular launch artifact: ${file}`);
    }
    return { file, bytes: await readFile(file), mode: metadata.mode & 0o777, missingParents: [] };
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    const missingParents = [];
    let parent = path.dirname(file);
    while (parent !== path.dirname(parent)) {
      try { await lstat(parent); break; }
      catch (parentError) {
        if (parentError.code !== "ENOENT") throw parentError;
        missingParents.push(parent);
        parent = path.dirname(parent);
      }
    }
    return { file, bytes: null, mode: null, missingParents };
  }
}

async function restoreLaunchFile(snapshot) {
  if (snapshot.bytes !== null) {
    await mkdir(path.dirname(snapshot.file), { recursive: true });
    await writeFile(snapshot.file, snapshot.bytes);
    await chmod(snapshot.file, snapshot.mode);
    return;
  }
  await rm(snapshot.file, { force: true });
  for (const parent of snapshot.missingParents) {
    try { await rmdir(parent); }
    catch (error) { if (!["ENOENT", "ENOTEMPTY", "EEXIST"].includes(error.code)) throw error; }
  }
}

export async function withRestoredLaunchFiles(files, action) {
  const snapshots = [];
  for (const file of files) snapshots.push(await snapshotRestoredFile(file));
  try {
    return await action();
  } finally {
    for (const snapshot of snapshots.toReversed()) await restoreLaunchFile(snapshot);
  }
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
    const groupExists = () => {
      if (!Number.isSafeInteger(child.pid) || child.pid <= 1) return false;
      try { process.kill(-child.pid, 0); return true; }
      catch (error) { if (error.code === "ESRCH") return false; throw error; }
    };
    const waitForGroupExit = async () => {
      const deadline = Date.now() + graceMs;
      while (groupExists() && Date.now() < deadline) {
        await new Promise((settle) => setTimeout(settle, 10));
      }
      if (groupExists()) throw new Error("Linux command process group did not stop after SIGKILL.");
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
      // Wait for group quiescence before callers restore files descendants may
      // still be writing.
      signalGroup("SIGKILL");
      void waitForGroupExit().then(() => {
        cleanup();
        if (signalError) { reject(signalError); return; }
        resolve({ code, signal: stopSignal ?? signal });
      }, (error) => {
        cleanup();
        reject(signalError ?? error);
      });
    });
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = linuxTestPlan({ platform: process.platform, arch: process.arch,
      env: process.env, args: process.argv.slice(2) });
    console.error("Experimental Linux test build. Use the scheduler heavy.sh wrapper on the coordinated host.");
    const result = await withRestoredLaunchFiles([
      path.join(root, "src-tauri/Cargo.toml"),
      path.join(root, "src-tauri/gen/schemas/linux-schema.json"),
    ], () => runLinuxTestCommand(process.execPath,
      [path.join(root, "node_modules/@tauri-apps/cli/tauri.js"), ...args]));
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
