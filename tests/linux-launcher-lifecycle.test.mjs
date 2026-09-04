import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { once } from "node:events";
import test from "node:test";
import { runLinuxTestCommand } from "../scripts/linux-test.mjs";

const linux = process.platform === "linux";
const moduleUrl = new URL("../scripts/linux-test.mjs", import.meta.url).href;
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function stopped(pid) {
  try {
    const stat = await readFile(`/proc/${pid}/stat`, "utf8");
    // A dead orphan can await init's reap; it must not remain executable.
    return stat.slice(stat.lastIndexOf(")") + 2).startsWith("Z");
  } catch (error) { if (error.code === "ENOENT") return true; throw error; }
}
async function waitStopped(pid) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (await stopped(pid)) return;
    await delay(10);
  }
  assert.fail(`Process ${pid} remained alive after launcher exit`);
}

async function fixture(mode, signal) {
  const descendant = `process.on('SIGTERM', () => {}); process.on('SIGINT', () => {}); setInterval(() => {}, 1000); process.send(process.pid);`;
  const leader = `
    const { spawn } = require('node:child_process');
    for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => {
      console.log(JSON.stringify({ forwarded: signal }));
      ${mode === "graceful" ? "process.exit(0);" : ""}
    });
    const child = spawn(process.execPath, ['-e', ${JSON.stringify(descendant)}], { stdio: ['ignore', 'inherit', 'inherit', 'ipc'] });
    child.once('message', pid => {
      console.log(JSON.stringify({ leader: process.pid, descendant: pid }));
      ${mode === "exit" ? "process.exit(7);" : "setInterval(() => {}, 1000);"}
    });`;
  const launcherSource = `
    import { runLinuxTestCommand } from ${JSON.stringify(moduleUrl)};
    const result = await runLinuxTestCommand(process.execPath, ['-e', ${JSON.stringify(leader)}], { graceMs: 100 });
    console.log(JSON.stringify({ result }));`;
  const launcher = spawn(process.execPath, ["--input-type=module", "-e", launcherSource], { stdio: ["ignore", "pipe", "pipe"] });
  const completion = once(launcher, "exit");
  const outputClosed = once(launcher.stdout, "close");
  let output = "", errors = "", ids;
  launcher.stdout.setEncoding("utf8");
  launcher.stderr.setEncoding("utf8");
  launcher.stderr.on("data", (chunk) => { errors += chunk; });
  const ready = new Promise((resolve) => launcher.stdout.on("data", (chunk) => {
    output += chunk;
    const line = output.split("\n")[0];
    if (!ids && output.includes("\n")) { ids = JSON.parse(line); resolve(); }
  }));
  const watchdog = setTimeout(() => {
    launcher.kill("SIGKILL");
    if (ids) { try { process.kill(-ids.leader, "SIGKILL"); } catch {} }
  }, 5000);
  try {
    await Promise.race([ready, completion.then(() => { if (!ids) throw new Error(`Launcher exited before readiness: ${errors}`); })]);
    if (signal) launcher.kill(signal);
    const [code, killed] = await completion;
    assert.equal(code, 0, errors);
    assert.equal(killed, null);
    await outputClosed;
    const result = output.trim().split("\n").map((line) => JSON.parse(line)).find((line) => line.result)?.result;
    assert.ok(result, output);
    if (signal) {
      assert.equal(result.signal, signal);
      assert.ok(output.trim().split("\n").some((line) => JSON.parse(line).forwarded === signal), output);
      if (mode === "graceful") assert.equal(result.code, 0);
      else assert.equal(result.code, null);
    }
    else assert.deepEqual(result, { code: 7, signal: null });
    await waitStopped(ids.leader);
    await waitStopped(ids.descendant);
  } finally {
    clearTimeout(watchdog);
    if (launcher.exitCode === null) launcher.kill("SIGKILL");
    if (ids) { try { process.kill(-ids.leader, "SIGKILL"); } catch {} }
  }
}

test("Linux launcher forwards termination and escalates stubborn process groups", { skip: !linux, timeout: 15000 }, async () => {
  for (const signal of ["SIGINT", "SIGTERM"]) {
    await fixture("wait", signal);
    await fixture("graceful", signal);
  }
});

test("Linux launcher preserves exit status and stops a leader's leftover child", { skip: !linux, timeout: 10000 }, async () => {
  await fixture("exit");
});

test("Linux launcher rejects spawn failures and removes its signal handlers", { skip: !linux }, async () => {
  const before = [process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")];
  await assert.rejects(runLinuxTestCommand("/opemos-nonexistent-test-executable", []), { code: "ENOENT" });
  assert.deepEqual([process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")], before);
  for (const graceMs of [0, -1, 5001, NaN]) await assert.rejects(runLinuxTestCommand(process.execPath, [], { graceMs }));
});
