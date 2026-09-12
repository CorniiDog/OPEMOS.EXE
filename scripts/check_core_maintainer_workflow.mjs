#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { CORE_MAINTAINER_WORKFLOW } from "../src/maintainer-release-workflow.js";
const root = process.env.OPEMOS_CORE_CONTRACT_ROOT;
if (!root) throw new Error("OPEMOS_CORE_CONTRACT_ROOT is required.");
const actual = JSON.parse(execFileSync("python3", [path.join(root, "lib/maintainer_release_workflow.py"), "--steamos", "3.8.14", "--kernel", "6.16.12-valve24.4-1-neptune-616-gfe145653a794", "--nvidia", "575.64.05", "--architecture", "x86_64"], { encoding: "utf8" }));
assert.deepEqual(actual, CORE_MAINTAINER_WORKFLOW);
console.log("[maintainer-workflow] Bundled EXE plan matches exact Core output.");
