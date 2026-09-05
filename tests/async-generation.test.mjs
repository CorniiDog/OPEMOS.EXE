import assert from "node:assert/strict";
import test from "node:test";

import { createLatestRequestGate } from "../src/async-generation.js";

test("only the latest asynchronous request generation can commit", () => {
  const gate = createLatestRequestGate();
  const first = gate.begin();
  const second = gate.begin();
  assert.equal(gate.isCurrent(first), false);
  assert.equal(gate.isCurrent(second), true);
  assert.equal(gate.isCurrent(0), false);
  assert.equal(gate.isCurrent(2.5), false);
  assert.equal(gate.isCurrent("2"), false);
});

test("request gates are isolated and expose no mutable counter", () => {
  const left = createLatestRequestGate();
  const right = createLatestRequestGate();
  assert.equal(left.begin(), 1);
  assert.equal(left.begin(), 2);
  assert.equal(right.begin(), 1);
  assert.deepEqual(Object.keys(left).sort(), ["begin", "isCurrent"]);
  assert.equal(Object.isFrozen(left), true);
});
