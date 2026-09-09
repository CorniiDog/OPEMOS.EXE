import assert from "node:assert/strict";
import test from "node:test";
import { displayPath } from "../src/display-path.js";

test("normalizes Windows verbatim paths for display only", () => {
  assert.equal(displayPath(String.raw`\\?\C:\Users\Test User\image.img`), String.raw`C:\Users\Test User\image.img`);
  assert.equal(displayPath(String.raw`\\?\UNC\server\share\image.img`), String.raw`\\server\share\image.img`);
  assert.equal(displayPath(String.raw`C:\plain path\image.img`), String.raw`C:\plain path\image.img`);
  assert.equal(displayPath("/tmp/image.img"), "/tmp/image.img");
  assert.equal(displayPath(null), null);
});
