import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("maintainer menu loads and runs the authenticated release session", async () => {
  const source = await readFile(new URL("../src/maintainer.js", import.meta.url), "utf8");
  assert.match(source, /installReleasePlanReview\(document, \(command, request\) =>/);
  assert.match(source, /invoke\("run_maintainer_release_operation", \{ command, request \}\)/);
  assert.match(source, /invoke\("prepare_maintainer_release_operation"\)/);
  assert.match(source, /invoke\("import_maintainer_release_product", \{ directory \}\)/);
  assert.match(source, /Validating and materializing the exact Core product/);
  assert.match(source, /openFolder\(\{ multiple: false, directory: true \}\)/);
  assert.match(source, /\.then\(releaseReview\.render\)/);
});
