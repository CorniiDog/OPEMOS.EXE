import assert from "node:assert/strict";
import { access, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const requiredPages = [
  "index.md",
  "getting-started.md",
  "workflow.md",
  "developer-guide.md",
  "architecture.md",
  "security.md",
  "troubleshooting.md",
];

const read = (relative) => readFile(path.join(root, relative), "utf8");

for (const page of requiredPages) {
  const relative = path.join("docs", page);
  const body = await read(relative);
  assert.match(body, /^---\n[\s\S]*?\n---\n/, `${relative} needs complete front matter`);
  assert.match(body, /\ntitle:\s*\S/, `${relative} needs a title`);
  assert.match(body, /\ndescription:\s*\S/, `${relative} needs a description`);
}

const config = await read("docs/_config.yml");
const styles = await read("docs/assets/main.scss");
const pill = await read("docs/assets/images/opemos-pill.svg");
assert.match(config, /^title: OPEMOS\.EXE$/m);
assert.match(config, /^baseurl: \/OPEMOS\.EXE$/m);
assert.match(config, /^repository: CorniiDog\/OPEMOS\.EXE$/m);
assert.match(styles, /\.screenshot-grid\s*\{/);
assert.match(styles, /\.screenshot-slot\s*\{/);
assert.match(styles, /aspect-ratio:\s*16\s*\/\s*9/);
assert.match(styles, /--syntax-keyword:\s*#426b00/);
assert.match(styles, /\.highlight span\s*\{/);
assert.match(styles, /table th\s*\{/);
assert.match(pill, /<linearGradient id="opemos-gradient"/);
assert.match(pill, /#1a9fff/);
assert.match(pill, /#76b900/);
for (const page of requiredPages.slice(1)) {
  assert.match(config, new RegExp(`^  - ${page.replace(".", "\\.")}$`, "m"));
}

const index = await read("docs/index.md");
for (const slot of ["main-window", "build-progress", "maintainer-workspace"]) {
  assert.match(index, new RegExp(`data-screenshot="${slot}"`), `missing ${slot} screenshot slot`);
}

const markdownFiles = ["README.md", ...requiredPages.map((page) => `docs/${page}`)];
const markdownLink = /\[[^\]]*\]\(([^)]+)\)/g;
for (const relative of markdownFiles) {
  const body = await read(relative);
  for (const match of body.matchAll(markdownLink)) {
    const target = match[1].split("#", 1)[0];
    if (!target || /^(?:https?:|mailto:|\{\{)/.test(target)) continue;
    const resolved = path.resolve(path.dirname(path.join(root, relative)), target);
    assert.ok(resolved.startsWith(`${root}${path.sep}`), `${relative} link escapes repository: ${target}`);
    await access(resolved);
  }
}

const readme = await read("README.md");
assert.ok((await stat(path.join(root, "README.md"))).size < 16_000, "README should remain a concise landing page");
assert.match(readme, /actions\/workflows\/checks\.yml\/badge\.svg/);
assert.match(readme, /actions\/workflows\/pages\.yml\/badge\.svg/);
assert.match(readme, /https:\/\/corniidog\.github\.io\/OPEMOS\.EXE\//);
assert.match(readme, /docs\/assets\/images\/opemos-app-icon\.png/);

const checks = await read(".github/workflows/checks.yml");
assert.match(checks, /^name: Checks$/m);
assert.match(checks, /npm run test:frontend/);
assert.match(checks, /cargo test --manifest-path src-tauri\/Cargo\.toml/);
assert.match(checks, /^permissions:\n  contents: read$/m);

const pages = await read(".github/workflows/pages.yml");
for (const action of [
  "actions/configure-pages@v5",
  "actions/jekyll-build-pages@v1",
  "actions/upload-pages-artifact@v3",
  "actions/deploy-pages@v4",
]) {
  assert.ok(pages.includes(action), `Pages workflow is missing ${action}`);
}
assert.match(pages, /pages: write/);
assert.match(pages, /id-token: write/);
assert.match(pages, /if: github\.event_name != 'pull_request'/);

console.log("[documentation] Documentation contracts passed.");
