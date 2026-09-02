import assert from "node:assert/strict";
import { access, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { inflateSync } from "node:zlib";

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
const pngDimensions = async (relative) => {
  const bytes = await readFile(path.join(root, relative));
  assert.equal(bytes.subarray(1, 4).toString("ascii"), "PNG", `${relative} must be a PNG`);
  return { width: bytes.readUInt32BE(16), height: bytes.readUInt32BE(20) };
};

const pngRgbaCornerAlphas = async (relative) => {
  const bytes = await readFile(path.join(root, relative));
  const width = bytes.readUInt32BE(16);
  const height = bytes.readUInt32BE(20);
  assert.equal(bytes[24], 8, `${relative} must use 8-bit samples`);
  assert.equal(bytes[25], 6, `${relative} must use RGBA pixels`);
  assert.equal(bytes[28], 0, `${relative} must not be interlaced`);
  const chunks = [];
  for (let offset = 8; offset + 12 <= bytes.length;) {
    const length = bytes.readUInt32BE(offset);
    const type = bytes.subarray(offset + 4, offset + 8).toString("ascii");
    if (type === "IDAT") chunks.push(bytes.subarray(offset + 8, offset + 8 + length));
    offset += 12 + length;
  }
  const packed = inflateSync(Buffer.concat(chunks));
  const stride = width * 4;
  const pixels = Buffer.alloc(stride * height);
  for (let row = 0, source = 0; row < height; row += 1) {
    const filter = packed[source++];
    const target = row * stride;
    for (let column = 0; column < stride; column += 1) {
      const raw = packed[source++];
      const left = column >= 4 ? pixels[target + column - 4] : 0;
      const above = row ? pixels[target + column - stride] : 0;
      const upperLeft = row && column >= 4 ? pixels[target + column - stride - 4] : 0;
      const predictor = (() => {
        if (filter === 0) return 0;
        if (filter === 1) return left;
        if (filter === 2) return above;
        if (filter === 3) return Math.floor((left + above) / 2);
        if (filter === 4) {
          const estimate = left + above - upperLeft;
          const distances = [Math.abs(estimate - left), Math.abs(estimate - above), Math.abs(estimate - upperLeft)];
          return distances[0] <= distances[1] && distances[0] <= distances[2] ? left : distances[1] <= distances[2] ? above : upperLeft;
        }
        assert.fail(`${relative} uses unsupported PNG filter ${filter}`);
      })();
      pixels[target + column] = (raw + predictor) & 0xff;
    }
  }
  return [pixels[3], pixels[stride - 1], pixels[(height - 1) * stride + 3], pixels[pixels.length - 1]];
};

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
assert.match(pill, /<rect x="2\.5" y="2\.5" width="187" height="43" rx="21\.5"/);
assert.doesNotMatch(pill, /M20 12h134/);
for (const page of requiredPages.slice(1)) {
  assert.match(config, new RegExp(`^  - ${page.replace(".", "\\.")}$`, "m"));
}

const index = await read("docs/index.md");
for (const slot of ["main-window", "build-progress", "maintainer-workspace"]) {
  assert.match(index, new RegExp(`data-screenshot="${slot}"`), `missing ${slot} screenshot slot`);
  assert.match(index, new RegExp(`assets/screenshots/${slot}\\.png`), `missing ${slot} screenshot image`);
  const screenshot = await stat(path.join(root, "docs", "assets", "screenshots", `${slot}.png`));
  assert.ok(screenshot.size < 2 * 1024 * 1024, `${slot}.png must remain below 2 MiB`);
  const dimensions = await pngDimensions(`docs/assets/screenshots/${slot}.png`);
  assert.equal(dimensions.width * 9, dimensions.height * 16, `${slot}.png must be 16:9`);
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
assert.match(readme, /img\.shields\.io\/github\/actions\/workflow\/status\/CorniiDog\/OPEMOS\.EXE\/checks\.yml/);
assert.match(readme, /img\.shields\.io\/github\/actions\/workflow\/status\/CorniiDog\/OPEMOS\.EXE\/pages\.yml/);
assert.match(readme, /style=for-the-badge/);
assert.match(readme, /labelColor=192c3c/);
assert.match(readme, /https:\/\/corniidog\.github\.io\/OPEMOS\.EXE\//);
assert.match(readme, /docs\/assets\/images\/opemos-app-icon\.svg/);
assert.match(readme, /docs\/assets\/screenshots\/main-window-readme\.png/);
assert.match(readme, /docs\/assets\/screenshots\/build-progress-readme\.png/);
for (const screenshot of ["main-window-readme.png", "build-progress-readme.png"]) {
  const dimensions = await pngDimensions(`docs/assets/screenshots/${screenshot}`);
  assert.equal(dimensions.width * 9, dimensions.height * 16, `${screenshot} must be 16:9`);
}

const iconSvg = await read("docs/assets/images/opemos-app-icon.svg");
assert.match(iconSvg, /id="half-ring"/);
assert.match(iconSvg, /transform="translate\(1024 0\) scale\(-1 1\)"/);
assert.match(iconSvg, /<circle cx="512" cy="456" r="142"/);
assert.match(iconSvg, /<circle cx="512" cy="456" r="55"/);
assert.match(iconSvg, /M 424 640 L 512 738 L 600 640 Z/);
assert.doesNotMatch(iconSvg, /M 104 226 Q 170 92 330 78/);
assert.doesNotMatch(iconSvg, /<rect x="48" y="48"[^>]*filter=/);
const iconDimensions = await pngDimensions("docs/assets/images/opemos-app-icon.png");
assert.deepEqual(iconDimensions, { width: 1024, height: 1024 });
assert.deepEqual(await pngRgbaCornerAlphas("docs/assets/images/opemos-app-icon.png"), [0, 0, 0, 0]);
assert.deepEqual(await pngRgbaCornerAlphas("src-tauri/icons/icon.png"), [0, 0, 0, 0]);

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
