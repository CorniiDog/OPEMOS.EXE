import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const files = ["cargodev_init_macos.sh", "cargodev_init_linux.sh", "cargodev_init_windows.ps1", "test_welcome_macos.sh", "test_welcome_linux.sh", "test_welcome_windows.ps1"];
test("all three hosts expose setup and safe welcome entry points", async () => {
  for (const file of files) await access(file);
  const linux = await readFile("cargodev_init_linux.sh", "utf8");
  assert.match(linux, /--check\|--print-only/); assert.match(linux, /x86_64 Linux only/); assert.match(linux, /npm ci/);
  const windows = await readFile("cargodev_init_windows.ps1", "utf8");
  assert.match(windows, /\$CheckOnly/); assert.match(windows, /\$PrintOnly/); assert.match(windows, /npm ci/);
  const welcome = await readFile("test_welcome_windows.ps1", "utf8");
  assert.match(welcome, /127\.0\.0\.1/); assert.match(welcome, /--user-data-dir/); assert.match(welcome, /ProcessStartInfo/); assert.match(welcome, /taskkill\.exe \/PID/); assert.match(welcome, /Remove-Item/);
  assert.doesNotMatch(welcome, /PhysicalDrive|qemu-system|diskpart|Format-Volume/);
});

test("README pins real three-platform commands and output contracts", async () => {
  const readme = await readFile("README.md", "utf8");
  for (const text of ["cargodev_init_macos.sh", "cargodev_init_linux.sh", "cargodev_init_windows.ps1", "test_welcome_macos.sh", "test_welcome_linux.sh", "test_welcome_windows.ps1", "pwsh -File", "npm run dev:linux-test", "npm run build:linux-test", "npm run build:debian12-test", "npm run test:package-linux", "cargo test --manifest-path src-tauri/Cargo.toml --locked windows_", "cargo build --manifest-path src-tauri/Cargo.toml --release --locked", "src-tauri/target/release/steamos-nvidia-image-builder.exe", "disposable overlay"])
    assert.match(readme, new RegExp(text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  const workflow = await readFile(".github/workflows/windows-portable.yml", "utf8");
  assert.match(workflow, /cargo test --manifest-path src-tauri\/Cargo\.toml --locked windows_/);
  assert.match(workflow, /cargo build --manifest-path src-tauri\/Cargo\.toml --release --locked/);
});
