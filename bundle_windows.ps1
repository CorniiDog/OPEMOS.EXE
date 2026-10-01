param(
  [string]$RuntimeRoot,
  [string]$PreparedRuntimeRoot,
  [Parameter(Mandatory = $true)][string]$CoreRoot
)
$ErrorActionPreference = "Stop"
if ($RuntimeRoot -and $PreparedRuntimeRoot) { throw "RuntimeRoot and PreparedRuntimeRoot are mutually exclusive." }
if ($PreparedRuntimeRoot) {
  python scripts/validate_cached_windows_runtime.py --runtime $PreparedRuntimeRoot --lock runtime/windows-x86_64.sources.json --core-root $CoreRoot
  if ($LASTEXITCODE -ne 0) { throw "Cached Windows runtime validation failed." }
  $prepared = (Resolve-Path -LiteralPath $PreparedRuntimeRoot).Path
}
if (-not $RuntimeRoot) {
  if (-not $PreparedRuntimeRoot) {
    python scripts/acquire_runtime_windows.py
    if ($LASTEXITCODE -ne 0) { throw "Windows runtime acquisition failed." }
    $RuntimeRoot = "build/runtime/windows"
  }
}
$core = (Resolve-Path -LiteralPath $CoreRoot).Path
$sourceCommit = (git rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw "Could not resolve the exact source commit." }
if (-not $PreparedRuntimeRoot) {
  $root = (Resolve-Path -LiteralPath $RuntimeRoot).Path
  $prepared = Join-Path (Resolve-Path -LiteralPath ".").Path "build/runtime/windows-with-core-zstd"
  if (Test-Path -LiteralPath $prepared) { throw "Prepared Windows runtime output already exists: $prepared" }
  python scripts/prepare_windows_runtime.py --runtime-root $root --core-root $core --output $prepared
  if ($LASTEXITCODE -ne 0) { throw "Windows Core zstd runtime preparation failed." }
}
$manifest = Join-Path $prepared "runtime-manifest.json"
$env:OPEMOS_RUNTIME_MANIFEST_SHA256 = (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant()
cargo build --manifest-path src-tauri/Cargo.toml --release --locked
if ($LASTEXITCODE -ne 0) { throw "Windows application build failed." }
$application = "build/OPEMOS.EXE-windows-x86_64-unsigned.exe"
Copy-Item -LiteralPath "src-tauri/target/release/steamos-nvidia-image-builder.exe" -Destination $application
python scripts/stage_runtime_bundle.py --platform windows --runtime-root $prepared --output dist/windows --source-commit $sourceCommit --application $application
if ($LASTEXITCODE -ne 0) { throw "Windows bundle staging failed." }
python scripts/acquire_appliance_windows.py --deadline-seconds 4500
if ($LASTEXITCODE -ne 0) { throw "Windows Fedora appliance acquisition failed." }
Move-Item -LiteralPath "build/appliance/windows" -Destination "dist/windows/appliance"
