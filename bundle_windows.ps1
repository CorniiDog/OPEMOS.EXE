param([Parameter(Mandatory = $true)][string]$RuntimeRoot)
$ErrorActionPreference = "Stop"
$root = (Resolve-Path -LiteralPath $RuntimeRoot).Path
$sourceCommit = (git rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw "Could not resolve the exact source commit." }
$manifest = Join-Path $root "runtime-manifest.json"
$env:OPEMOS_RUNTIME_MANIFEST_SHA256 = (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant()
cargo build --manifest-path src-tauri/Cargo.toml --release --locked
if ($LASTEXITCODE -ne 0) { throw "Windows application build failed." }
python scripts/stage_runtime_bundle.py --platform windows --runtime-root $root --output dist/windows --source-commit $sourceCommit --application src-tauri/target/release/steamos-nvidia-image-builder.exe
if ($LASTEXITCODE -ne 0) { throw "Windows bundle staging failed." }
