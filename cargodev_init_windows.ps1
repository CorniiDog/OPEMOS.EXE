[CmdletBinding()]
param([switch]$CheckOnly, [switch]$PrintOnly)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'PowerShell 7 or newer is required.' }
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'cargodev_init_windows.ps1 supports Windows only.' }
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not (Test-Path -LiteralPath (Join-Path $Root 'package-lock.json') -PathType Leaf)) { throw 'Run this script from an OPEMOS.EXE checkout.' }
if ($PrintOnly) { Write-Output 'npm ci'; Write-Output 'npm run dev'; exit 0 }
$required = @('node','npm','cargo','rustc','git','python','qemu-system-x86_64','qemu-img','gpgv')
$missing = @($required | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
if ($missing.Count) { throw "Missing Windows prerequisites: $($missing -join ', '). Install Node.js, Rust, Git, Python, QEMU, GnuPG, WebView2 Runtime, and Visual Studio C++ Build Tools." }
Write-Output 'Windows development prerequisites are available. USB writing remains test-harness only.'
if ($CheckOnly) { exit 0 }
Push-Location -LiteralPath $Root
try { npm ci; if ($LASTEXITCODE) { throw "npm ci failed with exit code $LASTEXITCODE" }; npm run dev; exit $LASTEXITCODE }
finally { Pop-Location }
