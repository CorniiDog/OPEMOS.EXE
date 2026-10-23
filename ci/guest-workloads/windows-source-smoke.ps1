$ErrorActionPreference = 'Stop'
# Fixed A recipe, executed only inside the admitted Windows guest.

$source = "dist/windows/OPEMOS.EXE-windows-x86_64-unsigned.exe"
$qemuBefore = @(Get-Process -Name "qemu-system-*" -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Id):$($_.StartTime.ToUniversalTime().Ticks)" })
$webviewBefore = @(Get-Process -Name "msedgewebview2" -ErrorAction SilentlyContinue | ForEach-Object { try { "$($_.Id):$($_.StartTime.ToUniversalTime().Ticks)" } catch {} })
$process = Start-Process -FilePath $source -PassThru
try {
  $deadline = [DateTime]::UtcNow.AddSeconds(30)
  do {
    Start-Sleep -Milliseconds 250
    $process.Refresh()
    if ($process.HasExited) {
      throw "Portable executable exited during startup with code $($process.ExitCode)."
    }
  } while (($process.MainWindowHandle -eq 0 -or $process.MainWindowTitle -cne "SteamOS NVIDIA Builder") -and [DateTime]::UtcNow -lt $deadline)
  if ($process.MainWindowHandle -eq 0) {
    throw "Portable executable did not show a native main window within 30 seconds."
  }
  if ($process.MainWindowTitle -cne "SteamOS NVIDIA Builder") {
    throw "Portable executable showed an unexpected window title: $($process.MainWindowTitle)"
  }
}
finally {
  if (-not $process.HasExited) {
    Stop-Process -Id $process.Id
    $process.WaitForExit()
  }
}
$qemuDeadline = [DateTime]::UtcNow.AddSeconds(5)
do {
  $qemuAfter = @(Get-Process -Name "qemu-system-*" -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Id):$($_.StartTime.ToUniversalTime().Ticks)" } | Where-Object { $_ -notin $qemuBefore })
  if ($qemuAfter.Count -eq 0) {
    break
  }
  Start-Sleep -Milliseconds 250
} while ([DateTime]::UtcNow -lt $qemuDeadline)
if ($qemuAfter.Count -ne 0) {
  throw "Portable executable left new QEMU processes after bounded shutdown: $($qemuAfter -join ', ')"
}
$webviewDeadline = [DateTime]::UtcNow.AddSeconds(15)
do {
  $webviewAfter = @(Get-Process -Name "msedgewebview2" -ErrorAction SilentlyContinue | ForEach-Object { try { "$($_.Id):$($_.StartTime.ToUniversalTime().Ticks)" } catch {} } | Where-Object { $_ -notin $webviewBefore })
  if ($webviewAfter.Count -eq 0) {
    break
  }
  Start-Sleep -Milliseconds 250
} while ([DateTime]::UtcNow -lt $webviewDeadline)
if ($webviewAfter.Count -ne 0) {
  throw "Portable executable left new WebView processes after bounded shutdown: $($webviewAfter -join ', ')"
}
$bundleRoot = (Resolve-Path -LiteralPath "dist/windows").Path
$state = Join-Path $bundleRoot "state"
if (Test-Path -LiteralPath $state) {
  $stateItem = Get-Item -LiteralPath $state -Force
  if (-not $stateItem.PSIsContainer -or ($stateItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw "Portable smoke-test state is not an owned real directory."
  }
  $stateCleanupDeadline = [DateTime]::UtcNow.AddSeconds(10)
  do {
    try {
      Remove-Item -LiteralPath $state -Recurse -Force -ErrorAction Stop
    }
    catch {
      if ([DateTime]::UtcNow -ge $stateCleanupDeadline) {
        throw
      }
      Start-Sleep -Milliseconds 250
    }
  } while (Test-Path -LiteralPath $state)
}
if (Test-Path -LiteralPath $state) {
  throw "Portable smoke-test state survived cleanup."
}

$source = "dist/windows/OPEMOS.EXE-windows-x86_64-unsigned.exe"
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
  throw "Expected executable is absent: $source"
}
$signature = Get-AuthenticodeSignature -LiteralPath $source
if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::NotSigned) {
  throw "Executable must be unsigned; signature status is $($signature.Status)"
}
$output = "dist/windows"
$name = "OPEMOS.EXE-windows-x86_64-unsigned.exe"
$destination = $source
$file = Get-Item -LiteralPath $destination
$sha256 = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
$lines = @(
  "schema_version=1"
  "repository=$env:GITHUB_REPOSITORY"
  "source_commit=$env:OPEMOS_EXE_COMMIT"
  "core_commit=$env:OPEMOS_CORE_COMMIT"
  "rust_toolchain=$env:RUST_TOOLCHAIN"
  "node_version=$env:NODE_VERSION"
  "crt_static=true"
  "runner_image=$env:ImageOS"
  "runner_image_version=$env:ImageVersion"
  "filename=$name"
  "size=$($file.Length)"
  "sha256=$sha256"
  "signed=false"
  "portable=true"
)
Set-Content -LiteralPath (Join-Path $output "provenance.txt") -Value $lines -Encoding ascii
Set-Content -LiteralPath (Join-Path $output "SHA256SUMS.txt") -Value "$sha256  $name" -Encoding ascii
