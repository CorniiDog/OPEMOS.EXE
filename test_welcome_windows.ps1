[CmdletBinding()]
param([switch]$PrintOnly)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'PowerShell 7 or newer is required.' }
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$UiRoot = Join-Path $Root 'builder/welcome'
$Server = Join-Path $UiRoot 'welcome_server.py'
if (-not (Test-Path -LiteralPath $Server -PathType Leaf) -or -not (Test-Path -LiteralPath (Join-Path $UiRoot 'index.html') -PathType Leaf)) { throw 'SteamOS with NVIDIA drivers graphical test bundle is missing.' }
if ($PrintOnly) { Write-Output "python `"$Server`" --mock --ui-root `"$UiRoot`""; exit 0 }
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'test_welcome_windows.ps1 supports Windows only.' }
$Python = (Get-Command python -ErrorAction Stop).Source
$Edge = (Get-Command msedge -ErrorAction SilentlyContinue).Source
if (-not $Edge) { $Edge = Join-Path ${env:ProgramFiles(x86)} 'Microsoft/Edge/Application/msedge.exe' }
if (-not (Test-Path -LiteralPath $Edge -PathType Leaf)) { throw 'Microsoft Edge is required for the Windows graphical preview.' }
$Runtime = Join-Path ([IO.Path]::GetTempPath()) ("opemos-welcome-windows-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Runtime | Out-Null
$serverProcess = $null; $browserProcess = $null
function Start-OwnedProcess([string]$File, [string[]]$Arguments) {
  $info = [Diagnostics.ProcessStartInfo]::new()
  $info.FileName = $File
  $info.UseShellExecute = $false
  foreach ($argument in $Arguments) { [void]$info.ArgumentList.Add($argument) }
  $process = [Diagnostics.Process]::new(); $process.StartInfo = $info
  if (-not $process.Start()) { throw "Could not start $File" }
  return $process
}
function Stop-OwnedTree($Process) {
  if ($Process -and -not $Process.HasExited) {
    & taskkill.exe /PID $Process.Id /T /F | Out-Null
    $Process.WaitForExit()
  }
}
try {
  $serverProcess = Start-OwnedProcess $Python @($Server,'--mock','--ui-root',$UiRoot,'--runtime',$Runtime)
  $portFile = Join-Path $Runtime 'port'
  for ($i=0; $i -lt 100 -and -not (Test-Path -LiteralPath $portFile -PathType Leaf); $i++) { if ($serverProcess.HasExited) { throw 'The graphical simulation stopped before readiness.' }; Start-Sleep -Milliseconds 50 }
  if (-not (Test-Path -LiteralPath $portFile -PathType Leaf)) { throw 'The graphical simulation did not start.' }
  $port = (Get-Content -LiteralPath $portFile -Raw).Trim()
  if ($port -notmatch '^\d{1,5}$' -or [int]$port -lt 1 -or [int]$port -gt 65535) { throw 'The graphical simulation returned an invalid loopback port.' }
  Write-Output 'Opening the safe graphical simulation. No disks, privileges, QEMU processes, or installers are used.'
  $browserProcess = Start-OwnedProcess $Edge @("--user-data-dir=$Runtime\edge",'--app=http://127.0.0.1:'+$port+'/','--start-fullscreen','--no-first-run','--disable-sync','--disable-background-networking')
  $browserProcess.WaitForExit()
}
finally {
  foreach ($process in @($browserProcess,$serverProcess)) { Stop-OwnedTree $process }
  Remove-Item -LiteralPath $Runtime -Recurse -Force -ErrorAction SilentlyContinue
}
