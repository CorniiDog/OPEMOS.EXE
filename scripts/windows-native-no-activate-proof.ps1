[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Executable,
  [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExecutableSha256,
  [Parameter(Mandatory = $true)][int]$ExpectedForegroundProcessId,
  [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedForegroundExecutableSha256,
  [ValidateRange(5, 120)][int]$StartupTimeoutSeconds = 45,
  [ValidateRange(2, 120)][int]$ObservationSeconds = 10
)
$ErrorActionPreference = 'Stop'
$launcherName = 'OPEMOS-native-no-activate-proof.ps1'
if ([IO.Path]::GetFileName($PSCommandPath) -cne $launcherName) { throw "Run only the transient launcher named $launcherName." }
try {
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'This proof runs on Windows only.' }
$candidate = (Resolve-Path -LiteralPath $Executable -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw 'The exact OPEMOS executable is missing.' }
if ((Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash -cne $ExecutableSha256.ToUpperInvariant()) { throw 'The OPEMOS executable SHA-256 does not match the authorized candidate.' }

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
public static class OpemosNoActivateNative {
  public sealed class WindowIdentity { public IntPtr Handle; public uint ProcessId; public string Title; public string ClassName; }
  public sealed class MonitorBounds { public string Device; public int Left,Top,Right,Bottom,WorkLeft,WorkTop,WorkRight,WorkBottom; }
  [StructLayout(LayoutKind.Sequential)] private struct RECT { public int Left,Top,Right,Bottom; }
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] private struct MONITORINFOEX { public int Size; public RECT Monitor; public RECT Work; public uint Flags; [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)] public string Device; }
  private delegate void WinEventDelegate(IntPtr hook,uint evt,IntPtr hwnd,int obj,int child,uint thread,uint time);
  private delegate bool EnumWindowsDelegate(IntPtr hwnd,IntPtr data);
  private delegate bool MonitorEnumDelegate(IntPtr monitor,IntPtr hdc,IntPtr rect,IntPtr data);
  [StructLayout(LayoutKind.Sequential)] private struct POINT { public int X,Y; }
  [StructLayout(LayoutKind.Sequential)] private struct MSG { public IntPtr Hwnd; public uint Message; public UIntPtr WParam; public IntPtr LParam; public uint Time; public POINT Point; }
  private static WinEventDelegate guardDelegate; private static IntPtr guardHook; private static long expectedForeground; private static long unexpectedForeground; private static uint guardThreadId; private static Thread guardThread;
  [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] private static extern bool GetWindowThreadProcessId(IntPtr hwnd,out uint pid);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] private static extern int GetWindowText(IntPtr hwnd,StringBuilder text,int count);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] private static extern int GetClassName(IntPtr hwnd,StringBuilder text,int count);
  [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsDelegate callback,IntPtr data);
  [DllImport("user32.dll")] private static extern bool EnumDisplayMonitors(IntPtr hdc,IntPtr clip,MonitorEnumDelegate callback,IntPtr data);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] private static extern bool GetMonitorInfo(IntPtr monitor,ref MONITORINFOEX info);
  [DllImport("user32.dll")] private static extern bool GetWindowRect(IntPtr hwnd,out RECT rect);
  [DllImport("user32.dll")] private static extern bool SetWindowPos(IntPtr hwnd,IntPtr after,int x,int y,int cx,int cy,uint flags);
  [DllImport("user32.dll")] private static extern IntPtr SetWinEventHook(uint min,uint max,IntPtr module,WinEventDelegate callback,uint pid,uint tid,uint flags);
  [DllImport("user32.dll")] private static extern bool UnhookWinEvent(IntPtr hook);
  [DllImport("user32.dll")] private static extern int GetMessage(out MSG message,IntPtr hwnd,uint min,uint max);
  [DllImport("user32.dll")] private static extern bool PostThreadMessage(uint thread,uint message,UIntPtr wparam,IntPtr lparam);
  [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();
  private static WindowIdentity Read(IntPtr hwnd) { uint pid; GetWindowThreadProcessId(hwnd,out pid); var title=new StringBuilder(512); GetWindowText(hwnd,title,title.Capacity); var klass=new StringBuilder(256); GetClassName(hwnd,klass,klass.Capacity); return new WindowIdentity{Handle=hwnd,ProcessId=pid,Title=title.ToString(),ClassName=klass.ToString()}; }
  public static WindowIdentity Foreground() { return Read(GetForegroundWindow()); }
  public static void StartGuard(IntPtr expected) { if(expected==IntPtr.Zero) throw new InvalidOperationException("Foreground window is unavailable."); expectedForeground=expected.ToInt64(); unexpectedForeground=0; var ready=new ManualResetEventSlim(false); Exception failure=null; guardThread=new Thread(delegate(){ try { guardThreadId=GetCurrentThreadId(); guardDelegate=delegate(IntPtr h,uint e,IntPtr w,int o,int c,uint t,uint m){ if(w!=IntPtr.Zero && w.ToInt64()!=Interlocked.Read(ref expectedForeground)) Interlocked.CompareExchange(ref unexpectedForeground,w.ToInt64(),0); }; guardHook=SetWinEventHook(3,3,IntPtr.Zero,guardDelegate,0,0,0); if(guardHook==IntPtr.Zero)throw new InvalidOperationException("Could not install the foreground-event guard."); ready.Set(); MSG message; while(GetMessage(out message,IntPtr.Zero,0,0)>0){} } catch(Exception error){failure=error;ready.Set();} finally {if(guardHook!=IntPtr.Zero){UnhookWinEvent(guardHook);guardHook=IntPtr.Zero;}} }); guardThread.IsBackground=true;guardThread.Start(); if(!ready.Wait(5000))throw new InvalidOperationException("Foreground-event guard did not become ready."); if(failure!=null)throw new InvalidOperationException("Foreground-event guard failed.",failure); }
  public static void AssertGuard() { long changed=Interlocked.Read(ref unexpectedForeground); if(changed!=0) throw new InvalidOperationException("Foreground activation changed."); if(GetForegroundWindow().ToInt64()!=Interlocked.Read(ref expectedForeground)) throw new InvalidOperationException("Foreground window no longer matches the captured game window."); }
  public static void StopGuard() { if(guardThreadId!=0)PostThreadMessage(guardThreadId,0x0012,UIntPtr.Zero,IntPtr.Zero);if(guardThread!=null && !guardThread.Join(5000))throw new InvalidOperationException("Foreground-event guard did not stop.");guardThread=null;guardThreadId=0;guardDelegate=null; }
  public static WindowIdentity FindWindow(uint pid,string title) { var found=new List<WindowIdentity>(); EnumWindows(delegate(IntPtr hwnd,IntPtr data){var item=Read(hwnd);if(item.ProcessId==pid && item.Title==title)found.Add(item);return true;},IntPtr.Zero); if(found.Count==0)return null;if(found.Count!=1)throw new InvalidOperationException("Expected exactly one OPEMOS top-level window.");return found[0]; }
  public static MonitorBounds[] Monitors() { var found=new List<MonitorBounds>(); EnumDisplayMonitors(IntPtr.Zero,IntPtr.Zero,delegate(IntPtr monitor,IntPtr hdc,IntPtr rect,IntPtr data){var info=new MONITORINFOEX();info.Size=Marshal.SizeOf(info);if(!GetMonitorInfo(monitor,ref info))throw new InvalidOperationException("Could not inspect monitor bounds.");found.Add(new MonitorBounds{Device=info.Device,Left=info.Monitor.Left,Top=info.Monitor.Top,Right=info.Monitor.Right,Bottom=info.Monitor.Bottom,WorkLeft=info.Work.Left,WorkTop=info.Work.Top,WorkRight=info.Work.Right,WorkBottom=info.Work.Bottom});return true;},IntPtr.Zero);return found.ToArray(); }
  public static int[] WindowRect(IntPtr hwnd) { RECT r;if(!GetWindowRect(hwnd,out r))throw new InvalidOperationException("Could not inspect OPEMOS window bounds.");return new[]{r.Left,r.Top,r.Right,r.Bottom}; }
  public static void PlaceNoActivate(IntPtr hwnd,int x,int y,int width,int height) { const uint SWP_NOZORDER=0x4,SWP_NOACTIVATE=0x10,SWP_SHOWWINDOW=0x40,SWP_ASYNCWINDOWPOS=0x4000;if(!SetWindowPos(hwnd,IntPtr.Zero,x,y,width,height,SWP_NOZORDER|SWP_NOACTIVATE|SWP_SHOWWINDOW|SWP_ASYNCWINDOWPOS))throw new InvalidOperationException("Could not place the OPEMOS window without activation."); }
}
'@

$process = $null
$foreground = [OpemosNoActivateNative]::Foreground()
if ($foreground.Handle -eq [IntPtr]::Zero -or $foreground.ProcessId -ne $ExpectedForegroundProcessId) { throw 'The current foreground window does not match the required gaming process.' }
$game = Get-Process -Id $ExpectedForegroundProcessId -ErrorAction Stop
if ((Get-FileHash -LiteralPath $game.MainModule.FileName -Algorithm SHA256).Hash -cne $ExpectedForegroundExecutableSha256.ToUpperInvariant()) { throw 'The foreground gaming executable SHA-256 does not match the required identity.' }
$gameStart = $game.StartTime.ToUniversalTime().Ticks
[OpemosNoActivateNative]::StartGuard($foreground.Handle)
try {
  [OpemosNoActivateNative]::AssertGuard()
  $monitors = @([OpemosNoActivateNative]::Monitors())
  if ($monitors.Count -lt 2) { throw 'The existing multi-monitor layout is unavailable.' }
  $minimumLeft = ($monitors | Measure-Object -Property Left -Minimum).Minimum
  $leftPortrait = @($monitors | Where-Object { $_.Left -eq $minimumLeft -and ($_.Bottom-$_.Top) -gt ($_.Right-$_.Left) })
  if ($leftPortrait.Count -ne 1) { throw 'Exactly one existing leftmost portrait monitor is required.' }
  $monitor = $leftPortrait[0]
  $info = [Diagnostics.ProcessStartInfo]::new(); $info.FileName=$candidate; $info.UseShellExecute=$false; $info.Environment['OPEMOS_NATIVE_NO_ACTIVATE_PROOF']='1'
  $process = [Diagnostics.Process]::new(); $process.StartInfo=$info
  if (-not $process.Start()) { throw 'Could not start the exact OPEMOS candidate.' }
  $deadline=[DateTime]::UtcNow.AddSeconds($StartupTimeoutSeconds); $window=$null
  do { [OpemosNoActivateNative]::AssertGuard(); if($process.HasExited){throw 'OPEMOS exited before its hidden proof window was ready.'}; $window=[OpemosNoActivateNative]::FindWindow([uint32]$process.Id,'SteamOS NVIDIA Builder'); if(-not $window){Start-Sleep -Milliseconds 10} } while(-not $window -and [DateTime]::UtcNow -lt $deadline)
  if(-not $window){throw 'OPEMOS did not create its hidden main window before the deadline.'}
  $rect=[OpemosNoActivateNative]::WindowRect($window.Handle); $width=$rect[2]-$rect[0]; $height=$rect[3]-$rect[1]
  if($width -le 0 -or $height -le 0 -or $width -gt ($monitor.WorkRight-$monitor.WorkLeft) -or $height -gt ($monitor.WorkBottom-$monitor.WorkTop)){throw 'The OPEMOS window does not fit the left portrait monitor work area.'}
  [OpemosNoActivateNative]::PlaceNoActivate($window.Handle,$monitor.WorkLeft,$monitor.WorkTop,$width,$height)
  $observeUntil=[DateTime]::UtcNow.AddSeconds($ObservationSeconds)
  do { [OpemosNoActivateNative]::AssertGuard(); Start-Sleep -Milliseconds 10 } while([DateTime]::UtcNow -lt $observeUntil)
  $placed=[OpemosNoActivateNative]::WindowRect($window.Handle)
  if($placed[0] -lt $monitor.WorkLeft -or $placed[1] -lt $monitor.WorkTop -or $placed[2] -gt $monitor.WorkRight -or $placed[3] -gt $monitor.WorkBottom){throw 'The OPEMOS window is not wholly contained by the left portrait monitor.'}
  $currentGame=Get-Process -Id $ExpectedForegroundProcessId -ErrorAction Stop
  if($currentGame.StartTime.ToUniversalTime().Ticks -ne $gameStart){throw 'The foreground gaming process identity changed.'}
  [OpemosNoActivateNative]::AssertGuard()
  [pscustomobject]@{result='passed';candidate_sha256=$ExecutableSha256.ToLowerInvariant();opemos_pid=$process.Id;foreground_pid=$ExpectedForegroundProcessId;foreground_title=$foreground.Title;foreground_class=$foreground.ClassName;monitor=$monitor.Device;bounds=@($placed)} | ConvertTo-Json -Compress
}
finally {
  if($process -and -not $process.HasExited){Stop-Process -Id $process.Id -Force;$process.WaitForExit()}
  [OpemosNoActivateNative]::StopGuard()
}
}
finally { Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue }
