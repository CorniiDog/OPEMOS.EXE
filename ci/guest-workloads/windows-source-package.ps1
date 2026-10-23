$ErrorActionPreference = 'Stop'
# Fixed A structural package validation INSIDE the admitted Windows guest.
# No app launch, UI/formatting/test gate, signing or publication operation.
$path = 'dist/windows/OPEMOS.EXE-windows-x86_64-unsigned.exe'
$before = Get-Item -LiteralPath $path -Force
if ($before.PSIsContainer -or ($before.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
  throw 'Native package must be an actual regular non-reparse executable.'
}
$stream = [IO.File]::Open($before.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
try {
  $reader = [IO.BinaryReader]::new($stream)
  if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5A4D) { throw 'Missing native DOS/PE header.' }
  $stream.Position = 60
  $offset = $reader.ReadUInt32()
  if ($offset -lt 64 -or $offset -gt 2097152 -or $offset + 24 -gt $stream.Length) { throw 'Invalid bounded PE header offset.' }
  $stream.Position = $offset
  if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664) { throw 'Native package must be AMD64 PE.' }
  $stream.Position = 0
  $algorithm = [Security.Cryptography.SHA256]::Create()
  try { $sha = [Convert]::ToHexString($algorithm.ComputeHash($stream)).ToLowerInvariant() }
  finally { $algorithm.Dispose() }
  $signature = Get-AuthenticodeSignature -LiteralPath $before.FullName
  if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::NotSigned) {
    throw "Expected unchanged unsigned test output; actual signature status $($signature.Status)"
  }
  $after = Get-Item -LiteralPath $before.FullName -Force
  if ($after.Length -ne $before.Length -or $after.LastWriteTimeUtc.Ticks -ne $before.LastWriteTimeUtc.Ticks) {
    throw 'Native output changed during structural validation.'
  }
  $receipt = @{kind='OMEN_NATIVE_WINDOWS_PACKAGE_V1'; source_commit=$env:OPEMOS_EXE_COMMIT;
    executable=$before.Name; bytes=$stream.Length; sha256=$sha; machine='AMD64'; signature='NotSigned';
    location='OMEN_VM'; app_test_passed=$false; GUI_image_accepted=$false; publication_authorized=$false}
  $raw = [Text.Encoding]::UTF8.GetBytes(($receipt | ConvertTo-Json -Compress) + "`n")
  $out = [IO.File]::Open('dist/windows/native-package.json', [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try { $out.Write($raw,0,$raw.Length); $out.Flush($true) } finally { $out.Dispose() }
} finally { $stream.Dispose() }
