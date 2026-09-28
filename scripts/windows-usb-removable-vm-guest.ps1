param(
    [Parameter(Mandatory = $true)][string]$CandidatePath,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$SourceCommit,
    [Parameter(Mandatory = $true)][ValidatePattern('^OPEMOS-VM-[A-Za-z0-9-]+$')][string]$ExpectedUsbSerial,
    [Parameter(Mandatory = $true)][string]$EvidencePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-LowerSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-TargetDisk {
    $matches = @()
    foreach ($disk in @(Get-Disk)) {
        if ([string]$disk.BusType -ne 'USB') { continue }
        $drive = Get-CimInstance Win32_DiskDrive -Filter ('Index=' + $disk.Number) -ErrorAction Stop
        if (([string]$drive.SerialNumber).Trim() -ne $ExpectedUsbSerial) { continue }
        if ([string]$drive.MediaType -ne 'Removable Media') {
            throw "The exact QEMU USB target was not reported as Removable Media."
        }
        $matches += [pscustomobject]@{ Disk = $disk; Drive = $drive }
    }
    if ($matches.Count -ne 1) {
        throw "Expected exactly one USB removable disk with the guarded serial; found $($matches.Count)."
    }
    return $matches[0]
}

function Get-RawPrefixSha256([string]$DevicePath, [UInt64]$Length) {
    $stream = [System.IO.File]::Open(
        $DevicePath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite
    )
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $buffer = [byte[]]::new(1024 * 1024)
        [UInt64]$remaining = $Length
        while ($remaining -gt 0) {
            $wanted = [int][Math]::Min([UInt64]$buffer.Length, $remaining)
            $read = $stream.Read($buffer, 0, $wanted)
            if ($read -le 0) { throw 'The raw USB readback ended early.' }
            [void]$sha.TransformBlock($buffer, 0, $read, $null, 0)
            $remaining -= [UInt64]$read
        }
        [void]$sha.TransformFinalBlock([byte[]]::new(0), 0, 0)
        return ([BitConverter]::ToString($sha.Hash)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The removable-USB VM guest gate must run elevated.'
}

$candidate = (Resolve-Path -LiteralPath $CandidatePath).Path
$candidateItem = Get-Item -LiteralPath $candidate
if ($candidateItem.PSIsContainer -or $candidateItem.Length -lt 1) {
    throw 'The candidate executable is invalid.'
}
$evidenceFull = [System.IO.Path]::GetFullPath($EvidencePath)
$root = Join-Path ([System.IO.Path]::GetDirectoryName($evidenceFull)) 'writer-exchange'
if (Test-Path -LiteralPath $root) { throw 'The guarded writer exchange already exists.' }
[void](New-Item -ItemType Directory -Path $root)

try {
    $selected = Get-TargetDisk
    $disk = $selected.Disk
    $drive = $selected.Drive
    if ($disk.IsBoot -or $disk.IsSystem -or $disk.IsReadOnly -or $disk.IsOffline) {
        throw 'The guarded USB target failed its initial safety state.'
    }
    if ([UInt64]$disk.Size -lt 64MB -or [UInt64]$disk.Size -gt 2TB) {
        throw 'The guarded USB target has an invalid capacity.'
    }
    if (@(512, 1024, 2048, 4096) -notcontains [UInt64]$disk.LogicalSectorSize) {
        throw 'The guarded USB target has an unsupported logical sector size.'
    }

    $offlineErrorId = ''
    $offlineRefused = $false
    try {
        Set-Disk -Number $disk.Number -IsOffline $true -ErrorAction Stop
    }
    catch {
        $offlineRefused = $true
        $offlineErrorId = [string]$_.FullyQualifiedErrorId
    }
    $afterProbe = Get-Disk -Number $disk.Number -ErrorAction Stop
    if (-not $offlineRefused -or $afterProbe.IsOffline -or $offlineErrorId -notmatch 'Set-Disk') {
        if ($afterProbe.IsOffline) {
            Set-Disk -Number $disk.Number -IsOffline $false -ErrorAction SilentlyContinue
        }
        throw 'Windows did not reproduce the removable-media Set-Disk offline refusal.'
    }

    if ([string]$disk.PartitionStyle -eq 'RAW') {
        Initialize-Disk -Number $disk.Number -PartitionStyle GPT -PassThru | Out-Null
    }
    $existingPartitions = @(Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue)
    if ($existingPartitions.Count -eq 0) {
        $partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
        Format-Volume -Partition $partition -FileSystem NTFS -NewFileSystemLabel 'OPEMOS_VM_USB' -Confirm:$false | Out-Null
    }

    $imagePath = Join-Path $root 'source.img'
    $imageLength = 8MB
    $image = [System.IO.File]::Open($imagePath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $buffer = [byte[]]::new(1024 * 1024)
        for ($offset = 0; $offset -lt $buffer.Length; $offset++) {
            $buffer[$offset] = [byte](($offset * 31 + 17) % 251)
        }
        for ($written = 0; $written -lt $imageLength; $written += $buffer.Length) {
            $image.Write($buffer, 0, $buffer.Length)
        }
        $image.Flush($true)
    }
    finally {
        $image.Dispose()
    }
    $sourceSha = Get-LowerSha256 $imagePath
    $manifestPath = "$imagePath.manifest.json"
    $manifest = [ordered]@{
        schemaVersion = 1
        output = [ordered]@{
            filename = 'source.img'
            format = 'raw'
            bytes = [UInt64]$imageLength
            sha256 = $sourceSha
        }
    } | ConvertTo-Json -Compress -Depth 5
    [System.IO.File]::WriteAllText($manifestPath, $manifest, [System.Text.UTF8Encoding]::new($false))

    $selected = Get-TargetDisk
    $disk = $selected.Disk
    $drive = $selected.Drive
    $number = [UInt32]$disk.Number
    $deviceIdentifier = "PhysicalDrive$number"
    $deviceNode = "\\.\PHYSICALDRIVE$number"
    $mediaName = [string]$disk.FriendlyName
    $uniqueId = [string]$disk.UniqueId
    $serial = ([string]$drive.SerialNumber).Trim()
    if ([string]::IsNullOrEmpty($uniqueId) -or [string]::IsNullOrEmpty($serial)) {
        throw 'The guarded USB target lacks stable identity fields.'
    }
    $nul = [char]0
    $identity = "$number$nul$deviceNode$nul$([UInt64]$disk.Size)$nul$([UInt64]$disk.LogicalSectorSize)$nul$mediaName$nul$uniqueId$nul$serial"
    $identityBytes = [System.Text.Encoding]::UTF8.GetBytes($identity)
    $identityHasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $identityHash = $identityHasher.ComputeHash($identityBytes)
    }
    finally {
        $identityHasher.Dispose()
    }
    $identityToken = ([BitConverter]::ToString($identityHash)).Replace('-', '').ToLowerInvariant()

    $requestPath = Join-Path $root 'request.json'
    $receiptPath = Join-Path $root 'receipt.json'
    $progressPath = Join-Path $root 'progress.json'
    $request = [ordered]@{
        schemaVersion = 1
        expiresAtUnixMs = [DateTimeOffset]::UtcNow.AddSeconds(60).ToUnixTimeMilliseconds()
        imagePath = $imagePath
        imageBytes = [UInt64]$imageLength
        imageSha256 = $sourceSha
        deviceIdentifier = $deviceIdentifier
        deviceNode = $deviceNode
        mediaName = $mediaName
        deviceBytes = [UInt64]$disk.Size
        blockSize = [UInt64]$disk.LogicalSectorSize
        identityToken = $identityToken
    } | ConvertTo-Json -Compress -Depth 4
    [System.IO.File]::WriteAllText($requestPath, $request, [System.Text.UTF8Encoding]::new($false))
    $requestSha = Get-LowerSha256 $requestPath

    $helper = Start-Process -FilePath $candidate -ArgumentList @(
        'windows-usb-writer-helper', '--request', $requestPath,
        '--request-sha256', $requestSha, '--receipt', $receiptPath,
        '--progress', $progressPath
    ) -NoNewWindow -Wait -PassThru
    $helperExitCode = $helper.ExitCode
    if ($helperExitCode -ne 0 -or -not (Test-Path -LiteralPath $receiptPath)) {
        throw "The exact Windows writer helper failed with exit code $helperExitCode."
    }
    $receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
    if ($receipt.schemaVersion -ne 1 -or $receipt.requestSha256 -ne $requestSha -or
        -not $receipt.success -or $receipt.verifiedSha256 -ne $sourceSha -or
        $receipt.ejected -or -not [string]::IsNullOrEmpty([string]$receipt.error)) {
        throw ("The exact Windows writer helper returned an invalid success receipt " +
            "(exit=$helperExitCode schema=$($receipt.schemaVersion) requestMatch=$($receipt.requestSha256 -eq $requestSha) " +
            "success=$($receipt.success) verifiedMatch=$($receipt.verifiedSha256 -eq $sourceSha) " +
            "ejected=$($receipt.ejected) error=$([string]$receipt.error)).")
    }
    $afterWrite = Get-TargetDisk
    if ($afterWrite.Disk.IsOffline) { throw 'The writer did not return the removable target online.' }
    $rawSha = Get-RawPrefixSha256 $deviceNode ([UInt64]$imageLength)
    $sourceAfter = Get-LowerSha256 $imagePath
    if ($rawSha -ne $sourceSha -or $sourceAfter -ne $sourceSha) {
        throw 'Raw USB readback or source preservation failed.'
    }

    $result = [ordered]@{
        schemaVersion = 1
        test = 'windows-usb-removable-vm'
        sourceCommit = $SourceCommit
        executable = [ordered]@{
            size = [UInt64]$candidateItem.Length
            sha256 = Get-LowerSha256 $candidate
        }
        target = [ordered]@{
            busType = [string]$disk.BusType
            mediaType = [string]$drive.MediaType
            serialNumber = $serial
            isBoot = [bool]$disk.IsBoot
            isSystem = [bool]$disk.IsSystem
            isReadOnly = [bool]$disk.IsReadOnly
            initiallyOffline = [bool]$disk.IsOffline
            deviceBytes = [UInt64]$disk.Size
            blockSize = [UInt64]$disk.LogicalSectorSize
        }
        offlineProbe = [ordered]@{
            attempted = $true
            refused = $offlineRefused
            remainedOnline = -not [bool]$afterProbe.IsOffline
            fullyQualifiedErrorId = $offlineErrorId
        }
        writer = [ordered]@{
            helperExitCode = [int]$helperExitCode
            receiptSuccess = [bool]$receipt.success
            sourceSha256 = $sourceSha
            verifiedSha256 = [string]$receipt.verifiedSha256
            rawReadbackSha256 = $rawSha
            sourceUnchanged = ($sourceAfter -eq $sourceSha)
            targetOnlineAfter = -not [bool]$afterWrite.Disk.IsOffline
            ejected = [bool]$receipt.ejected
        }
    }
    $json = $result | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($evidenceFull, $json, [System.Text.UTF8Encoding]::new($false))
}
finally {
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}
