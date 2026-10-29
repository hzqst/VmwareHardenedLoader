[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RepositoryRoot,

    [Parameter(Mandatory = $true)]
    [string]$ProjectDirectory,

    [Parameter(Mandatory = $true)]
    [string]$IntermediateDirectory,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-FullPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $BasePath $Path))
}

function Reset-SafeDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$AllowedRoot
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullRoot = [System.IO.Path]::GetFullPath($AllowedRoot).TrimEnd('\') + '\'

    if (-not $fullPath.StartsWith($fullRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to reset a directory outside the intermediate directory: $fullPath"
    }

    if (Test-Path -LiteralPath $fullPath) {
        Remove-Item -LiteralPath $fullPath -Recurse -Force
    }

    New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
    return $fullPath
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE`: $FilePath $($Arguments -join ' ')"
    }
}

function Test-HexUInt32 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if (-not $Value.StartsWith('0x', [System.StringComparison]::OrdinalIgnoreCase)) {
        return $false
    }

    $parsed = 0
    return [UInt32]::TryParse(
        $Value.Substring(2),
        [System.Globalization.NumberStyles]::HexNumber,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [ref]$parsed)
}

function Update-KphManifest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,

        [Parameter(Mandatory = $true)]
        [string]$ManifestUrl
    )

    $manifestDirectory = Split-Path -Parent $ManifestPath
    $downloadPath = Join-Path $manifestDirectory ('.kphdyn.download.' + [Guid]::NewGuid().ToString('N') + '.xml')
    $backupPath = Join-Path $manifestDirectory ('.kphdyn.backup.' + [Guid]::NewGuid().ToString('N') + '.xml')

    try {
        Write-Host "Downloading KPH XML from $ManifestUrl"

        Invoke-WebRequest `
            -Uri $ManifestUrl `
            -OutFile $downloadPath `
            -Headers @{ 'Cache-Control' = 'no-cache, no-store'; 'Pragma' = 'no-cache' } `
            -UseBasicParsing

        $settings = New-Object System.Xml.XmlReaderSettings
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $document = New-Object System.Xml.XmlDocument
        $document.XmlResolver = $null

        $reader = [System.Xml.XmlReader]::Create($downloadPath, $settings)
        try {
            $document.Load($reader)
        }
        finally {
            $reader.Dispose()
        }

        $dataNodes = $document.SelectNodes('/dyn/data')
        $fieldNodes = $document.SelectNodes('/dyn/fields')
        if (-not $dataNodes -or $dataNodes.Count -eq 0 -or -not $fieldNodes -or $fieldNodes.Count -eq 0) {
            throw 'Downloaded dynamic data XML has no data or fields nodes.'
        }

        $fieldsById = @{}
        foreach ($fieldsNode in $fieldNodes) {
            $id = $fieldsNode.GetAttribute('id')
            if ([string]::IsNullOrWhiteSpace($id)) {
                throw 'Downloaded dynamic data XML contains a fields node without an id.'
            }
            $fieldsById[$id] = $fieldsNode
        }

        $supportedFirmwareRecords = 0
        $unsupportedFirmwareRecords = 0
        foreach ($dataNode in $dataNodes) {
            $fileName = $dataNode.GetAttribute('file')
            if ($fileName -ne 'ntoskrnl.exe' -and $fileName -ne 'ntkrla57.exe') {
                continue
            }

            $fieldId = $dataNode.InnerText.Trim()
            if (-not $fieldsById.ContainsKey($fieldId)) {
                throw "Downloaded dynamic data XML references missing fields id $fieldId."
            }

            $resource = $fieldsById[$fieldId].SelectSingleNode("field[@name='ExpFirmwareTableResource']")
            $providerList = $fieldsById[$fieldId].SelectSingleNode("field[@name='ExpFirmwareTableProviderListHead']")
            if (-not $resource -or -not $providerList) {
                $unsupportedFirmwareRecords++
                continue
            }

            if (-not (Test-HexUInt32 ($resource.GetAttribute('value'))) -or
                -not (Test-HexUInt32 ($providerList.GetAttribute('value')))) {
                throw "Downloaded dynamic data XML contains an invalid firmware RVA in fields id $fieldId."
            }

            $supportedFirmwareRecords++
        }

        if ($supportedFirmwareRecords -eq 0) {
            throw 'Downloaded dynamic data XML contains no usable firmware records.'
        }

        if (Test-Path -LiteralPath $ManifestPath) {
            [System.IO.File]::Replace($downloadPath, $ManifestPath, $backupPath, $true)
            Remove-Item -LiteralPath $backupPath -Force
        }
        else {
            Move-Item -LiteralPath $downloadPath -Destination $ManifestPath
        }

        Write-Host "Validated KPH XML: $supportedFirmwareRecords firmware records, $unsupportedFirmwareRecords unsupported records."
    }
    finally {
        if (Test-Path -LiteralPath $downloadPath) {
            Remove-Item -LiteralPath $downloadPath -Force
        }
        if (Test-Path -LiteralPath $backupPath) {
            Remove-Item -LiteralPath $backupPath -Force
        }
    }
}

function Ensure-SigningKeyPair {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourcesDirectory,

        [Parameter(Mandatory = $true)]
        [string]$SignToolPath
    )

    New-Item -ItemType Directory -Path $ResourcesDirectory -Force | Out-Null

    $privateKey = Join-Path $ResourcesDirectory 'kph.key'
    $publicKey = Join-Path $ResourcesDirectory 'public.key'
    $privateExists = Test-Path -LiteralPath $privateKey
    $publicExists = Test-Path -LiteralPath $publicKey

    if ($privateExists -xor $publicExists) {
        throw 'Exactly one VmLoader dynamic-data signing key exists. Restore the matching key instead of rotating it.'
    }

    if (-not $privateExists) {
        $temporaryPrivateKey = Join-Path $ResourcesDirectory ('kph.' + [Guid]::NewGuid().ToString('N') + '.tmp')
        $temporaryPublicKey = Join-Path $ResourcesDirectory ('public.' + [Guid]::NewGuid().ToString('N') + '.tmp')
        try {
            Invoke-Checked $SignToolPath @('createkeypair', $temporaryPrivateKey, $temporaryPublicKey)
            if ((Get-Item -LiteralPath $temporaryPrivateKey).Length -eq 0 -or
                (Get-Item -LiteralPath $temporaryPublicKey).Length -eq 0) {
                throw 'CustomSignTool generated an empty key file.'
            }

            Move-Item -LiteralPath $temporaryPrivateKey -Destination $privateKey
            Move-Item -LiteralPath $temporaryPublicKey -Destination $publicKey
            Write-Host "Generated a VmLoader-specific dynamic-data key pair in $ResourcesDirectory."
        }
        finally {
            if (Test-Path -LiteralPath $temporaryPrivateKey) {
                Remove-Item -LiteralPath $temporaryPrivateKey -Force
            }
            if (Test-Path -LiteralPath $temporaryPublicKey) {
                Remove-Item -LiteralPath $temporaryPublicKey -Force
            }
        }
    }

    return @($privateKey, $publicKey)
}

function Write-PublicKeyHeader {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PublicKeyPath,

        [Parameter(Mandatory = $true)]
        [string]$HeaderPath
    )

    $bytes = [System.IO.File]::ReadAllBytes($PublicKeyPath)
    if ($bytes.Length -lt 24 -or $bytes.Length -gt 65536) {
        throw "Unexpected public key length: $($bytes.Length)."
    }
    if ($bytes[0] -ne [byte][char]'R' -or $bytes[1] -ne [byte][char]'S' -or
        $bytes[2] -ne [byte][char]'A' -or $bytes[3] -ne [byte][char]'1') {
        throw 'The dynamic-data public key is not a BCRYPT_RSAPUBLIC_BLOB.'
    }

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.AppendLine('#pragma once')
    [void]$builder.AppendLine()
    [void]$builder.AppendLine("#define VMLOADER_DYNDATA_PUBLIC_KEY_LENGTH $($bytes.Length)u")
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('static const UCHAR VmLoaderDynDataPublicKey[VMLOADER_DYNDATA_PUBLIC_KEY_LENGTH] =')
    [void]$builder.AppendLine('{')

    for ($offset = 0; $offset -lt $bytes.Length; $offset += 12) {
        $end = [Math]::Min($offset + 12, $bytes.Length)
        $values = for ($index = $offset; $index -lt $end; $index++) {
            '0x{0:X2}' -f $bytes[$index]
        }
        [void]$builder.AppendLine('    ' + ($values -join ', ') + ',')
    }

    [void]$builder.AppendLine('};')
    [System.IO.File]::WriteAllText(
        $HeaderPath,
        $builder.ToString(),
        (New-Object System.Text.UTF8Encoding($false)))
}

$projectRoot = [System.IO.Path]::GetFullPath($ProjectDirectory)
$repository = Get-FullPath $RepositoryRoot $projectRoot
$intermediate = Get-FullPath $IntermediateDirectory $projectRoot
$output = Get-FullPath $OutputDirectory $projectRoot
$systemInformer = Join-Path $repository 'thirdparty\systeminformer'
$manifest = Join-Path $systemInformer 'kphlib\kphdyn.xml'
$manifestUrl = 'https://github.com/HLND2T/kphtools/releases/latest/download/kphdyn.xml'
$customBuildProject = Join-Path $systemInformer 'tools\CustomBuildTool\CustomBuildTool.csproj'
$signTool = Join-Path $systemInformer 'tools\CustomSignTool\bin\Release64\CustomSignTool.exe'
$resources = Join-Path $systemInformer 'tools\CustomSignTool\Resources'

if (-not (Test-Path -LiteralPath $customBuildProject) -or -not (Test-Path -LiteralPath $signTool)) {
    throw 'The System Informer build or signing tool is missing.'
}

if (-not [string]::IsNullOrWhiteSpace($env:VMLOADER_KPHDYN_URL)) {
    try {
        $overrideUrl = New-Object System.Uri($env:VMLOADER_KPHDYN_URL, [System.UriKind]::Absolute)
    }
    catch {
        $overrideUrl = $null
    }

    if (-not $overrideUrl -or $overrideUrl.Scheme -ne 'https') {
        throw "VMLOADER_KPHDYN_URL must be an absolute HTTPS URL: $env:VMLOADER_KPHDYN_URL"
    }

    $manifestUrl = $overrideUrl.AbsoluteUri
}

New-Item -ItemType Directory -Path $intermediate -Force | Out-Null
$toolOutput = Reset-SafeDirectory (Join-Path $intermediate 'CustomBuildTool') $intermediate
$toolIntermediate = Reset-SafeDirectory (Join-Path $intermediate 'CustomBuildToolObj') $intermediate
$staging = Reset-SafeDirectory (Join-Path $intermediate 'DynDataStaging') $intermediate

Update-KphManifest $manifest $manifestUrl
$keyPair = Ensure-SigningKeyPair $resources $signTool
$privateKey = $keyPair[0]
$publicKey = $keyPair[1]

Invoke-Checked 'dotnet' @(
    'msbuild',
    $customBuildProject,
    '-restore',
    '-t:Build',
    '-p:Configuration=Release',
    '-p:Platform=x64',
    '-p:TargetFramework=net9.0-windows7.0',
    '-p:PublishAot=false',
    '-p:PublishReadyToRun=false',
    '-p:PublishSingleFile=false',
    '-p:SelfContained=false',
    "-p:OutDir=$toolOutput\",
    "-p:IntDir=$toolIntermediate\",
    '-v:minimal'
)

$customBuildExe = Join-Path $toolOutput 'CustomBuildTool.exe'
$customBuildDll = Join-Path $toolOutput 'CustomBuildTool.dll'
Push-Location $systemInformer
try {
    if (Test-Path -LiteralPath $customBuildExe) {
        Invoke-Checked $customBuildExe @('-dyndata', $staging)
    }
    elseif (Test-Path -LiteralPath $customBuildDll) {
        Invoke-Checked 'dotnet' @($customBuildDll, '-dyndata', $staging)
    }
    else {
        throw 'CustomBuildTool was not produced by dotnet build.'
    }
}
finally {
    Pop-Location
}

$configPath = Join-Path $staging 'ksidyn.bin'
$signaturePath = Join-Path $staging 'ksidyn.sig'
if (-not (Test-Path -LiteralPath $configPath) -or -not (Test-Path -LiteralPath $signaturePath)) {
    throw 'CustomBuildTool did not generate both ksidyn.bin and ksidyn.sig.'
}

Invoke-Checked $signTool @('verify', '-k', $publicKey, '-s', $signaturePath, $configPath)

$configBytes = [System.IO.File]::ReadAllBytes($configPath)
if ($configBytes.Length -lt 4 -or [BitConverter]::ToUInt32($configBytes, 0) -ne 20) {
    throw 'Generated dynamic data is not version 20.'
}

$generatedHeader = Join-Path $systemInformer 'kphlib\include\kphdyn.h'
$generatedSource = Join-Path $systemInformer 'kphlib\kphdyn.c'
$headerText = [System.IO.File]::ReadAllText($generatedHeader)
if (-not $headerText.Contains('KPH_DYN_CONFIGURATION_VERSION           ((ULONG)20)') -or
    -not $headerText.Contains('ULONG ExpFirmwareTableResource;') -or
    -not $headerText.Contains('ULONG ExpFirmwareTableProviderListHead;') -or
    -not (Test-Path -LiteralPath $generatedSource)) {
    throw 'Generated KPH source/header files do not contain the v20 firmware layout.'
}

Write-PublicKeyHeader $publicKey (Join-Path $intermediate 'vmloader_dyndata_public_key.h')

New-Item -ItemType Directory -Path $output -Force | Out-Null
[System.IO.File]::Copy($configPath, (Join-Path $output 'dyndata.bin'), $true)
[System.IO.File]::Copy($signaturePath, (Join-Path $output 'dyndata.sig'), $true)

Write-Host "Published signed dynamic data to $output."
