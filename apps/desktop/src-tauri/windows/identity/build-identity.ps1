[CmdletBinding(DefaultParameterSetName = "Thumbprint")]
param(
    [Parameter(Mandatory = $true)]
    [string]$Publisher,

    [Parameter(Mandatory = $true, ParameterSetName = "Thumbprint")]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $true, ParameterSetName = "Pfx")]
    [string]$PfxPath,

    [Parameter(ParameterSetName = "Pfx")]
    [string]$PfxPassword = "",

    [string]$TimestampUrl = "https://timestamp.digicert.com",
    [string]$Version = "",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Drawing

function Write-SquarePng {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,

        [Parameter(Mandatory = $true)]
        [string]$Destination,

        [Parameter(Mandatory = $true)]
        [int]$Size
    )

    $SourceImage = [System.Drawing.Image]::FromFile($Source)
    try {
        $Bitmap = [System.Drawing.Bitmap]::new(
            $Size,
            $Size,
            [System.Drawing.Imaging.PixelFormat]::Format32bppArgb
        )
        try {
            $Graphics = [System.Drawing.Graphics]::FromImage($Bitmap)
            try {
                $Graphics.Clear([System.Drawing.Color]::Transparent)
                $Graphics.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceCopy
                $Graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
                $Graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
                $Graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
                $Graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
                $Graphics.DrawImage($SourceImage, 0, 0, $Size, $Size)
            } finally {
                $Graphics.Dispose()
            }
            $Bitmap.Save($Destination, [System.Drawing.Imaging.ImageFormat]::Png)
        } finally {
            $Bitmap.Dispose()
        }
    } finally {
        $SourceImage.Dispose()
    }
}

$IdentityDir = $PSScriptRoot
$TauriDir = (Resolve-Path (Join-Path $IdentityDir "..\..")).Path
if (-not $Version) {
    $TauriConfig = Get-Content -LiteralPath (Join-Path $TauriDir "tauri.conf.json") -Raw |
        ConvertFrom-Json
    $Version = [string]$TauriConfig.version
}
$VersionParts = @($Version.Split('.'))
if ($VersionParts.Count -gt 4 -or $VersionParts.Count -lt 1) {
    throw "Identity package version must contain between one and four numeric components: $Version"
}
while ($VersionParts.Count -lt 4) {
    $VersionParts += "0"
}
foreach ($Part in $VersionParts) {
    if ($Part -notmatch '^\d+$' -or [int]$Part -gt 65535) {
        throw "Invalid identity package version component '$Part' in $Version"
    }
}
$PackageVersion = $VersionParts -join "."

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $IdentityDir "dist"
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path

$KitsRoot = (Get-ItemProperty `
    -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots" `
    -Name KitsRoot10).KitsRoot10
$SdkBin = Get-ChildItem -LiteralPath (Join-Path $KitsRoot "bin") -Directory |
    Where-Object {
        Test-Path -LiteralPath (Join-Path $_.FullName "x64\makeappx.exe") -PathType Leaf
    } |
    Sort-Object { [version]$_.Name } -Descending |
    Select-Object -First 1
if ($null -eq $SdkBin) {
    throw "A Windows 10/11 SDK containing MakeAppx.exe was not found"
}
$MakeAppx = Join-Path $SdkBin.FullName "x64\makeappx.exe"
$SignTool = Join-Path $SdkBin.FullName "x64\signtool.exe"

if ($PSCmdlet.ParameterSetName -eq "Thumbprint") {
    $Certificate = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My |
        Where-Object { $_.Thumbprint -eq $CertificateThumbprint.Replace(' ', '') } |
        Select-Object -First 1
} else {
    $PfxPath = (Resolve-Path -LiteralPath $PfxPath).Path
    $Certificate = Get-PfxCertificate -FilePath $PfxPath
}
if ($null -eq $Certificate) {
    throw "The production signing certificate was not found"
}
if ($Certificate.Subject -ne $Publisher) {
    throw "Certificate subject '$($Certificate.Subject)' does not match package publisher '$Publisher'"
}

$Staging = Join-Path ([System.IO.Path]::GetTempPath()) ("hybridcipher-identity-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $Staging | Out-Null
try {
    $Manifest = Get-Content -LiteralPath (Join-Path $IdentityDir "AppxManifest.xml.in") -Raw
    $Manifest = $Manifest.Replace("@PUBLISHER@", $Publisher).Replace("@VERSION@", $PackageVersion)
    Set-Content -LiteralPath (Join-Path $Staging "AppxManifest.xml") -Value $Manifest -Encoding utf8

    $MsixPath = Join-Path $OutputDirectory "HybridCipher.identity.msix"
    & $MakeAppx pack /o /nv /d $Staging /p $MsixPath
    if ($LASTEXITCODE -ne 0) {
        throw "MakeAppx failed with exit code $LASTEXITCODE"
    }

    $SignArguments = @("sign", "/fd", "SHA256")
    if ($TimestampUrl) {
        $SignArguments += @("/td", "SHA256", "/tr", $TimestampUrl)
    }
    if ($PSCmdlet.ParameterSetName -eq "Thumbprint") {
        $SignArguments += @("/sha1", $CertificateThumbprint.Replace(' ', ''))
    } else {
        $SignArguments += @("/f", $PfxPath)
        if ($PfxPassword) {
            $SignArguments += @("/p", $PfxPassword)
        }
    }
    $SignArguments += $MsixPath
    & $SignTool @SignArguments
    if ($LASTEXITCODE -ne 0) {
        throw "SignTool failed to sign the identity package (exit code $LASTEXITCODE)"
    }
    & $SignTool verify /pa /all $MsixPath
    if ($LASTEXITCODE -ne 0) {
        throw "The signed identity package failed signature verification"
    }

    # Sparse-package visual assets are resolved from the external install location,
    # not from inside the identity-only MSIX.
    $Assets = Join-Path $OutputDirectory "Assets"
    New-Item -ItemType Directory -Path $Assets -Force | Out-Null
    $SourceIcon = Join-Path $TauriDir "icons\512x512.png"
    Write-SquarePng -Source $SourceIcon -Destination (Join-Path $Assets "StoreLogo.png") -Size 50
    Write-SquarePng -Source $SourceIcon -Destination (Join-Path $Assets "Square150x150Logo.png") -Size 150
    Write-SquarePng -Source $SourceIcon -Destination (Join-Path $Assets "Square44x44Logo.png") -Size 44
    Copy-Item -LiteralPath (Join-Path $TauriDir "icons\icon.ico") `
        -Destination (Join-Path $OutputDirectory "HybridCipher.ico") -Force
    Copy-Item -LiteralPath (Join-Path $IdentityDir "register-identity.ps1") `
        -Destination (Join-Path $OutputDirectory "register-identity.ps1") -Force

    Write-Host "Signed sparse identity package: $MsixPath"
    Write-Host "Publisher: $Publisher"
    Write-Host "Version: $PackageVersion"
} finally {
    if (Test-Path -LiteralPath $Staging) {
        Remove-Item -LiteralPath $Staging -Recurse -Force
    }
}
