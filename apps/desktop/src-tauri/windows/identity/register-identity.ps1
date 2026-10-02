[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Install", "Uninstall")]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [string]$InstallDirectory
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression.FileSystem

$PackageName = "HybridCipher.Desktop"

function Test-InstalledPackagePayload {
    param([string]$PackagePath, [string]$InstalledPath)
    $Root = [IO.Path]::GetFullPath($InstalledPath).TrimEnd('\') + '\'
    $PackageArchive = [IO.Compression.ZipFile]::OpenRead($PackagePath)
    try {
        foreach ($Entry in $PackageArchive.Entries) {
            # These describe/sign the package, not its installed application payload.
            if ($Entry.FullName -in @('AppxBlockMap.xml', 'AppxSignature.p7x', '[Content_Types].xml', 'AppxMetadata/CodeIntegrity.cat') -or $Entry.FullName.EndsWith('/')) { continue }
            $InstalledFile = [IO.Path]::GetFullPath((Join-Path $Root $Entry.FullName))
            if (-not $InstalledFile.StartsWith($Root, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $InstalledFile -PathType Leaf)) { return $false }
            $ExpectedStream = $Entry.Open()
            $ActualStream = [IO.File]::OpenRead($InstalledFile)
            try {
                if ($Entry.FullName -eq 'AppxManifest.xml') {
                    # Windows removes a UTF-8 BOM when staging the manifest.
                    # Compare the exact decoded text so that a BOM alone does
                    # not make an otherwise identical registration look stale.
                    $ExpectedReader = [IO.StreamReader]::new($ExpectedStream)
                    $ActualReader = [IO.StreamReader]::new($ActualStream)
                    if ($ExpectedReader.ReadToEnd() -cne $ActualReader.ReadToEnd()) { return $false }
                } else {
                    $Hasher = [Security.Cryptography.SHA256]::Create()
                    try {
                        $ExpectedHash = [Convert]::ToBase64String($Hasher.ComputeHash($ExpectedStream))
                        $ActualHash = [Convert]::ToBase64String($Hasher.ComputeHash($ActualStream))
                        if ($ExpectedHash -cne $ActualHash) { return $false }
                    } finally {
                        $Hasher.Dispose()
                    }
                }
            } finally {
                $ExpectedStream.Dispose()
                $ActualStream.Dispose()
            }
        }
        return $true
    } finally { $PackageArchive.Dispose() }
}
if ($Mode -eq "Uninstall") {
    Get-AppxPackage -Name $PackageName -ErrorAction SilentlyContinue |
        Remove-AppxPackage -ErrorAction Stop
    exit 0
}

if ([Environment]::OSVersion.Version.Build -lt 19041) {
    throw "HybridCipher cloud-file mounts require Windows 10 build 19041 or newer"
}
$InstallDirectory = (Resolve-Path -LiteralPath $InstallDirectory).Path
$MsixPath = Join-Path $InstallDirectory "HybridCipher.identity.msix"
if (-not (Test-Path -LiteralPath $MsixPath -PathType Leaf)) {
    throw "HybridCipher identity package is missing from $MsixPath"
}

$Archive = [System.IO.Compression.ZipFile]::OpenRead($MsixPath)
try {
    $ManifestEntry = $Archive.GetEntry("AppxManifest.xml")
    if ($null -eq $ManifestEntry) {
        throw "HybridCipher identity package has no AppxManifest.xml"
    }
    $Reader = [System.IO.StreamReader]::new($ManifestEntry.Open())
    try {
        [xml]$Manifest = $Reader.ReadToEnd()
    } finally {
        $Reader.Dispose()
    }
    $DesiredVersion = [version]$Manifest.Package.Identity.Version
    $DesiredPublisher = [string]$Manifest.Package.Identity.Publisher
    if ([string]$Manifest.Package.Identity.Name -ne $PackageName) {
        throw "Unexpected identity package name"
    }
} finally {
    $Archive.Dispose()
}

$Existing = Get-AppxPackage -Name $PackageName -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($null -ne $Existing -and [version]$Existing.Version -eq $DesiredVersion) {
    # Desktop updates often retain the same sparse identity. Reusing it must not
    # run uninstall cleanup: mounted files and pending operations belong to the user.
    $PackageManager = New-Object Windows.Management.Deployment.PackageManager
    $RegisteredPackage = $PackageManager.FindPackageForUser('', $Existing.PackageFullName)
    $ExternalLocation = $RegisteredPackage.EffectiveExternalLocation
    $SameLocation = $null -ne $ExternalLocation -and
        [IO.Path]::GetFullPath($ExternalLocation.Path).TrimEnd('\') -ieq $InstallDirectory.TrimEnd('\')
    if ($Existing.Publisher -eq $DesiredPublisher -and [string]$Existing.Status -eq 'Ok' -and
        $SameLocation -and (Test-InstalledPackagePayload -PackagePath $MsixPath -InstalledPath $Existing.InstallLocation)) {
        Write-Output "Existing HybridCipher identity verified. Explorer registrations and pending work were preserved."
        exit 0
    }
    throw "The existing same-version HybridCipher identity differs in payload, publisher, status, or install location. No Explorer roots were removed. Use an installer with a newer identity-package version or repair the existing registration."
}

Add-AppxPackage -Path $MsixPath -ExternalLocation $InstallDirectory -ErrorAction Stop

$Registered = Get-AppxPackage -Name $PackageName -ErrorAction SilentlyContinue
if ($null -eq $Registered) {
    throw "Windows did not retain the HybridCipher sparse package registration"
}
