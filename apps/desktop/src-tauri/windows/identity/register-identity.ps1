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
} finally {
    $Archive.Dispose()
}

$Existing = Get-AppxPackage -Name $PackageName -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($null -ne $Existing -and [version]$Existing.Version -eq $DesiredVersion) {
    $Executable = Join-Path $InstallDirectory "hybridcipher-desktop.exe"
    if (Test-Path -LiteralPath $Executable -PathType Leaf) {
        # GUI-subsystem executables do not reliably initialize PowerShell's
        # $LASTEXITCODE. Start the cleanup explicitly and read the waited
        # process result so repair installs always get a defined exit code.
        $CleanupProcess = Start-Process -FilePath $Executable `
            -ArgumentList "--unregister-shell-roots" `
            -Wait `
            -PassThru
        if ($CleanupProcess.ExitCode -ne 0) {
            throw "HybridCipher could not safely remove Explorer sync roots before identity repair"
        }
    }
    Remove-AppxPackage -Package $Existing.PackageFullName -ErrorAction Stop
}

Add-AppxPackage -Path $MsixPath -ExternalLocation $InstallDirectory -ErrorAction Stop

$Registered = Get-AppxPackage -Name $PackageName -ErrorAction SilentlyContinue
if ($null -eq $Registered) {
    throw "Windows did not retain the HybridCipher sparse package registration"
}
