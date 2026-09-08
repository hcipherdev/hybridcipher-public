<#
Purpose:
  Build the canonical unsigned HybridCipher Windows desktop verification
  artifact from public source and write a SHA-256 file beside it.

How to run from the repository root:
  powershell -ExecutionPolicy Bypass -File .\scripts\winos\public_desktop_verify.ps1

Output:
  target\x86_64-pc-windows-msvc\release\bundle\nsis\HybridCipher_<version>_x64-setup.exe
  target\x86_64-pc-windows-msvc\release\bundle\nsis\HybridCipher_<version>_x64-setup.exe.sha256
#>

[CmdletBinding()]
param(
    [ValidateSet("x86_64-pc-windows-msvc")]
    [string]$TargetTriple = "x86_64-pc-windows-msvc"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$DesktopDir = Join-Path $Repo "apps\desktop"
$DesktopCargoToml = Join-Path $DesktopDir "src-tauri\Cargo.toml"
$DesktopTauriConfig = Join-Path $DesktopDir "src-tauri\tauri.conf.json"
$WindowsUnsignedConfig = Join-Path $DesktopDir "src-tauri\tauri.windows.test.conf.json"
$CliPath = Join-Path $Repo "target\$TargetTriple\release\hybridcipher.exe"
$DesktopExePath = Join-Path $Repo "target\$TargetTriple\release\hybridcipher-desktop.exe"
$BundleDir = Join-Path $Repo "target\$TargetTriple\release\bundle\nsis"

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList
    )

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE`: $FilePath $($ArgumentList -join ' ')"
    }
}

function Find-Executable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [string[]]$Candidates = @()
    )

    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }

    foreach ($candidate in $Candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    return $null
}

function Initialize-MsvcEnvironment {
    $programFilesX86 = [Environment]::GetFolderPath("ProgramFilesX86")
    $vsWhere = Join-Path $programFilesX86 "Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path -LiteralPath $vsWhere -PathType Leaf)) {
        throw "Visual Studio Build Tools were not found. Install the Desktop development with C++ workload."
    }

    $vsInstallPath = (& $vsWhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath | Select-Object -First 1)
    if (-not $vsInstallPath) {
        throw "Visual Studio C++ build tools were not found. Install the Desktop development with C++ workload."
    }

    $devShellModule = Join-Path $vsInstallPath "Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
    if (-not (Test-Path -LiteralPath $devShellModule -PathType Leaf)) {
        throw "Visual Studio Developer PowerShell module was not found: $devShellModule"
    }

    Import-Module $devShellModule
    Enter-VsDevShell -VsInstallPath $vsInstallPath `
        -SkipAutomaticLocation `
        -DevCmdArguments "-arch=x64 -host_arch=x64" | Out-Null

    $kitsRoot = (Get-ItemProperty `
        -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots" `
        -Name KitsRoot10 `
        -ErrorAction SilentlyContinue).KitsRoot10
    if (-not $kitsRoot) {
        $kitsRoot = Join-Path $programFilesX86 "Windows Kits\10\"
    }

    $sdkLibRoot = Join-Path $kitsRoot "Lib"
    $sdkVersionDir = Get-ChildItem -LiteralPath $sdkLibRoot -Directory |
        Where-Object {
            $_.Name -match "^\d+\.\d+\.\d+\.\d+$" -and
            (Test-Path -LiteralPath (Join-Path $_.FullName "um\x64\kernel32.lib") -PathType Leaf)
        } |
        Sort-Object { [version]$_.Name } -Descending |
        Select-Object -First 1
    if ($null -eq $sdkVersionDir) {
        throw "A Windows 10 or Windows 11 SDK with x64 libraries was not found."
    }

    $sdkVersion = $sdkVersionDir.Name
    $env:WindowsSdkDir = $kitsRoot.TrimEnd("\") + "\"
    $env:WindowsSDKLibVersion = "$sdkVersion\"
    $env:LIB = @(
        (Join-Path $kitsRoot "Lib\$sdkVersion\um\x64")
        (Join-Path $kitsRoot "Lib\$sdkVersion\ucrt\x64")
        $env:LIB
    ) -join ";"
    $env:INCLUDE = @(
        (Join-Path $kitsRoot "Include\$sdkVersion\um")
        (Join-Path $kitsRoot "Include\$sdkVersion\shared")
        (Join-Path $kitsRoot "Include\$sdkVersion\winrt")
        (Join-Path $kitsRoot "Include\$sdkVersion\ucrt")
        $env:INCLUDE
    ) -join ";"
}

function Get-DesktopCargoVersion {
    $text = Get-Content -Raw -LiteralPath $DesktopCargoToml
    $packageMatch = [regex]::Match(
        $text,
        "(?ms)^\[package\]\s*(?<body>.*?)(?=^\[|\z)"
    )
    if (-not $packageMatch.Success) {
        return $null
    }

    $versionMatch = [regex]::Match(
        $packageMatch.Groups["body"].Value,
        '(?m)^version\s*=\s*"(?<version>[^"]+)"'
    )
    if (-not $versionMatch.Success) {
        return $null
    }

    return $versionMatch.Groups["version"].Value
}

function Get-DesktopTauriConfigVersion {
    $config = Get-Content -Raw -LiteralPath $DesktopTauriConfig | ConvertFrom-Json
    return $config.version
}

function Test-DesktopVersionConsistency {
    $cargoVersion = Get-DesktopCargoVersion
    $tauriVersion = Get-DesktopTauriConfigVersion

    if (-not $cargoVersion) {
        throw "Failed to detect desktop version from apps\desktop\src-tauri\Cargo.toml."
    }
    if (-not $tauriVersion) {
        throw "Failed to detect desktop version from apps\desktop\src-tauri\tauri.conf.json."
    }
    if ($cargoVersion -ne $tauriVersion) {
        throw "Desktop version mismatch: Cargo.toml=$cargoVersion tauri.conf.json=$tauriVersion."
    }
}

function Find-NodeDirectory {
    $nodeCandidates = @()
    if ($env:ProgramFiles) {
        $nodeCandidates += (Join-Path $env:ProgramFiles "nodejs")
    }
    if ($env:LOCALAPPDATA) {
        $nodeCandidates += (Join-Path $env:LOCALAPPDATA "Programs\nodejs")
    }

    $portableNodeRoot = Join-Path $env:TEMP "hybridcipher-build-tools"
    if (Test-Path -LiteralPath $portableNodeRoot -PathType Container) {
        $portableNode = Get-ChildItem -LiteralPath $portableNodeRoot -Directory -Filter "node-v*-win-x64" |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        if ($null -ne $portableNode) {
            $nodeCandidates += $portableNode.FullName
        }
    }

    $nodeDir = $nodeCandidates |
        Where-Object { Test-Path -LiteralPath (Join-Path $_ "npm.cmd") -PathType Leaf } |
        Select-Object -First 1
    if (-not $nodeDir) {
        $npmCommand = Get-Command "npm.cmd" -ErrorAction SilentlyContinue
        if ($null -ne $npmCommand) {
            $nodeDir = Split-Path -Parent $npmCommand.Source
        }
    }
    if (-not $nodeDir) {
        throw "Node.js 20 and npm were not found. Install Node.js 20 LTS first."
    }

    return $nodeDir
}

function Find-WindowsInstaller {
    if (-not (Test-Path -LiteralPath $BundleDir -PathType Container)) {
        throw "The build completed without producing the NSIS bundle directory: $BundleDir"
    }

    $installer = Get-ChildItem -LiteralPath $BundleDir -Filter "HybridCipher_*_x64-setup.exe" -File |
        Sort-Object LastWriteTime, Name -Descending |
        Select-Object -First 1
    if ($null -eq $installer) {
        throw "The build completed without producing a HybridCipher NSIS setup installer under: $BundleDir"
    }

    return $installer
}

function Write-Sha256File {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$Artifact
    )

    $hash = (Get-FileHash -LiteralPath $Artifact.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $shaPath = "$($Artifact.FullName).sha256"
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($shaPath, "$hash  $($Artifact.Name)`n", $utf8NoBom)

    return [PSCustomObject]@{
        Hash = $hash
        Path = $shaPath
    }
}

if ($env:OS -ne "Windows_NT") {
    throw "This script must run on Windows."
}

if (-not (Test-Path -LiteralPath $WindowsUnsignedConfig -PathType Leaf)) {
    throw "Unsigned Windows Tauri config missing: $WindowsUnsignedConfig"
}

$runningApp = Get-Process -Name "hybridcipher-desktop" -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -eq $DesktopExePath } |
    Select-Object -First 1
if ($null -ne $runningApp) {
    throw "HybridCipher is running from the build output. Right-click its tray icon, choose 'Quit HybridCipher', and run this script again."
}

$cargo = Find-Executable -Name "cargo.exe" -Candidates @(
    (Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe")
)
$rustup = Find-Executable -Name "rustup.exe" -Candidates @(
    (Join-Path $env:USERPROFILE ".cargo\bin\rustup.exe")
)
if (-not $cargo -or -not $rustup) {
    throw "Rust and rustup were not found. Install the stable MSVC Rust toolchain first."
}

$nodeDir = Find-NodeDirectory
$env:Path = "$nodeDir;$([System.IO.Path]::GetDirectoryName($cargo));$env:Path"
$npm = Join-Path $nodeDir "npm.cmd"
$npx = Join-Path $nodeDir "npx.cmd"

Write-Log "Preparing Windows build environment"
Initialize-MsvcEnvironment
Invoke-NativeCommand -FilePath $rustup -ArgumentList @(
    "target", "add", $TargetTriple
)

Test-DesktopVersionConsistency

Write-Log "Installing desktop frontend dependencies"
Push-Location $DesktopDir
try {
    Invoke-NativeCommand -FilePath $npm -ArgumentList @("ci")
} finally {
    Pop-Location
}

Write-Log "Building CLI for $TargetTriple"
Push-Location $Repo
try {
    Invoke-NativeCommand -FilePath $cargo -ArgumentList @(
        "build",
        "--release",
        "--target", $TargetTriple,
        "-p", "hybridcipher-cli",
        "--bin", "hybridcipher",
        "--features", "individual-edition"
    )
} finally {
    Pop-Location
}

if (-not (Test-Path -LiteralPath $CliPath -PathType Leaf)) {
    throw "CLI binary missing after build: $CliPath"
}
$env:HYBRIDCIPHER_CLI_PATH = (Resolve-Path -LiteralPath $CliPath).Path

Write-Log "Building unsigned Tauri NSIS bundle for $TargetTriple"
Push-Location $DesktopDir
try {
    Invoke-NativeCommand -FilePath $npx -ArgumentList @(
        "tauri", "build",
        "--target", $TargetTriple,
        "--bundles", "nsis",
        "--features", "individual-edition",
        "--config", "src-tauri\tauri.windows.test.conf.json",
        "--no-sign"
    )
} finally {
    Pop-Location
}

$installer = Find-WindowsInstaller
$signature = Get-AuthenticodeSignature -LiteralPath $installer.FullName
if ($signature.Status -ne "NotSigned") {
    throw "Expected an unsigned installer, but Authenticode status is '$($signature.Status)': $($installer.FullName)"
}

$sha = Write-Sha256File -Artifact $installer

Write-Host ""
Write-Host "Canonical unsigned Windows artifact built locally" -ForegroundColor Green
Write-Host $installer.FullName
Write-Host $sha.Path
Write-Host "SHA256: $($sha.Hash)"
