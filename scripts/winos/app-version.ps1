# The Windows app version is independent of Cargo package and MSIX revision metadata.
function Get-WindowsAppVersion {
    param([string]$ConfigPath = (Join-Path $PSScriptRoot "..\..\apps\desktop\src-tauri\tauri.windows.conf.json"))

    try {
        $Config = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $VersionProperty = $Config.PSObject.Properties['version']
        if ($null -eq $VersionProperty -or $VersionProperty.Value -isnot [string]) {
            throw "version must be a string"
        }
        $Version = $VersionProperty.Value
        if ($Version -cnotmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\z') {
            throw "version must be numeric major.minor.patch"
        }
        $Parts = $Version.Split('.')
        if ([decimal]$Parts[0] -gt 255 -or [decimal]$Parts[1] -gt 255 -or [decimal]$Parts[2] -gt 65535) {
            throw "version exceeds Windows MSI/MSIX limits"
        }
        foreach ($Name in @("tauri.windows.release.conf.json", "tauri.windows.test.conf.json")) {
            $OverlayPath = Join-Path (Split-Path -Parent $ConfigPath) $Name
            if (Test-Path -LiteralPath $OverlayPath -PathType Leaf) {
                $Overlay = Get-Content -LiteralPath $OverlayPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                $OverlayVersion = $Overlay.PSObject.Properties['version']
                if ($null -ne $OverlayVersion -and $OverlayVersion.Value -cne $Version) {
                    throw "Conflicting app version in $OverlayPath; edit only tauri.windows.conf.json"
                }
            }
        }
        return $Version
    } catch {
        throw "Invalid Windows app version in '$ConfigPath': $($_.Exception.Message)"
    }
}
