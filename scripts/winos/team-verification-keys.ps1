<#
.SYNOPSIS
  Reads the published Team verification public keys that desktop and CLI
  builds embed through HYBRIDCIPHER_ENTITLEMENT_PUBLIC_KEYS.

.USAGE
  . .\scripts\winos\team-verification-keys.ps1
  Get-PublishedTeamVerificationKeys -Repo (Get-Location).Path
      Returns the comma-joined kid:base64url list from
      apps\desktop\team-verification-keys.txt, or an empty string when the
      file is missing. Blank lines and lines starting with # are ignored.
#>

function Get-PublishedTeamVerificationKeys {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Repo
    )

    $path = Join-Path $Repo "apps\desktop\team-verification-keys.txt"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return ""
    }

    $entries = @(foreach ($line in Get-Content -LiteralPath $path) {
        $value = $line -replace '\s', ''
        if ($value -and -not $value.StartsWith('#')) {
            $value
        }
    })
    return ($entries -join ',')
}
