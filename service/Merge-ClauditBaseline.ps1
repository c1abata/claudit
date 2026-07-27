#Requires -Version 7.2
<#
.SYNOPSIS
    Merges a legacy Claudit baseline over the current packaged defaults.

.DESCRIPTION
    Upgrade helper used by install-ubuntu.sh. New default properties are added,
    while every operator-owned legacy value is retained. The destination is
    replaced atomically only after both inputs have been parsed successfully.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DefaultPath,
    [Parameter(Mandatory)][string]$LegacyPath,
    [Parameter(Mandatory)][string]$DestinationPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-ClauditJsonObject {
    param([Parameter(Mandatory)][string]$Path)

    try {
        $value = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Cannot read Claudit baseline '$Path': $($_.Exception.Message)"
    }
    if ($null -eq $value -or $value -isnot [pscustomobject]) {
        throw "Claudit baseline '$Path' must contain one JSON object."
    }
    return $value
}

function Merge-ClauditJsonObject {
    param(
        [Parameter(Mandatory)][pscustomobject]$Default,
        [Parameter(Mandatory)][pscustomobject]$Legacy
    )

    $merged = [ordered]@{}
    foreach ($property in $Default.PSObject.Properties) {
        $legacyProperty = $Legacy.PSObject.Properties[$property.Name]
        if ($null -eq $legacyProperty) {
            $merged[$property.Name] = $property.Value
            continue
        }

        if ($property.Value -is [pscustomobject] -and $legacyProperty.Value -is [pscustomobject]) {
            $merged[$property.Name] = Merge-ClauditJsonObject -Default $property.Value -Legacy $legacyProperty.Value
        }
        else {
            # Scalars and arrays are policy values: the operator's value wins.
            $merged[$property.Name] = $legacyProperty.Value
        }
    }

    # Retain extension fields used by private checks and future-compatible policy.
    foreach ($property in $Legacy.PSObject.Properties) {
        if (-not $merged.Contains($property.Name)) {
            $merged[$property.Name] = $property.Value
        }
    }
    return [pscustomobject]$merged
}

$defaults = Read-ClauditJsonObject -Path $DefaultPath
$legacy = Read-ClauditJsonObject -Path $LegacyPath
$merged = Merge-ClauditJsonObject -Default $defaults -Legacy $legacy

$destination = [System.IO.Path]::GetFullPath($DestinationPath)
$parent = Split-Path -Parent $destination
if ([string]::IsNullOrWhiteSpace($parent) -or -not (Test-Path -LiteralPath $parent -PathType Container)) {
    throw "Claudit baseline destination directory does not exist: $parent"
}

$temporary = Join-Path $parent ('.baseline-upgrade-' + [guid]::NewGuid().ToString('N') + '.tmp')
try {
    $json = $merged | ConvertTo-Json -Depth 32
    [System.IO.File]::WriteAllText($temporary, $json, [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::Move($temporary, $destination, $true)
}
finally {
    if (Test-Path -LiteralPath $temporary) {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}
