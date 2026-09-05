[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BaselinePath,
    [string]$Organization,
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$legacy = Join-Path $root 'legacy/powershell/Claudit.psd1'

function Convert-ExchangeFinding {
    param([Parameter(Mandatory)]$Finding)
    $status = switch ([string]$Finding.Status) {
        'Pass' { 'pass' }; 'Fail' { 'fail' }; 'Warning' { 'warning' }; 'Info' { 'info' }; default { 'unknown' }
    }
    [ordered]@{
        id = [string]$Finding.CheckId
        status = $status
        severity = ([string]$Finding.Severity).ToLowerInvariant()
        title = [string]$Finding.Title
        detail = [string]$Finding.Detail
    } | ConvertTo-Json -Compress -Depth 4
}

Import-Module -LiteralPath $legacy -Force -ErrorAction Stop
Get-CaBaseline -Path $BaselinePath -Force | Out-Null
try {
    $appOnly = $TenantId -and $ClientId -and $CertificateThumbprint -and $Organization
    if ($appOnly) {
        Connect-Claudit -SkipGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -Organization $Organization | Out-Null
    } else {
        Connect-Claudit -SkipGraph | Out-Null
    }
    Get-CaExchangeFindings | ForEach-Object { Convert-ExchangeFinding $_ }
}
finally {
    Disconnect-Claudit
}
