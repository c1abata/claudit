#Requires -Version 7.2
<#
.SYNOPSIS
    Long-running Claudit orchestrator for systemd.

.DESCRIPTION
    Loads a small JSON configuration, prepares persistent storage and starts
    the loopback-only dashboard. Secrets remain outside this file and may be
    supplied through the systemd EnvironmentFile or provider CLI stores.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = '/etc/claudit/service.json',
    [switch]$ValidateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ServiceConfigValue {
    param(
        [Parameter(Mandatory)][object]$Config,
        [Parameter(Mandatory)][string]$Name,
        $Default
    )
    $property = $Config.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return $Default }
    return $property.Value
}

if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "Claudit service configuration not found: $ConfigPath"
}

try {
    $config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
}
catch {
    throw "Invalid Claudit service JSON '$ConfigPath': $($_.Exception.Message)"
}

$allowedProperties = @('BindAddress', 'Port', 'PortFallbackCount', 'DataRoot', 'RetentionCount')
$unknown = @($config.PSObject.Properties.Name | Where-Object { $_ -notin $allowedProperties })
if ($unknown.Count -gt 0) { throw "Unknown Claudit service setting(s): $($unknown -join ', ')." }

$bindAddress = [string](Get-ServiceConfigValue -Config $config -Name BindAddress -Default '127.0.0.1')
$port = [int](Get-ServiceConfigValue -Config $config -Name Port -Default 8765)
$portFallbackCount = [int](Get-ServiceConfigValue -Config $config -Name PortFallbackCount -Default 0)
$dataRoot = [string](Get-ServiceConfigValue -Config $config -Name DataRoot -Default '/var/lib/claudit')
$retentionCount = [int](Get-ServiceConfigValue -Config $config -Name RetentionCount -Default 100)

$address = $null
if (-not [System.Net.IPAddress]::TryParse($bindAddress, [ref]$address) -or -not [System.Net.IPAddress]::IsLoopback($address)) {
    throw 'BindAddress must be an explicit loopback IP address such as 127.0.0.1 or ::1.'
}
if ($port -lt 1 -or $port -gt 65535) { throw 'Port must be between 1 and 65535.' }
if ($portFallbackCount -lt 0 -or $portFallbackCount -gt 100 -or ($port + $portFallbackCount) -gt 65535) {
    throw 'PortFallbackCount must be between 0 and 100 and remain inside the TCP port range.'
}
if ($retentionCount -lt 1 -or $retentionCount -gt 10000) { throw 'RetentionCount must be between 1 and 10000.' }
if (-not [System.IO.Path]::IsPathRooted($dataRoot)) { throw 'DataRoot must be an absolute path.' }

$serviceRoot = Split-Path -Parent $PSScriptRoot
$moduleManifest = Join-Path $serviceRoot 'Claudit.psd1'
if (-not (Test-Path -LiteralPath $moduleManifest -PathType Leaf)) { throw "Claudit module not found: $moduleManifest" }

$reportRoot = Join-Path $dataRoot 'reports'
$operationRoot = Join-Path $reportRoot 'dashboard'
$statePath = Join-Path $dataRoot 'dashboard-state.json'
foreach ($path in @($dataRoot, $reportRoot, $operationRoot)) {
    if (-not (Test-Path -LiteralPath $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
}

Import-Module $moduleManifest -Force -ErrorAction Stop
if ($ValidateOnly) {
    Write-Host "Claudit service configuration valid: data=$dataRoot retention=$retentionCount bind=$bindAddress`:$port"
    exit 0
}
Write-Host "Claudit service: data=$dataRoot retention=$retentionCount bind=$bindAddress`:$port"
Start-CaDashboard -BindAddress $bindAddress -Port $port -PortFallbackCount $portFallbackCount `
    -ReportRoot $reportRoot -OperationRoot $operationRoot -RetentionCount $retentionCount -StatePath $statePath
