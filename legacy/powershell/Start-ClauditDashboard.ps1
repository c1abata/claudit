#Requires -Version 7.2
<#
.SYNOPSIS
    Local Claudit web cockpit.

.DESCRIPTION
    Starts a loopback-only dashboard for running preflight/live read-only audits,
    following operation logs and opening generated report files. No Node.js,
    browser framework or permanent service is required.
#>
[CmdletBinding()]
param(
    [string]$BindAddress = '127.0.0.1',
    [int]$Port = 8765,
    [int]$PortFallbackCount = 20,
    [string]$ReportRoot,
    [string]$OperationRoot,
    [ValidateRange(1, 10000)][int]$RetentionCount = 100,
    [string]$StatePath,

    [Alias('h', '?')]
    [switch]$Help,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArguments
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
$moduleManifest = Join-Path $root 'Claudit.psd1'
Import-Module $moduleManifest -Force -ErrorAction Stop
if (Test-CaHelpRequested -Help:$Help -RemainingArguments $RemainingArguments -InvocationLine $MyInvocation.Line) {
    Show-CaCommandHelp -Command $PSCommandPath
    exit 0
}
Assert-CaNoRemainingArgument -RemainingArguments $RemainingArguments

$args = @{
    BindAddress       = $BindAddress
    Port              = $Port
    PortFallbackCount = $PortFallbackCount
    RetentionCount    = $RetentionCount
}
if (-not [string]::IsNullOrWhiteSpace($ReportRoot)) { $args['ReportRoot'] = $ReportRoot }
if (-not [string]::IsNullOrWhiteSpace($OperationRoot)) { $args['OperationRoot'] = $OperationRoot }
if (-not [string]::IsNullOrWhiteSpace($StatePath)) { $args['StatePath'] = $StatePath }

Start-CaDashboard @args
