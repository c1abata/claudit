#Requires -Version 7.2
<#
.SYNOPSIS
    Clears Claudit-related process environment variables.

.DESCRIPTION
    Safe local helper. By default it clears only CLAUDIT_FINDINGS, which is used
    by Pester offline replay. Use -ClearProxy to also clear process-level proxy
    variables for the current PowerShell session.
#>
[CmdletBinding()]
param(
    [switch]$ClearProxy,

    [Alias('h', '?')]
    [switch]$Help,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArguments
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$moduleManifest = Join-Path $PSScriptRoot 'Claudit.psd1'
Import-Module $moduleManifest -Force -ErrorAction Stop
if (Test-CaHelpRequested -Help:$Help -RemainingArguments $RemainingArguments -InvocationLine $MyInvocation.Line) {
    Show-CaCommandHelp -Command $PSCommandPath
    exit 0
}
Assert-CaNoRemainingArgument -RemainingArguments $RemainingArguments

$names = [System.Collections.Generic.List[string]]::new()
foreach ($name in @('CLAUDIT_FINDINGS', 'CLAUDIT_NOTIFY_WEBHOOK')) {
    $names.Add($name)
}
if ($ClearProxy) {
    foreach ($name in @('HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY')) {
        $names.Add($name)
    }
}

foreach ($name in $names) {
    Remove-Item -LiteralPath "Env:\$name" -ErrorAction SilentlyContinue
    Write-Host "Cleared process environment variable: $name" -ForegroundColor Green
}
