#Requires -Version 7.2
<#
.SYNOPSIS
    Claudit front controller.

.DESCRIPTION
    Small operator entry point for the existing Claudit scripts. It keeps the
    powerful scripts intact and only routes subcommands plus pass-through args.
#>
[CmdletBinding()]
param(
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

function Invoke-ClauditScript {
    param(
        [Parameter(Mandatory)][string]$ScriptName,
        [string[]]$Arguments = @()
    )

    $scriptPath = Join-Path $root $ScriptName
    if (-not (Test-Path -LiteralPath $scriptPath)) {
        throw "Claudit script not found: $scriptPath"
    }

    $pwsh = (Get-Process -Id $PID).Path
    if ([string]::IsNullOrWhiteSpace($pwsh) -or -not (Test-Path -LiteralPath $pwsh)) {
        $pwsh = 'pwsh'
    }

    & $pwsh -NoProfile -ExecutionPolicy Bypass -File $scriptPath @Arguments
    exit $LASTEXITCODE
}

function Invoke-ClauditTestSuite {
    param([string[]]$Arguments = @())

    Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop
    if ($Arguments.Count -gt 0) {
        throw 'Claudit test does not forward arbitrary Pester arguments. Run Invoke-Pester directly for custom selection.'
    }
    $result = Invoke-Pester -Path (Join-Path $root 'tests') -Output Detailed -PassThru
    if ($result.FailedCount -gt 0) { exit 1 }
    exit 0
}

if (Test-CaHelpRequested -Help:$Help -RemainingArguments $RemainingArguments -InvocationLine $MyInvocation.Line) {
    Show-CaCommandHelp -Command $PSCommandPath
    exit 0
}

$tokens = @($RemainingArguments | Where-Object { $_ -ne '.' })
if ($tokens.Count -gt 0 -and [string]$tokens[0] -notmatch '^-') {
    $commandName = [string]$tokens[0]
    $cmd = $commandName.ToLowerInvariant()
    $passThrough = @($tokens | Select-Object -Skip 1)
}
else {
    $commandName = 'dashboard'
    $cmd = 'dashboard'
    $passThrough = @($tokens)
}

switch ($cmd) {
    { $_ -in @('dashboard', 'dash', 'cockpit', 'ui') } {
        Invoke-ClauditScript -ScriptName 'Start-ClauditDashboard.ps1' -Arguments $passThrough
    }
    { $_ -in @('wizard', 'guide', 'guided') } {
        Invoke-ClauditScript -ScriptName 'Start-ClauditWizard.ps1' -Arguments $passThrough
    }
    { $_ -in @('preflight', 'check') } {
        Invoke-ClauditScript -ScriptName 'Test-ClauditPreflight.ps1' -Arguments $passThrough
    }
    'doctor' {
        Invoke-ClauditScript -ScriptName 'Test-ClauditPreflight.ps1' -Arguments (@('-Service', 'All') + $passThrough)
    }
    'formal' {
        Invoke-ClauditScript -ScriptName 'Start-ClauditSafeAudit.ps1' -Arguments (@('-ControlLevel', 'Formal') + $passThrough)
    }
    'passive' {
        Invoke-ClauditScript -ScriptName 'Start-ClauditSafeAudit.ps1' -Arguments (@('-ControlLevel', 'Passive') + $passThrough)
    }
    'active' {
        Invoke-ClauditScript -ScriptName 'Start-ClauditSafeAudit.ps1' -Arguments (@('-ControlLevel', 'Active') + $passThrough)
    }
    { $_ -in @('safe', 'run', 'go') } {
        Invoke-ClauditScript -ScriptName 'Start-ClauditSafeAudit.ps1' -Arguments $passThrough
    }
    'm365' {
        Invoke-ClauditScript -ScriptName 'Start-ClauditSafeAudit.ps1' -Arguments (@('-Service', 'M365') + $passThrough)
    }
    'all' {
        Invoke-ClauditScript -ScriptName 'Start-ClauditSafeAudit.ps1' -Arguments (@('-Service', 'All') + $passThrough)
    }
    'domain' {
        Invoke-ClauditScript -ScriptName 'Start-ClauditSafeAudit.ps1' -Arguments (@('-Service', 'Domain') + $passThrough)
    }
    'vps' {
        Invoke-ClauditScript -ScriptName 'Start-ClauditSafeAudit.ps1' -Arguments (@('-Service', 'VPS') + $passThrough)
    }
    { $_ -in @('audit', 'live') } {
        Invoke-ClauditScript -ScriptName 'Invoke-ClauditAudit.ps1' -Arguments $passThrough
    }
    'install' {
        Invoke-ClauditScript -ScriptName 'Install-ClauditPrerequisites.ps1' -Arguments $passThrough
    }
    'reset' {
        Invoke-ClauditScript -ScriptName 'Reset-ClauditEnvironment.ps1' -Arguments $passThrough
    }
    'test' {
        Invoke-ClauditTestSuite -Arguments $passThrough
    }
    default {
        throw "Unknown Claudit command '$commandName'. Use: .\claudit.ps1 --help"
    }
}
