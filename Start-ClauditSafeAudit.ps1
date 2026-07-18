#Requires -Version 7.2
<#
.SYNOPSIS
    Guarded Claudit launcher.

.DESCRIPTION
    Runs offline preflight by default. A live tenant audit starts only when
    -ConfirmTenantConnection is supplied. No webhook notification is sent unless
    the caller explicitly passes -NotifyWebhook.
#>
[CmdletBinding()]
param(
    [string[]]$Service = @('Entra', 'Exchange', 'SharePoint', 'OneDrive'),

    [ValidateSet('Html', 'Json', 'Markdown', 'Csv', 'All')]
    [string]$Format = 'All',

    [string]$TenantName = 'Cloud tenant',
    [string]$BaselinePath,
    [string]$OutputDirectory,
    [ValidateSet('Formal', 'Passive', 'Active')]
    [string]$ControlLevel = 'Passive',
    [int[]]$VpsProbePort = @(),
    [ValidateRange(250, 10000)]
    [int]$ActiveTimeoutMs = 3000,
    [switch]$ConfirmActiveProbes,
    [ValidateSet('Global', 'USGov', 'USGovDOD', 'China')]
    [string]$Environment = 'Global',
    [ValidateSet('DeviceCode', 'Browser')]
    [string]$GraphAuthMode = 'DeviceCode',

    [string]$AzureSubscription,
    [string]$AzureTenant,

    [string]$AwsProfile,
    [string[]]$AwsRegion,

    [string]$GcpProject,
    [string]$GcpAccount,
    [string]$GcpOrganization,

    [string]$TailscaleTailnet,
    [string]$TailscaleApiTokenEnv = 'TAILSCALE_API_TOKEN',
    [ValidateSet('Auto', 'Basic', 'Bearer')]
    [string]$TailscaleAuthScheme = 'Auto',

    [string[]]$Domain,
    [string[]]$DomainSubdomain,

    [string]$VpsTarget,
    [string]$VpsSshUser,
    [int]$VpsSshPort = 22,
    [int[]]$VpsAllowedPublicPort,

    [switch]$ConfirmTenantConnection,
    [switch]$RunPester,

    [switch]$AppOnly,
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint,
    [string]$Organization,

    [string]$CompareWith,
    [string]$NotifyWebhook,
    [ValidateSet('Teams', 'Slack')]
    [string]$NotifyType = 'Teams',

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
$Service = Resolve-CaServices -Service $Service
if ($ControlLevel -eq 'Formal') {
    if ($Service -notcontains 'Domain') {
        throw 'Formal DNS evaluation requires -Service Domain and at least one authorized -Domain.'
    }
    $excludedFormalServices = @($Service | Where-Object { $_ -ne 'Domain' })
    if ($excludedFormalServices.Count -gt 0) {
        Write-Warning "Formal level evaluates Domain only; excluded services: $($excludedFormalServices -join ', ')."
    }
    $Service = @('Domain')
}
if ($ControlLevel -eq 'Active' -and -not $ConfirmActiveProbes) {
    throw 'Active control level requires -ConfirmActiveProbes. Only explicitly authorized Domain and VPS targets are probed.'
}

function Add-ProcessArgument {
    param(
        [Parameter(Mandatory)][System.Collections.Generic.List[string]]$Arguments,
        [Parameter(Mandatory)][string]$Name,
        $Value
    )

    if ($null -eq $Value) { return }
    if ($Value -is [switch]) {
        if ($Value.IsPresent) { $Arguments.Add("-$Name") }
        return
    }
    if ($Value -is [bool]) {
        if ($Value) { $Arguments.Add("-$Name") }
        return
    }
    if ($Value -is [array]) {
        $items = @($Value | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) })
        if ($items.Count -eq 0) { return }
        $Arguments.Add("-$Name")
        $Arguments.Add(($items | ForEach-Object { [string]$_ }) -join ',')
        return
    }
    if ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value)) { return }

    $Arguments.Add("-$Name")
    $Arguments.Add([string]$Value)
}

function Invoke-IsolatedAuditProcess {
    param([Parameter(Mandatory)][hashtable]$Arguments)

    $oldNotifyWebhook = $env:CLAUDIT_NOTIFY_WEBHOOK
    $setNotifyWebhook = $false
    $childArguments = $Arguments.Clone()
    if ($childArguments.ContainsKey('NotifyWebhook') -and -not [string]::IsNullOrWhiteSpace([string]$childArguments['NotifyWebhook'])) {
        $env:CLAUDIT_NOTIFY_WEBHOOK = [string]$childArguments['NotifyWebhook']
        $childArguments.Remove('NotifyWebhook')
        $setNotifyWebhook = $true
    }

    $pwsh = (Get-Process -Id $PID).Path
    if ([string]::IsNullOrWhiteSpace($pwsh) -or -not (Test-Path -LiteralPath $pwsh)) {
        $pwsh = 'pwsh'
    }

    $argList = [System.Collections.Generic.List[string]]::new()
    $argList.Add('-NoProfile')
    $argList.Add('-ExecutionPolicy')
    $argList.Add('Bypass')
    $argList.Add('-File')
    $argList.Add((Join-Path $root 'Invoke-ClauditAudit.ps1'))

    foreach ($name in @(
        'Service', 'Format', 'TenantName', 'OutputDirectory', 'Environment',
        'GraphAuthMode', 'BaselinePath', 'ControlLevel', 'ActiveTimeoutMs',
        'VpsProbePort', 'CompareWith', 'NotifyWebhook',
        'NotifyType', 'AzureSubscription', 'AzureTenant', 'AwsProfile',
        'AwsRegion', 'GcpProject', 'GcpAccount', 'GcpOrganization',
        'TailscaleTailnet', 'TailscaleApiTokenEnv', 'TailscaleAuthScheme',
        'Domain', 'DomainSubdomain', 'VpsTarget', 'VpsSshUser', 'VpsSshPort',
        'VpsAllowedPublicPort',
        'TenantId', 'ClientId', 'CertificateThumbprint', 'Organization'
    )) {
        if ($childArguments.ContainsKey($name)) {
            Add-ProcessArgument -Arguments $argList -Name $name -Value $childArguments[$name]
        }
    }
    foreach ($name in @('RunPester', 'AppOnly', 'ConfirmActiveProbes')) {
        if ($childArguments.ContainsKey($name)) {
            Add-ProcessArgument -Arguments $argList -Name $name -Value ([bool]$childArguments[$name])
        }
    }

    Write-Host 'Starting isolated audit process (pwsh -NoProfile)...' -ForegroundColor Cyan
    try {
        & $pwsh @argList
        return $LASTEXITCODE
    }
    finally {
        if ($setNotifyWebhook) {
            if ($null -eq $oldNotifyWebhook) {
                Remove-Item Env:\CLAUDIT_NOTIFY_WEBHOOK -ErrorAction SilentlyContinue
            }
            else {
                $env:CLAUDIT_NOTIFY_WEBHOOK = $oldNotifyWebhook
            }
        }
    }
}

if (-not $OutputDirectory) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $OutputDirectory = Join-Path $root "reports\safe-$stamp"
}

if ($AppOnly) {
    foreach ($name in @('TenantId', 'ClientId', 'CertificateThumbprint')) {
        $value = Get-Variable -Name $name -ValueOnly
        if ([string]::IsNullOrWhiteSpace($value)) {
            throw "-AppOnly requires -$name."
        }
    }
    if (($Service -contains 'Exchange') -and [string]::IsNullOrWhiteSpace($Organization)) {
        throw '-AppOnly Exchange audits require -Organization (for example contoso.onmicrosoft.com).'
    }
}

$preflightArgs = @{
    Service         = $Service
    OutputDirectory = $OutputDirectory
}
if ($BaselinePath) { $preflightArgs['BaselinePath'] = $BaselinePath }
if ($RunPester) { $preflightArgs['RequirePester'] = $true }
if ($AppOnly) { $preflightArgs['AuthMode'] = 'AppOnly' }
if ($GraphAuthMode) { $preflightArgs['GraphAuthMode'] = $GraphAuthMode }
if ($AzureSubscription) { $preflightArgs['AzureSubscription'] = $AzureSubscription }
if ($AzureTenant) { $preflightArgs['AzureTenant'] = $AzureTenant }
if ($AwsProfile) { $preflightArgs['AwsProfile'] = $AwsProfile }
if ($AwsRegion) { $preflightArgs['AwsRegion'] = $AwsRegion }
if ($GcpProject) { $preflightArgs['GcpProject'] = $GcpProject }
if ($GcpAccount) { $preflightArgs['GcpAccount'] = $GcpAccount }
if ($GcpOrganization) { $preflightArgs['GcpOrganization'] = $GcpOrganization }
if ($TailscaleTailnet) { $preflightArgs['TailscaleTailnet'] = $TailscaleTailnet }
if ($TailscaleApiTokenEnv) { $preflightArgs['TailscaleApiTokenEnv'] = $TailscaleApiTokenEnv }
if ($TailscaleAuthScheme) { $preflightArgs['TailscaleAuthScheme'] = $TailscaleAuthScheme }
if ($Domain) { $preflightArgs['Domain'] = $Domain }
if ($DomainSubdomain) { $preflightArgs['DomainSubdomain'] = $DomainSubdomain }
if ($VpsTarget) { $preflightArgs['VpsTarget'] = $VpsTarget }
if ($VpsSshUser) { $preflightArgs['VpsSshUser'] = $VpsSshUser }
if ($VpsSshPort -ne 22) { $preflightArgs['VpsSshPort'] = $VpsSshPort }
if ($VpsAllowedPublicPort) { $preflightArgs['VpsAllowedPublicPort'] = $VpsAllowedPublicPort }
if ($TenantId) { $preflightArgs['TenantId'] = $TenantId }
if ($ClientId) { $preflightArgs['ClientId'] = $ClientId }
if ($CertificateThumbprint) { $preflightArgs['CertificateThumbprint'] = $CertificateThumbprint }
if ($Organization) { $preflightArgs['Organization'] = $Organization }

Write-Host 'Claudit safe launcher: offline preflight...' -ForegroundColor Cyan
& (Join-Path $root 'Test-ClauditPreflight.ps1') @preflightArgs
if ($LASTEXITCODE -ne 0) {
    throw "Preflight failed. Fix local prerequisites before connecting to a tenant."
}

if (-not $ConfirmTenantConnection -and $ControlLevel -ne 'Formal') {
    Write-Host ''
    Write-Host 'Preflight passed. Live tenant audit was not started.' -ForegroundColor Yellow
    Write-Host 'Rerun with -ConfirmTenantConnection to connect read-only and generate reports.' -ForegroundColor Yellow
    exit 0
}

$auditArgs = @{
    Service         = $Service
    Format          = $Format
    TenantName      = $TenantName
    OutputDirectory = $OutputDirectory
    Environment     = $Environment
    ControlLevel    = $ControlLevel
    ActiveTimeoutMs = $ActiveTimeoutMs
}
if ($VpsProbePort) { $auditArgs['VpsProbePort'] = $VpsProbePort }
if ($ConfirmActiveProbes) { $auditArgs['ConfirmActiveProbes'] = $true }
if ($BaselinePath) { $auditArgs['BaselinePath'] = $BaselinePath }
if ($RunPester) { $auditArgs['RunPester'] = $true }
if ($GraphAuthMode) { $auditArgs['GraphAuthMode'] = $GraphAuthMode }
if ($AzureSubscription) { $auditArgs['AzureSubscription'] = $AzureSubscription }
if ($AzureTenant) { $auditArgs['AzureTenant'] = $AzureTenant }
if ($AwsProfile) { $auditArgs['AwsProfile'] = $AwsProfile }
if ($AwsRegion) { $auditArgs['AwsRegion'] = $AwsRegion }
if ($GcpProject) { $auditArgs['GcpProject'] = $GcpProject }
if ($GcpAccount) { $auditArgs['GcpAccount'] = $GcpAccount }
if ($GcpOrganization) { $auditArgs['GcpOrganization'] = $GcpOrganization }
if ($TailscaleTailnet) { $auditArgs['TailscaleTailnet'] = $TailscaleTailnet }
if ($TailscaleApiTokenEnv) { $auditArgs['TailscaleApiTokenEnv'] = $TailscaleApiTokenEnv }
if ($TailscaleAuthScheme) { $auditArgs['TailscaleAuthScheme'] = $TailscaleAuthScheme }
if ($Domain) { $auditArgs['Domain'] = $Domain }
if ($DomainSubdomain) { $auditArgs['DomainSubdomain'] = $DomainSubdomain }
if ($VpsTarget) { $auditArgs['VpsTarget'] = $VpsTarget }
if ($VpsSshUser) { $auditArgs['VpsSshUser'] = $VpsSshUser }
if ($VpsSshPort -ne 22) { $auditArgs['VpsSshPort'] = $VpsSshPort }
if ($VpsAllowedPublicPort) { $auditArgs['VpsAllowedPublicPort'] = $VpsAllowedPublicPort }
if ($CompareWith) { $auditArgs['CompareWith'] = $CompareWith }
if ($NotifyWebhook) {
    $auditArgs['NotifyWebhook'] = $NotifyWebhook
    $auditArgs['NotifyType'] = $NotifyType
}
if ($AppOnly) {
    $auditArgs['AppOnly'] = $true
    $auditArgs['TenantId'] = $TenantId
    $auditArgs['ClientId'] = $ClientId
    $auditArgs['CertificateThumbprint'] = $CertificateThumbprint
    if ($Organization) { $auditArgs['Organization'] = $Organization }
}

Write-Host ''
$auditLabel = if ($ControlLevel -eq 'Formal') { 'Starting formal DNS audit (resolver traffic only)...' } else { 'Starting live read-only tenant audit...' }
Write-Host $auditLabel -ForegroundColor Cyan
$auditExit = Invoke-IsolatedAuditProcess -Arguments $auditArgs
exit $auditExit
