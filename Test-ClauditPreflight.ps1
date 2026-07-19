#Requires -Version 7.2
<#
.SYNOPSIS
    Offline safety preflight for Claudit.

.DESCRIPTION
    Validates local runtime, baseline, module import, report write path and
    optional dependency presence. It does not connect to Microsoft Graph,
    Exchange Online, DNS-over-HTTPS or notification webhooks.
#>
[CmdletBinding()]
param(
    [string[]]$Service = @('Entra', 'Exchange', 'SharePoint', 'OneDrive'),

    [string]$BaselinePath,
    [string]$OutputDirectory,
    [string]$JsonOutputPath,
    [ValidateSet('Interactive', 'AppOnly')]
    [string]$AuthMode = 'Interactive',
    [ValidateSet('DeviceCode', 'Browser')]
    [string]$GraphAuthMode = 'DeviceCode',

    [string]$AwsProfile,
    [string[]]$AwsRegion,

    [string]$AzureSubscription,
    [string]$AzureTenant,

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

    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint,
    [string]$Organization,

    [switch]$RequirePester,

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
$result = [ordered]@{
    SchemaVersion = '1.0'
    ReportType    = 'ClauditPreflight'
    Status        = 'Pass'
    Outcome       = 'Ready'
    Ready         = $true
    Root          = $root
    PowerShell    = $PSVersionTable.PSVersion.ToString()
    Services      = $Service
    AuthPlan      = @()
    Checks        = [System.Collections.Generic.List[object]]::new()
    Warnings      = [System.Collections.Generic.List[string]]::new()
    Errors        = [System.Collections.Generic.List[string]]::new()
    BlockingErrors = [System.Collections.Generic.List[object]]::new()
    Summary       = $null
    Environment   = [ordered]@{}
}

function Add-PreflightCheck {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Pass', 'Warning', 'Fail')][string]$Status,
        [string]$Detail = '',
        [ValidateSet('Runtime', 'Configuration', 'Dependency', 'Authentication', 'Scope', 'Output', 'Advisory', 'Internal')]
        [string]$Category = 'Runtime',
        [string]$Recommendation = ''
    )
    if ([string]::IsNullOrWhiteSpace($Recommendation) -and $Status -eq 'Fail') {
        $Recommendation = 'Correct this prerequisite and rerun preflight before starting the audit.'
    }
    $check = [pscustomobject]@{
        Name = $Name
        Status = $Status
        Category = if ($Status -eq 'Warning' -and $Category -eq 'Runtime') { 'Advisory' } else { $Category }
        BlocksExecution = ($Status -eq 'Fail')
        Detail = $Detail
        Recommendation = $Recommendation
        DiagnosticId = if ($Status -eq 'Fail') { 'CA-PRE-' + [guid]::NewGuid().ToString('N').Substring(0, 8) } else { '' }
    }
    $result.Checks.Add($check)
    if ($Status -eq 'Warning') { $result.Warnings.Add("${Name}: $Detail") }
    if ($Status -eq 'Fail') {
        $result.Errors.Add("${Name}: $Detail")
        $result.BlockingErrors.Add($check)
        $result.Status = 'Fail'
    }
}

function Test-ModuleAvailable {
    param([Parameter(Mandatory)][string]$Name)
    $mod = Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending | Select-Object -First 1
    if ($mod) {
        Add-PreflightCheck -Name "Module $Name" -Status Pass -Detail "Version $($mod.Version)"
    }
    else {
        Add-PreflightCheck -Name "Module $Name" -Status Fail -Detail "Missing. Install-Module $Name -Scope CurrentUser"
    }
}

function Test-CliAvailable {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$InstallHint
    )
    $cmd = Get-Command -Name $Name -ErrorAction SilentlyContinue
    if ($cmd) {
        Add-PreflightCheck -Name "CLI $Name" -Status Pass -Detail $cmd.Source
    }
    else {
        Add-PreflightCheck -Name "CLI $Name" -Status Fail -Detail $InstallHint
    }
}

function Add-EnvCheck {
    param([Parameter(Mandatory)][string]$Name)
    $value = [Environment]::GetEnvironmentVariable($Name, 'Process')
    if ($null -eq $value) {
        $result.Environment[$Name] = [pscustomobject]@{ IsSet = $false }
    }
    else {
        $result.Environment[$Name] = [pscustomobject]@{ IsSet = $true }
    }
    if ([string]::IsNullOrWhiteSpace($value)) {
        Add-PreflightCheck -Name "Env $Name" -Status Pass -Detail 'Not set in current process.'
        return
    }
    if ($Name -eq 'CLAUDIT_FINDINGS') {
        if (Test-Path -LiteralPath $value) {
            Add-PreflightCheck -Name "Env $Name" -Status Warning -Detail "Set to existing file: $value. Live runs restore it after Pester."
        }
        else {
            Add-PreflightCheck -Name "Env $Name" -Status Warning -Detail "Set but file does not exist: $value. Clear it before offline Pester replay."
        }
        return
    }
    Add-PreflightCheck -Name "Env $Name" -Status Warning -Detail 'Set in current process; verify it is intentional.'
}

function Add-IdentityAssemblyCheck {
    $assemblies = @([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {
        $_.GetName().Name -in @(
            'Microsoft.Identity.Client',
            'Microsoft.IdentityModel.Abstractions',
            'Azure.Identity'
        )
    })
    if ($assemblies.Count -eq 0) {
        Add-PreflightCheck -Name 'Graph identity assemblies' -Status Pass -Detail 'No MSAL/Azure Identity assemblies preloaded in this process.'
        return
    }

    $details = @($assemblies | ForEach-Object {
        "$($_.GetName().Name) $($_.GetName().Version) [$($_.Location)]"
    })
    Add-PreflightCheck -Name 'Graph identity assemblies' -Status Warning -Detail "Already loaded in current process: $($details -join '; '). Safe launcher isolates live audit in pwsh -NoProfile."
}

function Get-ExistingAncestorPath {
    param([Parameter(Mandatory)][string]$Path)
    $candidate = $Path
    while ($candidate) {
        if (Test-Path -LiteralPath $candidate) { return (Resolve-Path -LiteralPath $candidate).Path }
        $next = Split-Path -Parent $candidate
        if ($next -eq $candidate) { break }
        $candidate = $next
    }
    return $null
}

function Test-ReportOutputWritable {
    param([Parameter(Mandatory)][string]$Path)

    try {
        if (Test-Path -LiteralPath $Path) {
            $item = Get-Item -LiteralPath $Path -ErrorAction Stop
            if (-not $item.PSIsContainer) {
                throw "Path exists but is not a directory: $Path"
            }
        }
        else {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }
        $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
        $probe = Join-Path $resolved ('.claudit-write-test-' + [guid]::NewGuid().ToString('N') + '.tmp')
        'claudit preflight write probe' | Set-Content -LiteralPath $probe -Encoding UTF8 -ErrorAction Stop
        Remove-Item -LiteralPath $probe -Force -ErrorAction Stop
        return $resolved
    }
    catch {
        throw "Cannot write report output under '$Path': $($_.Exception.Message)"
    }
}

try {
    if ($PSVersionTable.PSVersion -lt [version]'7.2') {
        Add-PreflightCheck -Name 'PowerShell version' -Status Fail -Detail 'PowerShell 7.2+ is required.'
    }
    else {
        Add-PreflightCheck -Name 'PowerShell version' -Status Pass -Detail $PSVersionTable.PSVersion.ToString()
    }

    if (Test-Path -LiteralPath $moduleManifest) {
        Import-Module $moduleManifest -Force -ErrorAction Stop
        $Service = Resolve-CaServices -Service $Service
        $result.Services = $Service
        Set-CaProviderOption -Provider Azure -Options @{ Subscription = $AzureSubscription; Tenant = $AzureTenant }
        Set-CaProviderOption -Provider AWS -Options @{ Profile = $AwsProfile; Regions = @($AwsRegion) }
        Set-CaProviderOption -Provider GCP -Options @{ Project = $GcpProject; Account = $GcpAccount; Organization = $GcpOrganization }
        Set-CaProviderOption -Provider Tailscale -Options @{ Tailnet = $TailscaleTailnet; ApiTokenEnv = $TailscaleApiTokenEnv; AuthScheme = $TailscaleAuthScheme }
        Set-CaProviderOption -Provider Domain -Options @{ Domains = @($Domain); Subdomains = @($DomainSubdomain) }
        Set-CaProviderOption -Provider VPS -Options @{ Target = $VpsTarget; SshUser = $VpsSshUser; SshPort = $VpsSshPort; AllowedPublicPorts = @($VpsAllowedPublicPort) }
        $result.AuthPlan = @(Get-CaAuthPlan -Service $Service -AuthMode $AuthMode -GraphAuthMode $GraphAuthMode)
        Add-PreflightCheck -Name 'Claudit module import' -Status Pass -Detail $moduleManifest
    }
    else {
        Add-PreflightCheck -Name 'Claudit module manifest' -Status Fail -Detail "Not found: $moduleManifest"
    }

    if ($BaselinePath) {
        Get-CaBaseline -Path $BaselinePath -Force | Out-Null
        Add-PreflightCheck -Name 'Baseline JSON' -Status Pass -Detail (Resolve-Path -LiteralPath $BaselinePath).Path
    }
    else {
        Get-CaBaseline -Force | Out-Null
        Add-PreflightCheck -Name 'Baseline JSON' -Status Pass -Detail (Join-Path $root 'config\baseline.json')
    }

    if (-not $OutputDirectory) { $OutputDirectory = Join-Path $root 'reports' }
    $anchor = Get-ExistingAncestorPath -Path $OutputDirectory
    if (-not $anchor) {
        Add-PreflightCheck -Name 'Report output path' -Status Fail -Detail "No existing ancestor for: $OutputDirectory"
    }
    else {
        try {
            $writablePath = Test-ReportOutputWritable -Path $OutputDirectory
            Add-PreflightCheck -Name 'Report output path' -Status Pass -Detail "Writable: $writablePath"
        }
        catch {
            Add-PreflightCheck -Name 'Report output path' -Status Fail -Detail $_.Exception.Message
        }
    }

    foreach ($envName in @(
        'CLAUDIT_FINDINGS',
        'CLAUDIT_NOTIFY_WEBHOOK',
        'TAILSCALE_TAILNET',
        'HTTPS_PROXY',
        'HTTP_PROXY',
        'NO_PROXY',
        'POWERSHELL_TELEMETRY_OPTOUT'
    )) { Add-EnvCheck -Name $envName }

    if ($Service | Where-Object { $_ -in @('Entra', 'SharePoint', 'OneDrive') }) {
        Test-ModuleAvailable -Name 'Microsoft.Graph.Authentication'
        if ($AuthMode -eq 'AppOnly') {
            Add-PreflightCheck -Name 'Microsoft 365 auth mode' -Status Pass -Detail 'App-only certificate'
        }
        else {
            Add-PreflightCheck -Name 'Graph delegated auth mode' -Status Pass -Detail $GraphAuthMode
        }
        Add-IdentityAssemblyCheck
    }
    if (($Service | Where-Object { $_ -in @('Entra', 'Exchange', 'SharePoint', 'OneDrive') }) -and $AuthMode -eq 'AppOnly') {
        foreach ($name in @('TenantId', 'ClientId', 'CertificateThumbprint')) {
            $value = Get-Variable -Name $name -ValueOnly
            if ([string]::IsNullOrWhiteSpace($value)) {
                Add-PreflightCheck -Name "App-only $name" -Status Fail -Detail "Missing -$name for Microsoft 365 app-only authentication."
            }
            else {
                Add-PreflightCheck -Name "App-only $name" -Status Pass -Detail 'Provided.'
            }
        }
        if (($Service -contains 'Exchange') -and [string]::IsNullOrWhiteSpace($Organization)) {
            Add-PreflightCheck -Name 'App-only Exchange organization' -Status Fail -Detail 'Missing -Organization for Exchange app-only authentication.'
        }
        elseif ($Service -contains 'Exchange') {
            Add-PreflightCheck -Name 'App-only Exchange organization' -Status Pass -Detail $Organization
        }
    }
    if ($Service -contains 'Entra') {
        foreach ($name in @(
            'Microsoft.Graph.Identity.DirectoryManagement',
            'Microsoft.Graph.Identity.SignIns',
            'Microsoft.Graph.Applications',
            'Microsoft.Graph.Users'
        )) { Test-ModuleAvailable -Name $name }
    }
    if ($Service | Where-Object { $_ -in @('SharePoint', 'OneDrive') }) {
        Add-PreflightCheck -Name 'SharePoint Graph cmdlet module' -Status Warning -Detail 'Verify Get-MgAdminSharePointSetting is available after Microsoft Graph module install.'
    }
    if ($Service -contains 'Exchange') {
        Test-ModuleAvailable -Name 'ExchangeOnlineManagement'
        Add-PreflightCheck -Name 'Exchange DNS checks' -Status Warning -Detail 'SPF/DMARC checks use DNS-over-HTTPS, with Resolve-DnsName fallback.'
    }
    if ($Service -contains 'AWS') {
        Test-CliAvailable -Name 'aws' -InstallHint 'Missing. Install AWS CLI v2 and configure a read-only profile.'
        if ($AwsProfile) { Add-PreflightCheck -Name 'AWS profile selector' -Status Pass -Detail $AwsProfile }
        if ($AwsRegion) {
            Add-PreflightCheck -Name 'AWS audit regions' -Status Pass -Detail ($AwsRegion -join ', ')
        }
        else {
            Add-PreflightCheck -Name 'AWS audit regions' -Status Warning -Detail 'No -AwsRegion supplied; baseline AWS.Regions will be used.'
        }
        Add-PreflightCheck -Name 'AWS live API probe' -Status Warning -Detail 'Credentials and IAM permissions are validated during the read-only audit, not offline preflight.'
    }
    if ($Service -contains 'Azure') {
        Test-CliAvailable -Name 'az' -InstallHint 'Missing. Install Azure CLI and authenticate with az login.'
        if ($AzureSubscription) { Add-PreflightCheck -Name 'Azure subscription selector' -Status Pass -Detail $AzureSubscription }
        if ($AzureTenant) { Add-PreflightCheck -Name 'Azure tenant selector' -Status Pass -Detail $AzureTenant }
        Add-PreflightCheck -Name 'Azure live API probe' -Status Warning -Detail 'az login, subscription scope and directory/RBAC read permissions are validated during the read-only audit.'
    }
    if ($Service -contains 'GCP') {
        Test-CliAvailable -Name 'gcloud' -InstallHint 'Missing. Install Google Cloud SDK and authenticate with gcloud.'
        if ($GcpProject) {
            Add-PreflightCheck -Name 'GCP project selector' -Status Pass -Detail $GcpProject
        }
        elseif ($env:GOOGLE_CLOUD_PROJECT) {
            Add-PreflightCheck -Name 'GCP project selector' -Status Pass -Detail "GOOGLE_CLOUD_PROJECT=$env:GOOGLE_CLOUD_PROJECT"
        }
        else {
            Add-PreflightCheck -Name 'GCP project selector' -Status Warning -Detail 'No -GcpProject supplied; live audit will use gcloud config project.'
        }
        if ($GcpAccount) { Add-PreflightCheck -Name 'GCP account selector' -Status Pass -Detail $GcpAccount }
        if ($GcpOrganization) { Add-PreflightCheck -Name 'GCP organization selector' -Status Pass -Detail $GcpOrganization }
        Add-PreflightCheck -Name 'GCP live API probe' -Status Warning -Detail 'gcloud credentials, enabled APIs and IAM permissions are validated during the read-only audit.'
    }
    if ($Service -contains 'Tailscale') {
        if ($TailscaleTailnet) {
            Add-PreflightCheck -Name 'Tailscale tailnet selector' -Status Pass -Detail $TailscaleTailnet
        }
        elseif ($env:TAILSCALE_TAILNET) {
            Add-PreflightCheck -Name 'Tailscale tailnet selector' -Status Pass -Detail 'TAILSCALE_TAILNET is set.'
        }
        else {
            Add-PreflightCheck -Name 'Tailscale tailnet selector' -Status Warning -Detail 'No -TailscaleTailnet supplied and TAILSCALE_TAILNET is not set.'
        }
        $tokenEnvName = if ([string]::IsNullOrWhiteSpace($TailscaleApiTokenEnv)) { 'TAILSCALE_API_TOKEN' } else { $TailscaleApiTokenEnv }
        if ([Environment]::GetEnvironmentVariable($tokenEnvName, 'Process')) {
            Add-PreflightCheck -Name 'Tailscale API token env' -Status Pass -Detail "$tokenEnvName is set in current process."
        }
        else {
            Add-PreflightCheck -Name 'Tailscale API token env' -Status Warning -Detail "$tokenEnvName is not set; live Tailscale checks will be skipped."
        }
        Add-PreflightCheck -Name 'Tailscale auth scheme' -Status Pass -Detail $TailscaleAuthScheme
    }
    if ($Service -contains 'Domain') {
        try {
            $authorizedDomains = @(Get-CaAuthorizedDomains)
            if ($authorizedDomains.Count -eq 0) {
                Add-PreflightCheck -Name 'Domain authorized scope' -Status Fail -Detail 'No -Domain values supplied and no Domain.AuthorizedDomains baseline configured.'
            }
            else {
                Add-PreflightCheck -Name 'Domain authorized scope' -Status Pass -Detail ($authorizedDomains -join ', ')
            }
            $subs = @(Get-CaDomainSubdomains)
            Add-PreflightCheck -Name 'Domain takeover probes' -Status Pass -Detail "Common subdomains: $($subs -join ', ')"
            Add-PreflightCheck -Name 'Domain resolver traffic' -Status Warning -Detail 'Formal and passive domain audits query public recursive DNS resolvers; they do not connect to the audited asset.'
        }
        catch {
            Add-PreflightCheck -Name 'Domain authorized scope' -Status Fail -Detail $_.Exception.Message
        }
    }
    if ($Service -contains 'VPS') {
        if ($VpsTarget) {
            Test-CliAvailable -Name 'ssh' -InstallHint 'Missing. Install OpenSSH client or run the VPS audit locally on the Linux host.'
            Add-PreflightCheck -Name 'VPS SSH target' -Status Pass -Detail $VpsTarget
            if ($VpsSshUser) { Add-PreflightCheck -Name 'VPS SSH user' -Status Pass -Detail $VpsSshUser }
            Add-PreflightCheck -Name 'VPS SSH port' -Status Pass -Detail ([string]$VpsSshPort)
        }
        else {
            if (Get-Command -Name sh -ErrorAction SilentlyContinue) {
                Add-PreflightCheck -Name 'VPS local shell' -Status Pass -Detail 'sh found in PATH.'
            }
            else {
                Add-PreflightCheck -Name 'VPS local shell' -Status Warning -Detail 'No -VpsTarget supplied and sh is not in PATH; live VPS checks require Linux/POSIX shell.'
            }
        }
        if ($VpsAllowedPublicPort) {
            Add-PreflightCheck -Name 'VPS allowed public ports' -Status Pass -Detail ($VpsAllowedPublicPort -join ', ')
        }
        else {
            Add-PreflightCheck -Name 'VPS allowed public ports' -Status Warning -Detail 'No -VpsAllowedPublicPort supplied; baseline VPS.AllowedPublicPorts will be used.'
        }
        Add-PreflightCheck -Name 'VPS live host probe' -Status Warning -Detail 'SSH reachability and host permissions are validated during the read-only audit phase.'
    }
    if ($Service -contains 'Inventory') {
        Add-PreflightCheck -Name 'Inventory mode' -Status Warning -Detail 'Inventory collects from any configured aws/az/gcloud/Tailscale context and skips unavailable providers.'
    }

    $pester = Get-Module -ListAvailable -Name Pester | Sort-Object Version -Descending | Select-Object -First 1
    if ($pester -and $pester.Version -ge [version]'5.0') {
        Add-PreflightCheck -Name 'Pester 5+' -Status Pass -Detail "Version $($pester.Version)"
    }
    elseif ($RequirePester) {
        if ($pester) {
            $detail = "Installed version is $($pester.Version); 5.0+ required."
        }
        else {
            $detail = 'Pester is not installed.'
        }
        Add-PreflightCheck -Name 'Pester 5+' -Status Fail -Detail $detail
    }
    else {
        if ($pester) {
            $detail = "Installed version is $($pester.Version); tests require 5.0+."
        }
        else {
            $detail = 'Not installed; only needed for tests.'
        }
        Add-PreflightCheck -Name 'Pester 5+' -Status Warning -Detail $detail
    }
}
catch {
    Add-PreflightCheck -Name 'Unhandled preflight exception' -Status Fail -Category Internal -Detail $_.Exception.Message `
        -Recommendation 'Use the diagnostic ID with the local error record to correct the Claudit runtime failure.'
}

$failCount = @($result.Checks | Where-Object Status -eq 'Fail').Count
$warningCount = @($result.Checks | Where-Object Status -eq 'Warning').Count
$passCount = @($result.Checks | Where-Object Status -eq 'Pass').Count
$result.Ready = ($failCount -eq 0)
$result.Outcome = if ($failCount -gt 0) { 'Blocked' } elseif ($warningCount -gt 0) { 'ReadyWithWarnings' } else { 'Ready' }
$result.Summary = [pscustomobject]@{
    Total = $result.Checks.Count
    Pass = $passCount
    Warning = $warningCount
    Fail = $failCount
    Blocking = $failCount
}
$output = [pscustomobject]$result

if ($JsonOutputPath) {
    $jsonParent = Split-Path -Parent $JsonOutputPath
    if ($jsonParent -and -not (Test-Path -LiteralPath $jsonParent)) {
        New-Item -ItemType Directory -Path $jsonParent -Force | Out-Null
    }
    $output | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $JsonOutputPath -Encoding UTF8
}

$output

if ($result.Status -eq 'Fail') { exit 2 }
exit 0
