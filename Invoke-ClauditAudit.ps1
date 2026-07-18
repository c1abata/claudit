#Requires -Version 7.2
<#
.SYNOPSIS
    Claudit master runner - connects read-only, audits the tenant, writes reports.

.DESCRIPTION
    One-shot orchestration for an administrator or a Windows scheduled task.
    Read-only: it never modifies the tenant. Exit code is non-zero when any
    Critical/High failure is found, so a scheduled task can flag it.

.PARAMETER Service
    Subset of workloads to audit. Default: Microsoft 365 services.

.PARAMETER Format
    Report format(s): Html, Json, Markdown, Csv or All (default).

.PARAMETER Environment
    National cloud: Global (default), USGov, USGovDOD, China.

.PARAMETER CompareWith
    Path to a previous Claudit JSON report; prints a drift summary (regressions/fixes).

.PARAMETER NotifyWebhook
    Teams/Slack incoming-webhook URL to post the summary to.

.EXAMPLE
    ./Invoke-ClauditAudit.ps1
    Interactive audit of all services, all report formats.

.EXAMPLE
    ./Invoke-ClauditAudit.ps1 -AppOnly -TenantId <id> -ClientId <id> `
        -CertificateThumbprint <tp> -Organization contoso.onmicrosoft.com `
        -NotifyWebhook https://contoso.webhook.office.com/...
    Unattended audit suitable for a scheduled task, with Teams notification.
#>
[CmdletBinding()]
param(
    [string[]]$Service = @('Entra', 'Exchange', 'SharePoint', 'OneDrive'),

    [string]$OutputDirectory,
    [ValidateSet('Html', 'Json', 'Markdown', 'Csv', 'All')][string]$Format = 'All',
    [string]$TenantName = 'Cloud tenant',
    [string]$BaselinePath,
    [ValidateSet('Formal', 'Passive', 'Active')][string]$ControlLevel = 'Passive',
    [int[]]$VpsProbePort = @(),
    [ValidateRange(250, 10000)][int]$ActiveTimeoutMs = 3000,
    [switch]$ConfirmActiveProbes,
    [ValidateSet('Global', 'USGov', 'USGovDOD', 'China')][string]$Environment = 'Global',
    [ValidateSet('DeviceCode', 'Browser')][string]$GraphAuthMode = 'DeviceCode',

    [string]$AzureSubscription,
    [string]$AzureTenant,

    [string]$AwsProfile,
    [string[]]$AwsRegion,

    [string]$GcpProject,
    [string]$GcpAccount,
    [string]$GcpOrganization,

    [string]$TailscaleTailnet,
    [string]$TailscaleApiTokenEnv = 'TAILSCALE_API_TOKEN',
    [ValidateSet('Auto', 'Basic', 'Bearer')][string]$TailscaleAuthScheme = 'Auto',

    [string[]]$Domain,
    [string[]]$DomainSubdomain,

    [string]$VpsTarget,
    [string]$VpsSshUser,
    [int]$VpsSshPort = 22,
    [int[]]$VpsAllowedPublicPort,

    [string]$CompareWith,

    [string]$NotifyWebhook,
    [string]$NotifyWebhookEnv = 'CLAUDIT_NOTIFY_WEBHOOK',
    [ValidateSet('Teams', 'Slack')][string]$NotifyType = 'Teams',

    [switch]$SkipExchange,
    [switch]$RunPester,

    # App-only auth (optional)
    [switch]$AppOnly,
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint,
    [string]$Organization,

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
if ($ControlLevel -eq 'Active' -and -not $ConfirmActiveProbes) {
    throw 'Active control level requires -ConfirmActiveProbes. Only explicitly authorized Domain and VPS targets are probed.'
}
if ([string]::IsNullOrWhiteSpace($NotifyWebhook) -and -not [string]::IsNullOrWhiteSpace($NotifyWebhookEnv)) {
    $NotifyWebhook = [Environment]::GetEnvironmentVariable($NotifyWebhookEnv, 'Process')
}
$Service = Resolve-CaServices -Service $Service
if ($ControlLevel -eq 'Formal') {
    if ($Service -notcontains 'Domain') {
        throw 'Formal live evaluation currently applies to Domain only. Supply -Service Domain and at least one authorized -Domain.'
    }
    $unsupported = @($Service | Where-Object { $_ -ne 'Domain' })
    if ($unsupported.Count -gt 0) {
        Write-Warning "Formal level runs the Domain RFC checks only; excluded services: $($unsupported -join ', ')."
    }
    $Service = @('Domain')
}
Set-CaProviderOption -Provider Azure -Options @{ Subscription = $AzureSubscription; Tenant = $AzureTenant }
Set-CaProviderOption -Provider AWS -Options @{ Profile = $AwsProfile; Regions = @($AwsRegion) }
Set-CaProviderOption -Provider GCP -Options @{ Project = $GcpProject; Account = $GcpAccount; Organization = $GcpOrganization }
Set-CaProviderOption -Provider Tailscale -Options @{ Tailnet = $TailscaleTailnet; ApiTokenEnv = $TailscaleApiTokenEnv; AuthScheme = $TailscaleAuthScheme }
Set-CaProviderOption -Provider Domain -Options @{ Domains = @($Domain); Subdomains = @($DomainSubdomain) }
Set-CaProviderOption -Provider VPS -Options @{ Target = $VpsTarget; SshUser = $VpsSshUser; SshPort = $VpsSshPort; AllowedPublicPorts = @($VpsAllowedPublicPort) }

$s = [pscustomobject]@{
    Critical = 0
    High     = 0
}
$pesterFailed = $false

if ($BaselinePath) { Get-CaBaseline -Path $BaselinePath -Force | Out-Null }

$serviceSpecs = @($Service | ForEach-Object { Get-CaServiceSpec -Name $_ })
$needGraph = @($serviceSpecs | Where-Object { $_.RequiresGraph }).Count -gt 0
$needExchange = (@($serviceSpecs | Where-Object { $_.RequiresExchange }).Count -gt 0) -and -not $SkipExchange
$needMicrosoft = $needGraph -or $needExchange

$connectParams = @{ SkipExchange = (-not $needExchange); Environment = $Environment }
if (-not $needGraph) {
    $connectParams['SkipGraph'] = $true
}
elseif (-not $AppOnly) {
    $connectParams['GraphAuthMode'] = $GraphAuthMode
}
if ($AppOnly -and $needMicrosoft) {
    foreach ($p in 'TenantId', 'ClientId', 'CertificateThumbprint') {
        $value = Get-Variable -Name $p -ValueOnly
        if ([string]::IsNullOrWhiteSpace($value)) { throw "-AppOnly requires -$p." }
    }
    if ($needExchange -and [string]::IsNullOrWhiteSpace($Organization)) {
        throw '-AppOnly Exchange audits require -Organization (for example contoso.onmicrosoft.com).'
    }
    $connectParams['TenantId'] = $TenantId
    $connectParams['ClientId'] = $ClientId
    $connectParams['CertificateThumbprint'] = $CertificateThumbprint
    if ($Organization) { $connectParams['Organization'] = $Organization }
}
elseif ($AppOnly -and -not $needMicrosoft) {
    Write-Warning '-AppOnly was supplied but no Microsoft 365 service was selected; ignoring Microsoft app-only parameters.'
}

if ($needMicrosoft) {
    Write-Host 'Claudit: connecting Microsoft 365 (read-only)...' -ForegroundColor Cyan
}
else {
    Write-Host 'Claudit: no Microsoft 365 connection required for selected services.' -ForegroundColor Cyan
}
Connect-Claudit @connectParams | Out-Null

try {
    Write-Host "Claudit: $($ControlLevel.ToLowerInvariant()) audit of $($Service -join ', ')..." -ForegroundColor Cyan
    $findings = @(Get-CaAllFindings -Service $Service)
    $levelRank = @{ Formal = 1; Passive = 2; Active = 3 }
    $findings = @($findings | Where-Object { $levelRank[$_.ControlLevel] -le $levelRank[$ControlLevel] })
    if ($ControlLevel -eq 'Active') {
        $active = @(Get-CaActiveFindings -Service $Service -VpsProbePort $VpsProbePort -TimeoutMs $ActiveTimeoutMs)
        $findings = @($findings) + @($active)
        if ($active.Count -eq 0) {
            Write-Warning 'Active level selected, but no Domain or VPS service was selected; no network probes were added.'
        }
    }

    if ($findings.Count -eq 0) {
        throw 'No findings were produced. Check selected services and connection prerequisites.'
    }

    $report = $findings | New-CaReport -OutputDirectory $OutputDirectory -Format $Format -TenantName $TenantName
    if (-not $report) {
        throw 'Report generation returned no output.'
    }
    $s = $report.Summary

    Write-Host ''
    Write-Host ("Total {0} | Pass {1} | Fail {2} | Warning {3} | Skipped {4} | Error {5}" -f $s.Total, $s.Pass, $s.Fail, $s.Warning, $s.Skipped, $s.Error)
    Write-Host ("Failures by severity -> Critical {0} | High {1} | Medium {2} | Low {3}" -f $s.Critical, $s.High, $s.Medium, $s.Low) -ForegroundColor Yellow
    foreach ($f in $report.Files) { Write-Host "Report: $f" -ForegroundColor Green }

    # Drift comparison against a previous JSON report.
    if ($CompareWith) {
        $latestJson = $report.Files | Where-Object { $_ -like '*.json' } | Select-Object -First 1
        if (-not $latestJson) {
            Write-Warning 'Drift comparison needs a JSON report; include Json or All in -Format.'
        }
        elseif (-not (Test-Path -LiteralPath $CompareWith)) {
            Write-Warning "Drift baseline not found: $CompareWith"
        }
        else {
            $drift = Compare-ClauditResult -ReferencePath $CompareWith -DifferencePath $latestJson
            $regressed = @($drift | Where-Object { $_.Change -eq 'Regressed' })
            $fixed = @($drift | Where-Object { $_.Change -eq 'Fixed' })
            Write-Host ''
            Write-Host ("Drift vs baseline -> Regressed {0} | Fixed {1} | New {2}" -f $regressed.Count, $fixed.Count, @($drift | Where-Object { $_.Change -eq 'New' }).Count) -ForegroundColor Magenta
            $drift | Where-Object { $_.Change -in @('Regressed', 'Fixed', 'New', 'Changed') } |
                Format-Table CheckId, Service, Change, OldStatus, NewStatus -AutoSize | Out-Host
        }
    }

    if ($NotifyWebhook) {
        try {
            Send-CaNotification -WebhookUrl $NotifyWebhook -Summary $s -Type $NotifyType -TenantName $TenantName
            Write-Host "Notification sent to $NotifyType webhook." -ForegroundColor Green
        }
        catch { Write-Warning "Notification failed: $($_.Exception.Message)" }
    }

    if ($RunPester) {
        $latestJson = $report.Files | Where-Object { $_ -like '*.json' } | Select-Object -First 1
        if ($latestJson) {
            $oldFindingsEnv = $env:CLAUDIT_FINDINGS
            try {
                $env:CLAUDIT_FINDINGS = $latestJson
                $testDir = Join-Path $PSScriptRoot 'tests'
                if (Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version.Major -ge 5 }) {
                    Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop
                    $pesterResult = Invoke-Pester -Path $testDir -Output Detailed -PassThru
                    if ($pesterResult.FailedCount -gt 0) {
                        $pesterFailed = $true
                        Write-Warning "$($pesterResult.FailedCount) Pester test(s) failed."
                    }
                }
                else {
                    $pesterFailed = $true
                    Write-Warning 'Pester 5+ not installed; skipping test run. Install-Module Pester -Scope CurrentUser'
                }
            }
            finally {
                if ($null -eq $oldFindingsEnv) {
                    Remove-Item Env:\CLAUDIT_FINDINGS -ErrorAction SilentlyContinue
                }
                else {
                    $env:CLAUDIT_FINDINGS = $oldFindingsEnv
                }
            }
        }
    }
}
finally {
    Disconnect-Claudit
}

# Non-zero exit if high-impact issues or unevaluated checks exist (useful for scheduled tasks).
if (($s.Critical + $s.High + $s.Error) -gt 0 -or $pesterFailed) { exit 2 }
exit 0
