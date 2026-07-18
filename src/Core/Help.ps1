<#
    Help.ps1 - compact command help for script entry points.

    PowerShell scripts do not treat --help as a normal switch. The top-level
    scripts capture remaining arguments, then delegate here so every command has
    a consistent Unix-friendly help path without accepting arbitrary typos.
#>

function Test-CaHelpRequested {
    [CmdletBinding()]
    param(
        [switch]$Help,
        [string[]]$RemainingArguments = @(),
        [string]$InvocationLine = ''
    )

    if ($Help.IsPresent) { return $true }
    if ($InvocationLine -match '(^|\s)(--help|-help|/\?|-\?)(\s|$)') { return $true }
    return @($RemainingArguments | Where-Object { $_ -in @('--help', '-help', '/?', '-?') }).Count -gt 0
}

function Assert-CaNoRemainingArgument {
    [CmdletBinding()]
    param([string[]]$RemainingArguments = @())

    # Script invocation with ValueFromRemainingArguments can inject "." even
    # when the caller supplied no extra argument. Treat only that binder artifact
    # as harmless; real unknown tokens still fail loudly.
    $allowed = @('--help', '-help', '/?', '-?', '.')
    $unknown = @($RemainingArguments | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_) -and $_ -notin $allowed
    })
    if ($unknown.Count -gt 0) {
        throw "Unknown argument(s): $($unknown -join ', '). Use --help for command examples."
    }
}

function Show-CaCommandHelp {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Command)

    $name = [System.IO.Path]::GetFileNameWithoutExtension($Command)
    switch ($name) {
        'claudit' {
@'
claudit.ps1

Purpose:
  One operator entry point for Claudit. It routes to the focused scripts without
  hiding their advanced parameters.

Usage:
  .\claudit.ps1 [command] [args...]
  .\claudit.ps1 --help

Commands:
  dashboard | dash | ui        Start the local cockpit. Default command.
  wizard | guide              Guided profile, preflight and optional live run.
  preflight | check           Offline readiness check.
  doctor                      Offline preflight for every provider.
  formal                      Formal DNS/RFC control for authorized domains; no asset connection.
  passive                     Guarded read-only provider audit (default control level).
  active                      Guarded passive audit plus authorized bounded probes.
  safe | run | go             Guarded audit: preflight first, live only with confirmation.
  m365                        Shortcut for safe -Service M365.
  all                         Shortcut for safe -Service All.
  domain                      Shortcut for safe -Service Domain.
  vps                         Shortcut for safe -Service VPS.
  audit | live                Direct live audit entry point.
  install                     Install optional PowerShell prerequisites.
  reset                       Clear process-level Claudit/Pester residue.
  test                        Run Pester tests.

Examples:
  .\claudit.ps1
  .\claudit.ps1 doctor
  .\claudit.ps1 formal -Service All
  .\claudit.ps1 active -Service Domain,VPS -Domain example.com -VpsTarget vps.example.com -VpsProbePort 22,443 -ConfirmActiveProbes -ConfirmTenantConnection
  .\claudit.ps1 m365 -ConfirmTenantConnection -Format All
  .\claudit.ps1 vps -VpsTarget vps.example.com -VpsSshUser audit -VpsAllowedPublicPort 80,443 -ConfirmTenantConnection
  .\claudit.ps1 domain -Domain example.com -ConfirmTenantConnection -Format All
  .\claudit.ps1 audit -Service AWS -AwsProfile audit -AwsRegion eu-west-1 -Format All
  .\claudit.ps1 test

Operator tricks:
  - Prefer safe/go/m365/all/domain/vps during engagements: they preserve the preflight gate.
  - Use audit/live only when you intentionally want the direct runner.
  - Every command after the subcommand is passed to the underlying script.
  - The dashboard remains default because it exposes operations, history and logs in one loopback cockpit.
'@
        }
        'Invoke-ClauditAudit' {
@'
Invoke-ClauditAudit.ps1

Purpose:
  Run the live read-only audit and write reports.

Usage:
  .\Invoke-ClauditAudit.ps1 [options]
  .\Invoke-ClauditAudit.ps1 --help

Core options:
  -Service <list>          Entra, Exchange, SharePoint, OneDrive, Azure, AWS, GCP, Tailscale, Domain, VPS, Inventory, M365, All
  -Format <fmt>            Html, Json, Markdown, Csv, All
  -OutputDirectory <path>  Report folder
  -TenantName <name>       Display name in reports
  -BaselinePath <path>     Custom baseline JSON
  -CompareWith <json>      Compare with a previous Claudit JSON report
  -RunPester               Replay generated findings through Pester compliance tests
  -ControlLevel <level>    Passive (default) or Active
  -ConfirmActiveProbes     Required consent gate for Active
  -VpsProbePort <list>     Explicit remote VPS ports; no ranges or discovery
  -ActiveTimeoutMs <ms>    Per probe timeout, 250-10000 (default 3000)

Microsoft 365:
  -Environment <cloud>     Global, USGov, USGovDOD, China
  -GraphAuthMode <mode>    DeviceCode or Browser
  -SkipExchange            Do not connect Exchange even if selected
  -AppOnly                 Certificate-based unattended auth
  -TenantId <id> -ClientId <id> -CertificateThumbprint <thumbprint>
  -Organization <domain>   Required for Exchange app-only

Cloud provider selectors:
  -AzureSubscription <id>  Azure subscription for az CLI
  -AzureTenant <id>        Expected Azure tenant id
  -AwsProfile <name>       AWS CLI profile
  -AwsRegion <list>        AWS regions for regional checks
  -GcpProject <id>         Google Cloud project
  -GcpAccount <email>      gcloud account selector
  -GcpOrganization <id>    Optional GCP org id
  -TailscaleTailnet <name> Tailnet name; or set TAILSCALE_TAILNET
  -TailscaleApiTokenEnv <env>  Env var containing token; default TAILSCALE_API_TOKEN
  -TailscaleAuthScheme <s> Auto, Basic, Bearer
  -Domain <list>           Pre-authorized domains for passive DNS/email checks
  -DomainSubdomain <list>  Common subdomains for dangling-CNAME checks
  -VpsTarget <host>        Linux VPS SSH target; blank audits local host
  -VpsSshUser <user>       Optional SSH user when target omits user@
  -VpsSshPort <port>       SSH port, default 22
  -VpsAllowedPublicPort <list>  Public listener ports accepted by policy

Examples:
  .\Invoke-ClauditAudit.ps1
  .\Invoke-ClauditAudit.ps1 -Service M365 -Format All
  .\Invoke-ClauditAudit.ps1 -Service Azure -AzureSubscription <sub-id> -Format All
  .\Invoke-ClauditAudit.ps1 -Service AWS -AwsProfile audit -AwsRegion eu-west-1,eu-central-1
  .\Invoke-ClauditAudit.ps1 -Service GCP -GcpProject prod-project -GcpAccount auditor@example.com
  $env:TAILSCALE_TAILNET='example.com'; $env:TAILSCALE_API_TOKEN='<token>'
  .\Invoke-ClauditAudit.ps1 -Service Tailscale
  .\Invoke-ClauditAudit.ps1 -Service Inventory -Format All
  .\Invoke-ClauditAudit.ps1 -Service Domain -Domain example.com,example.org -Format All
  .\Invoke-ClauditAudit.ps1 -Service VPS -VpsTarget vps.example.com -VpsSshUser audit -VpsAllowedPublicPort 80,443
  .\Invoke-ClauditAudit.ps1 -Service All -CompareWith .\reports\old\claudit.json

Operator tricks:
  - DeviceCode is default for embedded terminals.
  - Browser auth opens a temporary browser profile and loopback callback; it does not use the Windows account/config picker.
  - Use -Format All when you need both human review and machine-readable drift.
  - Keep AWS regions small for a first run, then expand after permissions are clean.
  - Domain mode refuses implicit targets; pass only pre-authorized domains.
  - VPS mode runs local/SSH read-only shell probes; no agent is installed.
  - Tailscale tokens are never stored; set them only in the current process.
  - Exit code 2 means Critical/High failures or runtime Error findings.
'@
        }
        'Start-ClauditSafeAudit' {
@'
Start-ClauditSafeAudit.ps1

Purpose:
  Guarded launcher. Always runs offline preflight first; live audit starts only
  with -ConfirmTenantConnection.

Usage:
  .\Start-ClauditSafeAudit.ps1 [options]
  .\Start-ClauditSafeAudit.ps1 --help

Common options:
  -Service <list>                 M365, All, or concrete services
  -ControlLevel <level>           Formal, Passive (default), or Active
  -ConfirmTenantConnection        Start live read-only audit after preflight
  -ConfirmActiveProbes            Required second consent gate for Active
  -VpsProbePort <list>            Explicit VPS ports for bounded reachability checks
  -OutputDirectory <path>         Run output directory
  -Format <fmt>                   Html, Json, Markdown, Csv, All
  -RunPester                      Run compliance replay after report generation
  -CompareWith <json>             Drift comparison baseline
  -NotifyWebhook <url>            Teams/Slack webhook, never used unless supplied
  -NotifyType Teams|Slack

Provider options:
  Same selectors as Invoke-ClauditAudit: Azure, AWS, GCP, Tailscale and VPS
  options are passed through after preflight. Passive Domain mode uses DNS only;
  Active adds one TLS handshake per authorized root domain. VPS Active probes
  only explicit -VpsProbePort values.

Examples:
  .\Start-ClauditSafeAudit.ps1
  .\Start-ClauditSafeAudit.ps1 -Service All
  .\Start-ClauditSafeAudit.ps1 -Service M365 -ConfirmTenantConnection -Format All
  .\Start-ClauditSafeAudit.ps1 -Service Azure,AWS -AzureSubscription <sub-id> -AwsProfile audit -ConfirmTenantConnection
  .\Start-ClauditSafeAudit.ps1 -Service Tailscale -TailscaleTailnet example.com -ConfirmTenantConnection
  .\Start-ClauditSafeAudit.ps1 -Service Domain -Domain example.com -ConfirmTenantConnection
  .\Start-ClauditSafeAudit.ps1 -Service VPS -VpsTarget vps.example.com -VpsSshUser audit -ConfirmTenantConnection

Operator tricks:
  - Run without -ConfirmTenantConnection on new workstations.
  - Use this launcher for Graph/Exchange auth isolation; it starts a clean pwsh -NoProfile child.
  - Do not put webhook URLs in profiles or scripts; pass them only at execution time.
  - The safe launcher passes the webhook to the child through CLAUDIT_NOTIFY_WEBHOOK, not a process argument.
'@
        }
        'Start-ClauditWizard' {
@'
Start-ClauditWizard.ps1

Purpose:
  Interactive guided wizard for safe audits. It creates an idempotent non-secret
  profile, runs offline preflight, then asks before live connection.

Usage:
  .\Start-ClauditWizard.ps1 [options]
  .\Start-ClauditWizard.ps1 --help

Options:
  -ProfilePath <json>  Custom profile path; default is the private user config directory
  -UseDefaults         Non-interactive defaults/profile replay
  -NoLive              Stop after successful preflight

Examples:
  .\Start-ClauditWizard.ps1
  .\Start-ClauditWizard.ps1 -NoLive
  .\Start-ClauditWizard.ps1 -UseDefaults -NoLive
  .\Start-ClauditWizard.ps1 -ProfilePath C:\private\client-a.profile.json

Operator tricks:
  - The profile stores selectors only: tenant labels, service list, output path, provider names.
  - Certificate thumbprints, webhook URLs and Tailscale API tokens are never persisted.
  - Use -NoLive for workstation validation before touching a tenant.
  - Shortcut services: M365 for Microsoft 365 only, All for every provider.
  - Domain mode requires explicit authorized domains before any DNS lookup.
'@
        }
        'Start-ClauditDashboard' {
@'
Start-ClauditDashboard.ps1

Purpose:
  Start the local web cockpit for Claudit operations, logs and report files.
  It binds to loopback by default and uses only PowerShell plus vanilla HTML/CSS/JS.

Usage:
  .\Start-ClauditDashboard.ps1 [options]
  .\Start-ClauditDashboard.ps1 --help

Options:
  -BindAddress <ip>       Default 127.0.0.1
  -Port <port>            Default 8765
  -PortFallbackCount <n>  Try the next n ports if the requested port is busy
  -ReportRoot <path>      Report tree to index and serve, default .\reports
  -OperationRoot <path>   Dashboard operation logs, default .\reports\dashboard
  -RetentionCount <n>     Completed runs to keep; 1-10000, default 100
  -StatePath <path>       Persistent dashboard settings JSON

Examples:
  .\Start-ClauditDashboard.ps1
  .\Start-ClauditDashboard.ps1 -Port 8770
  .\Start-ClauditDashboard.ps1 -ReportRoot .\reports -RetentionCount 100

Operator tricks:
  - Open the Local URL printed at startup.
  - Non-loopback binds are rejected; use an SSH tunnel for remote operation.
  - Preflight mode is offline; live audit uses Start-ClauditSafeAudit with -ConfirmTenantConnection.
  - The UI accepts non-secret selectors only. Put tokens in environment variables before launch.
  - Report file access is confined to the configured ReportRoot.
  - Retention never removes running operations or unrelated directories.
'@
        }
        'Test-ClauditPreflight' {
@'
Test-ClauditPreflight.ps1

Purpose:
  Offline safety check for local runtime, modules, CLIs, baseline and output path.
  It does not connect to Microsoft Graph, Exchange, DNS-over-HTTPS, cloud APIs or webhooks.

Usage:
  .\Test-ClauditPreflight.ps1 [options]
  .\Test-ClauditPreflight.ps1 --help

Options:
  -Service <list>            Services to validate prerequisites for
  -BaselinePath <path>       Custom baseline JSON
  -OutputDirectory <path>    Target report directory
  -JsonOutputPath <path>     Write preflight result JSON
  -RequirePester             Fail if Pester 5+ is not installed
  -GraphAuthMode <mode>      DeviceCode or Browser
  Provider selectors: -AzureSubscription, -AwsProfile, -AwsRegion,
  -GcpProject, -GcpAccount, -TailscaleTailnet, -TailscaleApiTokenEnv,
  -Domain, -DomainSubdomain, -VpsTarget, -VpsSshUser, -VpsSshPort,
  -VpsAllowedPublicPort.

Examples:
  .\Test-ClauditPreflight.ps1
  .\Test-ClauditPreflight.ps1 -Service All
  .\Test-ClauditPreflight.ps1 -Service AWS -AwsProfile audit -AwsRegion eu-west-1
  .\Test-ClauditPreflight.ps1 -Service Azure -AzureSubscription <sub-id>
  .\Test-ClauditPreflight.ps1 -Service Tailscale -TailscaleTailnet example.com
  .\Test-ClauditPreflight.ps1 -Service Domain -Domain example.com
  .\Test-ClauditPreflight.ps1 -Service VPS -VpsTarget vps.example.com -VpsSshUser audit
  .\Test-ClauditPreflight.ps1 -Service M365 -RequirePester -JsonOutputPath .\reports\preflight.json

Operator tricks:
  - Preflight warnings are useful: they tell you what live audit may skip.
  - Tailscale token and webhook values are never serialized; preflight records only set/not set.
  - Use JsonOutputPath when collecting workstation evidence before an engagement.
  - Domain mode validates authorized scope offline and performs DNS lookups only during audit.
  - VPS mode validates local shell or OpenSSH client offline; host posture is checked during audit.
'@
        }
        'Install-ClauditPrerequisites' {
@'
Install-ClauditPrerequisites.ps1

Purpose:
  Explicit installer for PowerShell module prerequisites from PowerShell Gallery.
  It installs nothing unless -ConfirmInstall is supplied.

Usage:
  .\Install-ClauditPrerequisites.ps1 [options]
  .\Install-ClauditPrerequisites.ps1 --help

Options:
  -Service <list>      Choose modules needed for selected services
  -IncludePester       Install/upgrade Pester 5+
  -ConfirmInstall      Actually install modules
  -TrustPSGallery      Mark PSGallery trusted before installation

Examples:
  .\Install-ClauditPrerequisites.ps1
  .\Install-ClauditPrerequisites.ps1 -Service M365 -IncludePester -ConfirmInstall
  .\Install-ClauditPrerequisites.ps1 -Service Entra,Exchange -ConfirmInstall
  .\Install-ClauditPrerequisites.ps1 -Service All -IncludePester -ConfirmInstall

Operator tricks:
  - Gallery is community supply chain: install the minimum module set you need.
  - AWS, Azure, GCP, Tailscale and VPS use official CLIs/API tokens/SSH; this script prints install hints only.
  - Prefer CurrentUser scope; no admin rights needed for normal Claudit use.
'@
        }
        'Reset-ClauditEnvironment' {
@'
Reset-ClauditEnvironment.ps1

Purpose:
  Clear process-level Claudit/Pester residue from the current shell.

Usage:
  .\Reset-ClauditEnvironment.ps1 [options]
  .\Reset-ClauditEnvironment.ps1 --help

Options:
  -ClearProxy   Also clear HTTPS_PROXY, HTTP_PROXY and NO_PROXY from the current process.

Examples:
  .\Reset-ClauditEnvironment.ps1
  .\Reset-ClauditEnvironment.ps1 -ClearProxy

Operator tricks:
  - Use after Pester replay if CLAUDIT_FINDINGS points to an old report.
  - Also clears CLAUDIT_NOTIFY_WEBHOOK if a prior interrupted safe run left it in-process.
  - -ClearProxy affects only the current process environment, not machine/user persistent vars.
  - It does not clear cloud credentials or Tailscale API tokens.
'@
        }
        default {
            throw "No Claudit help topic registered for '$Command'."
        }
    }
}
