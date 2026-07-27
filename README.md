# Claudit

Read-only **multi-cloud diagnostic and misconfiguration auditing** suite for
Microsoft 365, Azure, AWS, Google Cloud, Tailscale, Linux VPS hosts and
pre-authorized public domains. Microsoft 365 coverage
includes SharePoint Online, OneDrive for Business, Entra ID (Azure AD) and
Exchange Online.

Claudit is intentionally small: PowerShell + Pester, run from an admin
workstation or a scheduled task. **No cloud development environment, no CI/CD,
no agents.** It never changes the tenant/account/project: Microsoft checks use
`Get-*` / read-only Graph calls, AWS checks use `aws` list/describe/get calls,
Azure checks use `az` list/show/REST GET calls, Google Cloud checks use
`gcloud` read/list/describe calls, Tailscale checks use read-only API GETs, VPS
checks run local or SSH read-only POSIX commands, and Domain mode performs
passive DNS lookups only against operator-supplied domains.

**Release status:** `0.3.1` stable for private operator use. The supported path is
PowerShell 7.2+, the guarded launcher/wizard, a reviewed baseline and least-
privilege read-only identities. Provider APIs and permissions still require live
validation in the target environment.

The maintainer release archive is generated from a clean Git commit, never from
an arbitrary working tree:

```powershell
pwsh -NoProfile -File ./Build-ClauditRelease.ps1
```

This creates `dist/claudit-<version>.zip` and a matching `.sha256` file. On
Windows, extract the archive and run `pwsh -NoProfile -File ./claudit.ps1
doctor`; Claudit is portable and does not require a machine-wide installation.
On Ubuntu, extract it and run `sudo bash ./install-ubuntu.sh` from the extracted
directory.

Claudit takes inspiration from the excellent FOSS [Maester](https://maester.dev)
project: control-framework mapping (CISA SCuBA / CIS), EIDSCA-style identity
checks, SPF/DMARC validation, Graph paging, national-cloud support, drift
detection and multi-format reporting — packaged in a deliberately lightweight,
dependency-light form.

## Three control levels

Claudit uses cumulative engagement levels with explicit blast-radius gates:

| Level | Network behavior | Purpose |
|-------|------------------|---------|
| **Formal** | No connection to the asset; local validation plus DNS queries to recursive resolvers for authorized domains | Validate policy/readiness and grade DNS conformance (RCODE, NS, SOA, DNSSEC, MX, SPF, DMARC, DKIM, CAA, MTA-STS/TLS-RPT). |
| **Passive** | Formal plus read-only provider APIs, DNS, optional `dnsx` and operator-approved SSH | Inventory and evaluate cloud, tenant, domain and VPS configuration. This is the default. |
| **Active** | Passive plus bounded TLS/TCP handshakes | Validate TLS on authorized root domains and reachability of explicitly declared VPS ports. |

Active never expands port ranges, discovers targets, crawls applications,
authenticates to services or sends test payloads. It requires both
`-ConfirmTenantConnection` and `-ConfirmActiveProbes`; the operator must supply
every domain, VPS target and VPS probe port.

## What it does

* Connects read-only to Microsoft Graph and Exchange Online (incl. US Gov / China clouds).
* Audits Azure subscription posture through Azure CLI: privileged service-principal RBAC, high-risk Microsoft Graph application permissions, storage exposure, Key Vault protections and public IP inventory.
* Audits AWS account posture through AWS CLI profiles: root MFA, IAM password policy,
  CloudTrail, GuardDuty, Security Hub, S3 public access block, stale access keys,
  EBS encryption, AWS Config and VPC Flow Logs.
* Audits Google Cloud project posture through `gcloud`: IAM primitive roles,
  service account keys, audit logs, Cloud Storage exposure, default network,
  open admin firewall rules, OS Login and logging sinks.
* Audits Tailscale tailnet posture through the Tailscale API: device lifecycle,
  auth-key hygiene and overly broad ACL/grant rules.
* Audits Linux VPS host posture locally or through OpenSSH BatchMode: SSH
  hardening, public listeners, host firewall signal, pending updates and auth
  log availability.
* Audits pre-authorized public domains through a cached multi-resolver DNS core:
  RCODE health, NS, SOA timer sanity, DNSSEC validation, MX/null-MX, SPF, DMARC,
  DKIM selector posture, CAA, MTA-STS/TLS-RPT and dangling CNAME candidates.
  An optional sandboxed `dnsx` adapter adds bounded bulk resolution with explicit
  NXDOMAIN/SERVFAIL/dangling-CNAME classification.
* Captures a normalized multi-cloud asset inventory inspired by Cloudlist-style
  blue-team inventory workflows.
* Evaluates the tenant against an editable JSON **baseline** (CIS / Microsoft Secure Score aligned).
* Emits a flat list of **findings** (`Pass` / `Fail` / `Warning` / `Info` / `Error` / `Skipped` / `NotApplicable` / `Investigate`,
  with stable `FindingId`, outcome, blocking flag, severity and **CISA/CIS control IDs**). `Fail`
  means a confirmed audit problem, `Error` means execution blocked that check,
  `Skipped` means a required check was not evaluated, and `NotApplicable` means
  non-applicability was positively established.
* Renders **HTML**, schema-v2 **JSON**, **Markdown** and **CSV** reports with an overall
  outcome, evaluation coverage, per-service summary, problems, execution errors
  with diagnostic IDs, not-evaluated controls and the complete result set.
  `All` also emits OCSF 1.8 JSONL, OSCAL 1.2.1 Assessment Results, a versioned
  Claudit control catalog and a SHA-256 artifact manifest.
* Redacts common token/webhook patterns and hardens Markdown/CSV output against report injection.
* Detects **configuration drift** between two runs (`Compare-ClauditResult`).
* Optionally posts a summary to **Teams or Slack** via an incoming webhook.
* Turns the same findings into **Pester** test cases (pass/fail compliance, NUnit-XML friendly).

## Requirements

* PowerShell **7.2+**
* Microsoft 365 modules (install per-user, no admin rights needed):

  ```powershell
  Install-Module Microsoft.Graph.Authentication -RequiredVersion 2.38.0 -Scope CurrentUser
  Install-Module Microsoft.Graph.Identity.DirectoryManagement -RequiredVersion 2.38.0 -Scope CurrentUser
  Install-Module Microsoft.Graph.Identity.SignIns -RequiredVersion 2.38.0 -Scope CurrentUser
  Install-Module Microsoft.Graph.Applications -RequiredVersion 2.38.0 -Scope CurrentUser
  Install-Module Microsoft.Graph.Users -RequiredVersion 2.38.0 -Scope CurrentUser
  Install-Module ExchangeOnlineManagement -RequiredVersion 3.10.0 -Scope CurrentUser
  Install-Module Pester -RequiredVersion 5.8.0 -Scope CurrentUser   # optional, for tests
  ```

  The EIDSCA-style checks use raw Graph calls (`Invoke-MgGraphRequest`), so
  `Microsoft.Graph.Authentication` alone covers them. SPF/DMARC checks use
  DNS-over-HTTPS — no extra module, works on Windows/Linux/macOS.
* Optional for cloud provider audits:

  ```powershell
  aws --version      # AWS CLI v2
  az --version       # Azure CLI
  gcloud --version   # Google Cloud SDK
  ```

  Claudit does not install or store provider credentials. Use local SSO/profile
  configuration (`aws configure sso`, `gcloud auth login`) with read-only roles.
  For Azure, use `az login` / `az account set` with reader-style access. For
  Tailscale, set a short-lived API token in `TAILSCALE_API_TOKEN`; the wizard
  only stores the environment variable name, not the token.
* Optional for Linux VPS audits:

  ```powershell
  ssh -V            # only needed for -VpsTarget remote checks
  sh --version      # only needed for local host checks
  ```

  Claudit does not install an agent or copy scripts to the VPS. Remote checks
  use OpenSSH `BatchMode=yes` and execute read-only shell probes over the
  existing SSH identity.
* Optional for high-volume passive DNS validation: ProjectDiscovery `dnsx`.
  Enable it explicitly with `Domain.EnableDnsx` in a private baseline. Claudit
  invokes it with an argv-only process, hard timeout, output cap and temporary
  authorized-target file; shell execution is never used.

## Least-privilege access

Claudit only ever needs **read** access. Recommended Entra roles: **Global Reader**
+ **Security Reader**; for Exchange-only checks, **View-Only Organization
Management**.

Delegated Graph scopes requested interactively:

```
Directory.Read.All  Policy.Read.All  RoleManagement.Read.Directory
Application.Read.All  Organization.Read.All  User.Read.All
SharePointTenantSettings.Read.All
```

## Usage

Recommended operator entry point:

```powershell
./claudit.ps1                 # local cockpit, default
./claudit.ps1 doctor          # offline preflight for every provider
./claudit.ps1 formal -Service All
./claudit.ps1 formal -Service Domain -Domain example.com -Format All
./claudit.ps1 passive -Service AWS -AwsProfile audit -ConfirmTenantConnection
./claudit.ps1 active -Service Domain,VPS -Domain example.com -VpsTarget vps.example.com -VpsProbePort 22,443 -ConfirmActiveProbes -ConfirmTenantConnection
./claudit.ps1 m365 -ConfirmTenantConnection -Format All
./claudit.ps1 all -ConfirmTenantConnection -Format All
./claudit.ps1 vps -VpsTarget vps.example.com -VpsSshUser audit -VpsAllowedPublicPort 80,443 -ConfirmTenantConnection
./claudit.ps1 domain -Domain example.com -ConfirmTenantConnection -Format All
./claudit.ps1 test
```

On WSL/Linux/macOS, the shell shim uses the same orchestrator:

```bash
./claudit.sh doctor
./claudit.sh vps -VpsTarget vps.example.com -VpsSshUser audit -ConfirmTenantConnection
```

Use the focused scripts directly when you want their exact entry point. The
orchestrator passes every argument after the command through unchanged.

Every top-level script supports Unix-style help:

```powershell
./claudit.ps1 --help
./Start-ClauditWizard.ps1 --help
./Invoke-ClauditAudit.ps1 --help
./Test-ClauditPreflight.ps1 --help
```

Guided sysadmin wizard:

```powershell
./Start-ClauditWizard.ps1
```

Wizard with every supported service:

```powershell
./Start-ClauditWizard.ps1
# Select: All
```

Wizard for every Microsoft 365 area only:

```powershell
./Start-ClauditWizard.ps1
# Select: M365
```

Safe local preflight (no tenant/cloud connection):

```powershell
./Test-ClauditPreflight.ps1
```

AWS/GCP preflight only validates local CLI presence and non-secret selectors:

```powershell
./Test-ClauditPreflight.ps1 -Service AWS -AwsProfile audit -AwsRegion eu-west-1,eu-central-1
./Test-ClauditPreflight.ps1 -Service GCP -GcpProject prod-project
```

Install missing prerequisites explicitly (uses PowerShell Gallery):

```powershell
./Install-ClauditPrerequisites.ps1 -IncludePester -ConfirmInstall
```

Guarded launcher: Formal Domain runs after preflight without an asset connection;
Passive/Active require explicit approval for live read-only connection:

```powershell
./Start-ClauditSafeAudit.ps1
./Start-ClauditSafeAudit.ps1 -ConfirmTenantConnection
```

The guarded launcher runs the live audit in an isolated `pwsh -NoProfile`
process. Use it for M365 interactive auth; it avoids MSAL/Graph/Exchange DLL
conflicts from the current admin shell.

Local web cockpit for operations, logs and report history:

```powershell
./Start-ClauditDashboard.ps1 -RetentionCount 100
# open the Local URL printed at startup
```

The cockpit is a PowerShell server with packaged HTML/CSS/vanilla JS assets. Its
frontend follows the lightweight [WebUI](https://github.com/webui-dev/webui)
model: browser-native controls, no Node.js runtime, no client framework and no
remote UI dependencies. Structure, styling and behavior are separate files;
dynamic API data is rendered with DOM nodes rather than HTML strings, and the
document CSP accepts scripts and styles only from the local asset route. By
default it binds to private loopback `127.0.0.1` and tries the next port if
`8765` is already in use. Non-loopback binding is rejected because this is a
single-operator console without a multi-user authentication layer. It can start offline
preflight runs, guarded live read-only audits, stream child-process logs and
open report files under the configured report root. It accepts non-secret
selectors only; keep API tokens and webhook URLs in
environment variables or pass them through the existing CLI commands. On shared
networks, access it through an SSH loopback tunnel.

The **Results to keep** field stores the retention policy in
`dashboard-state.json`. Retention counts completed cockpit runs, keeps the
newest results and never removes a running job. Deletion is confined to
validated `dashboard-*` run directories; unrelated files are ignored.

## Ubuntu systemd service

Claudit can run as a hardened, restartable Ubuntu service. PowerShell 7.2+ and
systemd must already be installed.

```bash
sudo bash ./install-ubuntu.sh
sudo systemctl status claudit --no-pager
```

The installer creates:

- immutable application code under `/opt/claudit`;
- configuration under `/etc/claudit/service.json`;
- an optional secret environment file at `/etc/claudit/claudit.env`;
- persistent results, logs and provider CLI state under `/var/lib/claudit`;
- a restricted `claudit` service account and `claudit.service` unit.

The Web UI remains loopback-only. From the operator workstation:

```bash
ssh -L 8765:127.0.0.1:8765 operator@ubuntu-host
# open http://127.0.0.1:8765/
```

Change the default retention in `/etc/claudit/service.json`, or select a new
value in the UI before starting an operation. UI changes persist in
`/var/lib/claudit/dashboard-state.json` and therefore survive restarts. Existing
configuration files are preserved during upgrades. When upgrading a pre-0.3
installation, the installer:

- saves the previous baseline and wizard profile under
  `/var/lib/claudit/upgrade-backups/<timestamp>/`;
- merges the previous baseline values over the new defaults, so new required
  keys appear without resetting operator policy;
- migrates the service-account wizard profile to
  `/var/lib/claudit/.config/claudit/`;
- copies legacy `/opt/claudit/reports` files into the persistent report store
  without overwriting files already present.

If a legacy baseline is malformed or incompatible, the upgrade stops before
restarting the service and leaves its raw backup available for recovery.

Detailed operator runbook: [`docs/OPERATIONS.md`](docs/OPERATIONS.md).
Multi-cloud diagnostic matrix: [`docs/CLOUD_PROVIDER_RUNBOOK.md`](docs/CLOUD_PROVIDER_RUNBOOK.md).
Design boundary notes: [`docs/SWISS_ARMY_CLOUD_AUDIT.md`](docs/SWISS_ARMY_CLOUD_AUDIT.md).

Clear Claudit/Pester process environment residue:

```powershell
./Reset-ClauditEnvironment.ps1
```

Interactive (an admin at the keyboard):

```powershell
./Invoke-ClauditAudit.ps1
```

Audit a subset, choose a report format/all formats, pick a national cloud:

```powershell
./Invoke-ClauditAudit.ps1 -Service Entra,Exchange -Format All -Environment USGov
```

Audit all Microsoft 365 areas without AWS/GCP:

```powershell
./Invoke-ClauditAudit.ps1 -Service M365 -Format All
```

In embedded terminals on Windows, use device-code Graph auth to avoid WAM/browser
issues. This is the default:

```powershell
./Invoke-ClauditAudit.ps1 -Service M365 -GraphAuthMode DeviceCode
```

When `-GraphAuthMode Browser` is selected, Claudit opens a temporary
Edge/Chrome/Brave profile and completes OAuth through a localhost callback with
PKCE. It does not use the Windows account/configuration picker, and the temporary
browser profile is removed after the token is captured.

Audit AWS through an existing read-only CLI profile:

```powershell
./Invoke-ClauditAudit.ps1 -Service AWS -AwsProfile audit -AwsRegion eu-west-1,eu-central-1
```

Audit Azure through an existing Azure CLI login:

```powershell
./Invoke-ClauditAudit.ps1 -Service Azure -AzureSubscription <subscription-id>
```

Audit Google Cloud through an existing `gcloud` login:

```powershell
./Invoke-ClauditAudit.ps1 -Service GCP -GcpProject prod-project
```

Audit Tailscale with a short-lived API token:

```powershell
$env:TAILSCALE_TAILNET = 'example.com'
$env:TAILSCALE_API_TOKEN = '<short-lived-token>'
./Invoke-ClauditAudit.ps1 -Service Tailscale
```

Audit pre-authorized public domains without tenant credentials:

```powershell
./Start-ClauditSafeAudit.ps1 -Service Domain `
  -Domain example.com,example.org `
  -DomainSubdomain www,autodiscover,mail,vpn,portal,admin,dev,staging `
  -ConfirmTenantConnection `
    -Format All
```

Audit a Linux VPS over SSH without installing an agent:

```powershell
./Start-ClauditSafeAudit.ps1 -Service VPS `
  -VpsTarget vps.example.com `
  -VpsSshUser audit `
  -VpsAllowedPublicPort 80,443 `
  -ConfirmTenantConnection `
  -Format All
```

Audit the current Linux host locally:

```powershell
./Invoke-ClauditAudit.ps1 -Service VPS -Format All
```

Capture normalized assets across any configured provider context:

```powershell
./Invoke-ClauditAudit.ps1 -Service Inventory -Format All
```

Run the Pester compliance suite as part of the audit:

```powershell
./Invoke-ClauditAudit.ps1 -RunPester
```

Detect drift against a previous run, and notify Teams:

```powershell
./Invoke-ClauditAudit.ps1 -CompareWith .\reports\claudit-20260101-080000.json `
    -NotifyWebhook https://contoso.webhook.office.com/webhookb2/...
```

Unattended (scheduled task) with certificate-based app-only auth — no secrets:

```powershell
./Invoke-ClauditAudit.ps1 -AppOnly `
    -TenantId    <tenant-guid> `
    -ClientId    <app-id> `
    -CertificateThumbprint <thumbprint> `
    -Organization contoso.onmicrosoft.com
```

The script exits with code **0** when no high-impact condition exists, **2** for
Critical/High findings (or a requested test failure), and **3** when one or more
execution errors or required skipped checks left the audit incomplete. This
keeps confirmed security risk separate from incomplete coverage in scheduled tasks.

PowerShell Gallery is used only when you explicitly run
`Install-ClauditPrerequisites.ps1 -ConfirmInstall`. Treat Gallery packages as
community content: install the minimum modules you need, review the exact versions
in `config/dependencies.psd1`,
and avoid storing secrets in module configuration.

### Report contract and interoperability

The canonical JSON contract is `schemas/claudit-report-v2.schema.json`. Schema
v2 records producer version/commit, runtime, baseline and dependency-lock
hashes, selected scope, per-service completeness and artifact-manifest name.
`FindingId` is a stable SHA-256 identity over control, scope and resource key;
it is distinct from the per-error `DiagnosticId`. `Compare-ClauditResult` reads
both legacy v1 and v2 reports and compares by stable finding identity.

The OCSF projection uses Compliance Finding/Create for SOC/GRC ingestion. The OSCAL
projection follows Assessment Results 1.2.1 and references Claudit's local
assessment-plan URN; certification workflows must bind that URN to an
organization-owned OSCAL assessment plan and SSP. External CISA/CIS/provider
mappings remain indicative: the catalog explicitly reports that it is not a
complete external-framework coverage claim.

### Using the module directly

```powershell
Import-Module ./Claudit.psd1
Connect-Claudit
$services = Get-CaDefaultServices
$findings = Get-CaAllFindings -Service $services
$findings | Where-Object Status -eq 'Fail' | Format-Table Service,CheckId,Severity,Title,ControlIds
$findings | New-CaReport -OutputDirectory ./reports -Format All `
    -ExpectedService $services -ExpectedControlLevel Passive
Disconnect-Claudit
```

Pass the expected service set and cumulative control level when using
`New-CaReport` directly for assurance. This turns a collector that silently
omits a catalogued control into a blocking `MissingControlResult` instead of a
partial green report. The top-level audit launchers supply these values
automatically.

## The baseline

`config/baseline.json` holds the expected state (thresholds and toggles). Edit it
to match your own policy, or point at a copy:

```powershell
./Invoke-ClauditAudit.ps1 -BaselinePath C:\policy\my-baseline.json
```

## Checks

| ID         | Service     | Check | Controls (indicative) |
|------------|-------------|-------|-----------------------|
| ENTRA-001  | Entra       | Security Defaults or Conditional Access enforced | CISA MS.AAD.3.1 |
| ENTRA-002  | Entra       | Global Administrator count within limit | CISA MS.AAD.7.1 |
| ENTRA-003  | Entra       | Legacy authentication blocked by CA | CISA MS.AAD.1.1 |
| ENTRA-004  | Entra       | Standard users cannot register applications | CIS 5.1.2.2 |
| ENTRA-005  | Entra       | Guest invitation policy restricted | CISA MS.AAD.8.1 |
| ENTRA-006  | Entra       | User consent to applications restricted | CISA MS.AAD.5.1 |
| ENTRA-007  | Entra       | No expired/expiring service-principal credentials | CISA MS.AAD.6.1 |
| ENTRA-008  | Entra       | Guest account inventory (informational) | CISA MS.AAD.8.3 |
| ENTRA-010  | Entra       | Authenticator number matching enforced (EIDSCA) | CISA MS.AAD.3.2 |
| ENTRA-011  | Entra       | Authenticator app/location context (EIDSCA) | CISA MS.AAD.3.2 |
| ENTRA-012  | Entra       | Authentication methods policy migration complete | CISA MS.AAD.3.3 |
| ENTRA-013  | Entra       | Admin consent request workflow enabled | CISA MS.AAD.5.4 |
| ENTRA-014  | Entra       | Legacy AAD/MSOnline PowerShell access blocked | CIS 5.1.2.3 |
| EXO-001    | Exchange    | Modern authentication enabled | CIS 6.5.1 |
| EXO-002    | Exchange    | Organization-wide mailbox auditing enabled | CISA MS.EXO.5.1 |
| EXO-003    | Exchange    | External auto-forwarding blocked | CISA MS.EXO.1.1 |
| EXO-004    | Exchange    | No transport rules redirect mail externally | CISA MS.EXO.1.1 |
| EXO-005    | Exchange    | DKIM signing enabled on all domains | CISA MS.EXO.4.2 |
| EXO-006    | Exchange    | SMTP AUTH disabled tenant-wide | CIS 6.5.2 |
| EXO-007    | Exchange    | POP3/IMAP4 disabled on mailboxes | CIS 6.5.1 |
| EXO-008    | Exchange    | Default remote domain disallows auto-forward | CISA MS.EXO.1.1 |
| EXO-009    | Exchange    | Anti-phishing policy present and enabled | CISA MS.EXO.7.1 |
| EXO-010    | Exchange    | SPF published with hard/soft fail (DNS) | CISA MS.EXO.4.1 |
| EXO-011    | Exchange    | DMARC enforced p=quarantine/reject (DNS) | CISA MS.EXO.4.3 |
| SPO-001    | SharePoint  | External sharing capability within baseline | CISA MS.SHAREPOINT.1.1 |
| SPO-002    | SharePoint  | Legacy auth protocols disabled | CISA MS.SHAREPOINT.3.1 |
| SPO-003    | SharePoint  | Guests must sign in with invited identity | CISA MS.SHAREPOINT.1.3 |
| SPO-004    | SharePoint  | External sharing domain restriction posture | CISA MS.SHAREPOINT.1.2 |
| OD-001     | OneDrive    | Sync restricted to managed devices | CIS 7.2.2 |
| OD-002     | OneDrive    | Sync of high-risk file extensions blocked | CIS 7.2.1 |
| OD-003     | OneDrive    | Deleted-user OneDrive retention meets minimum | CIS 1.3.3 |
| AZURE-001  | Azure       | Azure CLI context resolved | Azure Inventory |
| AZURE-002  | Azure       | Service principals do not hold high-risk Azure roles | CIS Azure / privilege escalation |
| AZURE-003  | Azure       | Application permissions avoid high-risk Microsoft Graph roles | CISA MS.AAD |
| AZURE-004  | Azure       | Storage accounts avoid public data exposure | CIS Azure |
| AZURE-005  | Azure       | Key Vaults have purge protection and controlled network exposure | CIS Azure |
| AZURE-006  | Azure       | Azure public IP exposure inventory captured | Azure Public Exposure |
| AWS-001    | AWS         | Caller identity resolved | AWS Inventory |
| AWS-002    | AWS         | Root account MFA enabled | CIS AWS 1.5 |
| AWS-003    | AWS         | IAM account password policy meets baseline | CIS AWS 1.8 |
| AWS-004    | AWS         | CloudTrail multi-region logging enabled | CIS AWS 3.1 |
| AWS-005    | AWS         | GuardDuty detectors enabled in audit regions | AWS FSBP GuardDuty |
| AWS-006    | AWS         | Security Hub enabled in audit regions | AWS FSBP SecurityHub |
| AWS-007    | AWS         | S3 account-level public access block enabled | CIS AWS 2.1.5 |
| AWS-008    | AWS         | No active IAM access keys older than baseline | CIS AWS 1.14 |
| AWS-009    | AWS         | EBS encryption by default enabled in audit regions | AWS FSBP EC2 |
| AWS-010    | AWS         | AWS Config recorders active in audit regions | CIS AWS 3.5 |
| AWS-011    | AWS         | VPC flow logs enabled for all VPCs in audit regions | CIS AWS 3.9 |
| GCP-001    | GCP         | GCP CLI context resolved | GCP Inventory |
| GCP-002    | GCP         | Primitive IAM roles restricted | CIS GCP 1.3 |
| GCP-003    | GCP         | No stale user-managed service account keys | CIS GCP 1.6 |
| GCP-004    | GCP         | Data Access audit logs configured | CIS GCP 2.1 |
| GCP-005    | GCP         | No public Cloud Storage buckets | CIS GCP 5.1 |
| GCP-006    | GCP         | Uniform bucket-level access enabled | GCP Storage |
| GCP-007    | GCP         | Default VPC network absent | CIS GCP 3.1 |
| GCP-008    | GCP         | No firewall rules expose admin ports to the internet | CIS GCP 3.6/3.7 |
| GCP-009    | GCP         | OS Login enabled at project level | CIS GCP 4.4 |
| GCP-010    | GCP         | Project logging sink configured | GCP Logging |
| TAILSCALE-001 | Tailscale | Tailscale API context resolved | Tailscale Inventory |
| TAILSCALE-002 | Tailscale | Tailnet has no stale devices beyond baseline | SOC2 CC6.2 |
| TAILSCALE-003 | Tailscale | Tailscale auth keys are constrained | SOC2 CC6.1 |
| TAILSCALE-004 | Tailscale | Tailscale ACL policy avoids allow-all rules | SOC2 CC6.6 |
| DOMAIN-001 | Domain | Authorized domain scope declared | Engagement Scope |
| DOMAIN-002 | Domain | Authoritative name servers present | DNS Delegation |
| DOMAIN-003 | Domain | MX records present | DNS MX |
| DOMAIN-004 | Domain | SPF present and terminates with fail policy | CISA MS.EXO.4.1 |
| DOMAIN-005 | Domain | DMARC enforced | CISA MS.EXO.4.3 |
| DOMAIN-006 | Domain | CAA records restrict certificate issuance | DNS CAA |
| DOMAIN-007 | Domain | Common subdomains have no dangling CNAMEs | Cloud takeover |
| DOMAIN-009 | Domain | DNS zone returns a healthy RCODE | DNS availability |
| DOMAIN-010 | Domain | SOA is present and timers are structurally sane | RFC 1035 / RFC 1912 |
| DOMAIN-011 | Domain | DNSSEC validation is not bogus and follows policy | RFC 4033-4035 |
| DOMAIN-012 | Domain | SPF avoids +all, ptr and excessive direct lookups | RFC 7208 |
| DOMAIN-013 | Domain | DMARC is singular and syntactically valid | DMARC / CISA MS.EXO.4.3 |
| DOMAIN-014 | Domain | Common/configured DKIM selectors expose a non-revoked key | RFC 6376 |
| DOMAIN-015 | Domain | MTA-STS and TLS-RPT discovery records are present | RFC 8461 / RFC 8460 |
| DOMAIN-016 | Domain | Optional dnsx bulk resolution has no high-signal DNS issue | DNS availability / takeover |
| VPS-001    | VPS | Linux VPS host context resolved | NIST CSF ID.AM |
| VPS-002    | VPS | SSH root and password authentication hardened | CIS Linux / SSH |
| VPS-003    | VPS | No unexpected services listen on public interfaces | CIS Linux / Network Services |
| VPS-004    | VPS | Host firewall appears active | CIS Linux / Firewall |
| VPS-005    | VPS | Pending package updates within baseline | Patch Management |
| VPS-006    | VPS | Authentication logs are available for investigation | Logging / Detection |
| INV-001    | Inventory   | Multi-cloud asset inventory captured | NIST CSF ID.AM |

> Control IDs are an **indicative** cross-reference to CISA SCuBA / CIS M365.
> Numbering changes between baseline versions — verify against the version you
> are certifying against.

## Layout

```
claudit.ps1 / claudit.sh          unified operator front-controller
Claudit.psd1 / Claudit.psm1     module manifest + glob loader
Invoke-ClauditAudit.ps1         master runner (interactive or scheduled)
Start-ClauditDashboard.ps1      local web cockpit for operations/history
install-ubuntu.sh               Ubuntu systemd installer
service/                        systemd unit, service runner and default config
config/baseline.json            editable secure baseline
config/dependencies.psd1        exact PowerShell module lock
config/control-catalog.json     versioned mappings, applicability and known gaps
schemas/claudit-report-v2.schema.json  canonical JSON report schema
src/Core/Findings.ps1           finding model (+ control auto-tagging)
src/Core/Catalog.ps1            service registry + provider runtime options
src/Core/Controls.ps1           Versioned control-catalog loader/validator
src/Core/ExternalCli.ps1        AWS/GCP CLI execution helpers
src/Core/Connection.ps1         read-only Graph + EXO connect (national clouds)
src/Core/Graph.ps1              Invoke-CaGraphRequest (paging helper)
src/Core/Dns.ps1                cross-platform DNS-over-HTTPS lookup
src/Core/Dnsx.ps1               optional bounded argv-only dnsx adapter
src/Core/Baseline.ps1           baseline loader
src/Core/Report.ps1             core report rendering and artifact orchestration
src/Core/Provenance.ps1         run scope, hashes and completeness ledger
src/Core/Interchange.ps1        OCSF 1.8 / OSCAL 1.2.1 projections
src/Core/Compare.ps1            v1/v2 stable-identity drift detection
src/Core/Notify.ps1             Teams / Slack webhook notification
src/Checks/Entra*.ps1           Entra ID checks (incl. EIDSCA)
src/Checks/Exchange*.ps1        Exchange checks (incl. SPF/DMARC)
src/Checks/SharePoint.ps1       SharePoint tenant checks
src/Checks/OneDrive.ps1         OneDrive tenant checks
src/Checks/Azure.ps1            Azure CLI read-only checks
src/Checks/AWS.ps1              AWS CLI read-only checks
src/Checks/GCP.ps1              gcloud read-only checks
src/Checks/Tailscale.ps1        Tailscale API read-only checks
src/Checks/Domain.ps1           pre-authorized passive DNS/domain checks
src/Checks/VPS.ps1              Linux VPS local/SSH read-only host checks
src/Checks/Inventory.ps1        normalized asset inventory
tests/Report.Tests.ps1          state contract, schema, drift and interchange
tests/Provider.Tests.ps1        provider denial/pagination/policy regressions
tests/Domain.Tests.ps1          offline DNS analyzers and resolver consensus
tests/Dashboard.Tests.ps1       cockpit asset, path and argv hardening
```

## Adding a check

Add a `Test-Ca<Service><Name>` function that wraps its body in `Invoke-CaCheck`.
For provider policy checks, keep collection separate from a pure analyzer,
return `New-CaCheckAssessment`, then pipe it to `ConvertTo-CaFinding`. This makes
Pass, Fail, NotApplicable and provider Error states fixture-testable without
credentials. See `docs/CHECK_CONTRACT.md` and the AWS VPC Flow Logs reference
implementation. Advisory checks may still return `New-CaFinding` directly.

Drop the check in any file under `src/Checks/` — the glob loader and prefix
auto-discovery pick it up, no registration needed. Add its control IDs to
`config/control-catalog.json` and assign it in `config/check-metadata.json`;
both catalogs are validated when the module loads.

## Scope of 0.3

Tenant-level controls are covered via Graph and Exchange Online. Deep per-site
SharePoint analysis (per-site anonymous links, broken inheritance) needs
`PnP.PowerShell` and is planned for a later release; the tenant sharing ceiling
checked here already bounds per-site exposure.

The local dashboard binds only to loopback, rejects cross-site state changes,
limits request sizes and redacts displayed logs. It is an operator console, not
a multi-user service: do not expose it through port forwarding or a reverse proxy.

## License

MIT; see `LICENSE`. Inspired by the FOSS PowerShell community and the Maester project. Verify
findings against your own policy before acting on them.
