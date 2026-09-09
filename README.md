# Claudit

Claudit is a Linux-first, read-only Bash tool for auditing authorized cloud
assets, VPS hosts and public DNS. It produces portable JSON, CSV, Markdown and
HTML findings without storing credentials or requiring PowerShell at runtime.

Its assessment contract is deliberately strict: a collector can emit only an
ID from the shipped runtime control catalog, each finding includes a category
and a concrete remediation, and unavailable evidence remains `unknown` or
`error` rather than becoming a successful result. The report exposes coverage
and copies the exact catalog used for the run alongside its artifacts.
`config/baseline-capabilities.json` separately states which baseline settings
are enforced or used only to constrain scope. Every shipped assessment setting
has an executable control; scope-only entries define authorized targets and
cannot count as passing checks.

AWS Passive assessment binds the selected CLI identity to a private run artifact
and evaluates root MFA, the IAM password policy, active IAM user access-key age,
CloudTrail presence/protection, and public security-group ingress against the
baseline. It also requires an active, successfully delivering Flow Log for each
collected VPC. IAM users, security groups, VPCs and Flow Logs are collected with
a ten-page bound; an incomplete sequence remains unassessed.

Azure Passive assessment binds a selected subscription and tenant to a private
run artifact. It evaluates high-risk role assignments against approved principal
object IDs, high-risk Microsoft Graph application-role grants, storage network
default action, Key Vault purge protection, and
enabled Activity Log alerts. Alert coverage must match every category in
`Azure.RequiredActivityLogCategories`, target the selected subscription, and
deliver to a configured action group.
Denied or malformed Azure responses remain unassessed or invalid evidence.

GCP Passive assessment binds the selected project identity to a private run
artifact. It evaluates primitive IAM-role membership, required allServices audit
log types, OS Login metadata and an enabled user-managed logging sink with an
explicit destination. It can bind the project to an expected organization and
also checks enabled user-managed service-account key
age without retaining service-account email or key identity. Destination
retention remains a separate infrastructure review.

The former PowerShell implementation is preserved unchanged in
[`legacy/powershell/`](legacy/powershell/) as migration reference material. It
is not invoked by the Bash runtime.

## Private work sessions

The cockpit now keeps local work sessions with fixed provider/domain scope,
a baseline snapshot, expected control results, desired DNS RRsets, notes and
an evidence-linked question history. No language model or external chat service
is used: descriptive queries select relevant findings and their catalog
remediations. A question never launches a probe.

Run the same cockpit used by systemd against a local writable data directory:

```bash
./claudit.sh dashboard --output-directory "$HOME/.local/share/claudit"
```

The compact cockpit separates decisions from execution: **Overview** correlates
risk, control families, coverage and evidence quality; **Operations** is the
only place that starts work through an adaptive five-step wizard; **Results**
provides a split assessment inspector with filters, evidence, remediation,
retest guidance and exports. Domain, cloud, VPS, specialist and local preflight
objectives expose only the scope and access fields needed for that operation.

Every syntactically valid domain entered in the CLI or cockpit is accepted and
registered as an asset; `Domain.AuthorizedDomains` is deprecated and ignored
when it is present in an older private baseline. The cockpit maintains a compact
`asset-history.json` ledger outside report retention. Repeated passive or active
assessments for the same normalized domain or provider asset are consolidated
into one timeline with coverage, risk score, evidence gaps and control-state
transitions. Deleting an old report removes its evidence files but keeps the
historical aggregate and clearly marks that source as outside current retention.

1. Choose services and provider/domain context in **New operation**.
2. Enter a session title and optional expected DNS records/control results.
3. Save the session, run Formal, then explicitly authorize Passive collection.
4. Ask about a finding ID, DNS, or the next step; save decisions as work notes.
5. Review the DNS change plan, apply approved changes separately, and reassess.
6. Export completed sessions, archive them read-only, then delete only from the archive when retention permits.

Desired DNS records are exact RRsets, compared without order or duplicate
sensitivity. Use resolver text representation (for example `10 mail.example.com.`
for MX and quoted TXT data); an empty value list means expected absence. Records
are confined to the session domain. Read-only JSON exports from Route 53, Azure
DNS, Google Cloud DNS and Cloudflare can populate these RRsets after local scope
validation. Claudit evaluates declared TTL limits, compares desired records
through configured verification resolvers, performs bounded configured-subdomain
discovery, and can use `dnsx` when enabled. The workspace exports a reviewable
BIND-style zone file. Passive DNS uses
only the explicit `Domain.Resolver` HTTPS endpoint from the baseline; it has no
fallback resolver. The shipped baseline names Cloudflare public DoH, so DNS
names leave the host by default. For private zones, provide an authorized custom
baseline with the trusted private DoH endpoint and set `Private` to `true`.
Each DNS evidence line retains that resolver provenance. Do not place secrets in
session notes or DNS baselines: resolver URLs cannot contain credentials, query
parameters or fragments.

New reports retain scope, the baseline, runtime catalog and baseline capability
map. Questions cite the latest retained successful passive/active run in the
session and disclose when a newer attempt lacks evidence. Report
retention/deletion can remove evidence; session history is retained separately,
including previous answers. The workspace bounds history and run references,
paginates report indexes, and can quarantine an unreadable session file.

The dashboard has no initial web login by default, including on an explicitly
configured LAN bind. The per-page request token still protects state-changing
requests. To restore HTTP Basic authentication, set `RequireAuthentication` to
`true` in `/etc/claudit/service.json` and provide
`CLAUDIT_DASHBOARD_PASSWORD` (at least 24 characters) in the protected service
environment; the username is `claudit`. The cockpit permits two simultaneous
runs, each with a 600-second limit.

See [the architecture review and Codex handoff](docs/CODEX_ARCHITECTURE_REPORT.md)
for implemented corrections, evidence and the explicit provider coverage.

## Requirements

Required: Bash 5+, `jq`, `curl`, Python 3, `dig` (`dnsutils`) and OpenSSH
client. Claudit installation also requires the official provider clients:
`aws` (AWS CLI v2), `az` (Azure CLI), and `gcloud` (Google Cloud CLI). This
keeps every control surface available from the installed cockpit; configure
only the identities and scopes you are authorized to use. The local dashboard
uses the Python 3 standard-library HTTP server.

```bash
sudo apt install jq curl python3 dnsutils openssh-client
./claudit.sh doctor
./tests/run.sh
```

## Safe operation model

Provider and host operations require the appropriate operator access. A domain
entered by the operator is accepted automatically as an assessment asset and
does not require an allow-list or a second passive-collection confirmation.
No commands mutate remote state.

- `formal` validates local prerequisites and declared scope.
- `passive` performs authenticated, read-only provider/API queries only after
  `--confirm-tenant-connection`.
- `active` additionally permits bounded network probes only after
  `--confirm-active-probes`.

An unavailable API, insufficient scope, or missing CLI produces `unknown`; it
does not become a passing result.

For business domains, Formal validates declared scope without network access.
Passive adds bounded public DNS evaluation (authoritative DNS, SPF, DMARC,
DNSSEC policy, MTA-STS, TLS-RPT and configured DKIM selectors). Active performs
one HTTPS HEAD/TLS handshake only to the declared root domain.

## Examples

```bash
# Offline/preflight checks
./claudit.sh doctor

# Authorized public DNS audit
./claudit.sh formal --service Domain --domain example.com

# Read-only multi-cloud checks
./claudit.sh passive --service AWS,Azure,GCP \
  --confirm-tenant-connection --aws-profile audit \
  --azure-subscription <subscription-id> --gcp-project <project-id>

# Microsoft 365 through Microsoft Graph. Supply the token through the environment.
export CLAUDIT_GRAPH_TOKEN="$(az account get-access-token --resource-type ms-graph --query accessToken -o tsv)"
./claudit.sh passive --service M365 --confirm-tenant-connection

# Explicitly authorized active SSH-port probe plus read-only SSH verification
./claudit.sh active --service VPS --vps-target audit.example.com \
  --confirm-active-probes --confirm-tenant-connection

# Compare two Bash reports without contacting a provider
./claudit.sh compare --reference reports/known-good/claudit-report.json \
  --difference reports/latest/claudit-report.json
```

Reports are written below `reports/<UTC timestamp>/` by default. The canonical
artifact is `claudit-report.json` using `claudit/bash-report-v2`; its findings
have stable fields for identifier, service, status, severity, title, detail,
control level and observation time. Each run additionally produces OCSF 1.8
JSON Lines and an OSCAL 1.2.3 assessment-results projection. The OCSF events
and OSCAL document pass their official upstream structural validators, but the
Claudit JSON report remains the authoritative evidence artifact. `unknown`,
`error` and `not_applicable` results remain OSCAL observations and are not
turned into objective determinations. `compare` creates a
drift artifact that labels findings as New, Removed, EvidenceChanged,
Regressed, Fixed or Unchanged.

For a deliberately configured Slack or Teams incoming webhook, pass an HTTPS
URL at runtime: `--webhook-url "$CLAUDIT_WEBHOOK_URL" --webhook-type slack`.
The URL is never written to a report or configuration file.

## Microsoft 365 scope

The Bash implementation uses Microsoft Graph REST with a token supplied by
`CLAUDIT_GRAPH_TOKEN`, or an existing Azure CLI session. It currently verifies
organization access, Entra authorization/Conditional Access, SharePoint tenant
settings and OneDrive API access. Entra checks cover Security Defaults,
administrator MFA, legacy-auth blocking, Global Administrator count,
guest invitations, application registration and user consent. Exchange controls use the isolated
`backends/exchange.ps1` adapter because Exchange Online exposes those controls
through its supported PowerShell module. It runs only for `Exchange`/`M365`,
only after connection confirmation, and returns normalized JSON Lines to Bash.

## Layout

```text
claudit.sh              Bash command entry point
lib/                    CLI, findings, reports and local dashboard
checks/                 DNS, VPS, provider, Microsoft 365 and inventory checks
config/                 Baseline and control metadata
service/                Hardened systemd launcher and configuration
tests/run.sh            Fast, offline Bash regression checks
legacy/powershell/      Preserved pre-migration implementation and Pester tests
```

## Installation

On Ubuntu with systemd, install prerequisites then run:

```bash
sudo bash ./install-ubuntu.sh
sudo systemctl status claudit --no-pager
```

Validate the installation procedure without changing the host:

```bash
./install-ubuntu.sh --dry-run
```

The service binds the report dashboard to loopback by default and uses
`/var/lib/claudit` for mutable data. It can be explicitly configured for
`0.0.0.0` when network access is required; place it behind an appropriate
firewall or reverse proxy. Review `service/service.json` and
`/etc/claudit/claudit.env` before enabling it in a production environment.

## Development

```bash
bash -n claudit.sh lib/*.sh checks/*.sh
./tests/run.sh
```

Keep check functions small, collect only what the finding needs, and never log
tokens, credentials, raw API authorization headers or private keys.

See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for the deployment acceptance
and rollback procedure.

## Control and fixture development

Add every new runtime check to
[`config/runtime-control-catalog.json`](config/runtime-control-catalog.json)
before writing its collector. The catalog is the reviewable contract for level,
service, category and remediation. Add a deterministic fixture for secure,
insecure and unavailable collection paths; `tests/fixtures/domain/` demonstrates
the DNS fixture format. Do not add broad discovery, crawling, brute force or
remediation actions: active checks must remain bounded to explicitly declared
targets.
