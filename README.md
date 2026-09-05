# Claudit

Claudit is a Linux-first, read-only Bash tool for auditing authorized cloud
assets, VPS hosts and public DNS. It produces portable JSON, CSV, Markdown and
HTML findings without storing credentials or requiring PowerShell at runtime.

Its assessment contract is deliberately strict: a collector can emit only an
ID from the shipped runtime control catalog, each finding includes a category
and a concrete remediation, and unavailable evidence remains `unknown` or
`error` rather than becoming a successful result. The report exposes coverage
and copies the exact catalog used for the run alongside its artifacts.

The former PowerShell implementation is preserved unchanged in
[`legacy/powershell/`](legacy/powershell/) as migration reference material. It
is not invoked by the Bash runtime.

## Requirements

Required: Bash 5+, `jq`, `curl`. Provider checks use their official clients:
`aws` (AWS CLI v2), `az` (Azure CLI), `gcloud` (Google Cloud CLI), and `ssh`.
The optional local dashboard uses the Python 3 standard-library HTTP server.

```bash
sudo apt install jq curl openssh-client
./claudit.sh doctor
./tests/run.sh
```

## Safe operation model

All operations require authorization for the tenant, account, domain or host.
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

# Microsoft 365 through Microsoft Graph. Do not put the token in a file.
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
JSON Lines and OSCAL 1.2.1 assessment-results projections. `compare` creates a
drift artifact that labels findings as New, Removed, EvidenceChanged,
Regressed, Fixed or Unchanged.

For a deliberately configured Slack or Teams incoming webhook, pass an HTTPS
URL at runtime: `--webhook-url "$CLAUDIT_WEBHOOK_URL" --webhook-type slack`.
The URL is never written to a report or configuration file.

## Microsoft 365 scope

The Bash implementation uses Microsoft Graph REST with a token supplied by
`CLAUDIT_GRAPH_TOKEN`, or an existing Azure CLI session. It currently verifies
organization access, Entra authorization/Conditional Access, SharePoint tenant
settings and OneDrive API access. Exchange controls use the isolated
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

The service is restricted to loopback networking for the report dashboard and
uses `/var/lib/claudit` for mutable data. Review `service/service.json` and
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
