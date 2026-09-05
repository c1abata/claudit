# Bash migration status

Claudit's runtime is Bash-only as of the in-progress 0.4 migration. The
runtime entry point is `./claudit.sh`; it never starts PowerShell.

## Completed runtime foundation

- Explicit Bash CLI, formal/passive/active confirmation gates and preflight.
- Normalized JSON findings plus CSV, Markdown and HTML reports, OCSF 1.8,
  OSCAL 1.2.1 and offline report-to-report drift comparison.
- Public DNS, VPS/SSH, AWS CLI, Azure CLI, Google Cloud CLI, Tailscale API and
  Microsoft Graph adapters.
- Loopback-only local static report dashboard and systemd launcher.
- Fast offline Bash regression test and ShellCheck-clean shell sources.

## Deliberately incomplete parity

The following legacy functionality is preserved but has not yet reached
feature-for-feature Bash parity: deep per-site SharePoint/OneDrive coverage,
rich dashboard operations and portions
of provider-specific baseline policy semantics. Their absence is represented by
`unknown` rather than a pass.

Exchange Online is the deliberate exception to Bash-only collectors:
`backends/exchange.ps1` is an isolated PowerShell 7 adapter for supported
read-only ExchangeOnlineManagement cmdlets. Bash owns authorization gating,
orchestration and reports; the adapter returns JSON Lines only.

Each missing feature must be ported with an official API/CLI, fixture-backed
test and an explicit mapping to its legacy check identifier. Do not re-enable
the legacy runtime merely to hide an unsupported check.
