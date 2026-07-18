# Changelog

## 0.2.0 - 2026-07-18

- Add a hardened Ubuntu systemd orchestrator with persistent `/var/lib/claudit` storage.
- Add Web UI retention selection with atomic state persistence and safe completed-run pruning.
- Add cumulative Formal, Passive and explicitly authorized Active control levels.
- Add bounded TLS validation for authorized domains and TCP reachability checks for declared VPS ports.
- Surface control level in JSON, CSV, Markdown, HTML and the loopback cockpit.
- Require a separate Active-probe confirmation gate; never expand targets or port ranges implicitly.
- Add a cached Cloudflare/Google DoH resolver that preserves RCODE, AD, backend and typed answers.
- Add formal DNS checks for SOA, DNSSEC, SPF mechanisms, DMARC syntax, DKIM selectors and MTA-STS/TLS-RPT.
- Add an opt-in `dnsx` adapter with argv-only execution, hard timeout, output cap and deterministic cleanup.
- Make Formal Domain audits runnable from the guarded CLI and loopback cockpit without connecting to the asset.
- Add portable cloud-provider icons, logo and favicon served from a traversal-safe local asset route.
- Add offline Pester vectors for DNS analyzers, DoH parsing, baseline policy and control mapping.

## 0.1.0 - 2026-07-11

First stable private-operator release.

- Validate the complete security baseline before any audit and isolate cache entries by policy path.
- Harden the loopback dashboard with bounded byte-accurate HTTP parsing, host checks, anti-CSRF tokens, security headers and redacted logs.
- Generate unique report names and publish each artifact through an atomic same-directory move.
- Store wizard profiles in the private user configuration directory, with atomic writes and legacy-profile compatibility.
- Propagate Pester failures through deterministic command exit codes.
- Preserve the dependency-light, read-only provider model and the existing multi-format finding contract.

Compatibility: PowerShell 7.2+; report JSON remains compatible with `Compare-ClauditResult`.
