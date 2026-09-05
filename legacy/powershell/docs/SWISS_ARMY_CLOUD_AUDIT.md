# Claudit swiss-army cloud audit notes

## Intent

Claudit remains a read-only operator tool: enumerate, evaluate, report, compare
drift. It does not brute force credentials, validate stolen secrets, bypass
logging, or remediate automatically.

## Assimilated patterns

- MFASweep: check MFA and Conditional Access gaps as configuration/evidence,
  not as repeated password login attempts.
- Azure AppHunter: prioritize excessive service-principal privilege and
  high-risk application permissions.
- Aurelian: keep one multi-cloud command surface and normalize evidence across
  providers.
- Cloudlist: produce asset inventory that can feed ASM and SOC workflows.
- Tailsnitch: cover tailnet ACLs, auth keys and stale devices.
- AuditKit: map findings to controls and emit audit-ready evidence.
- Thand: treat standing privilege as risk; recommend JIT/PIM and short-lived
  access for privileged paths.
- PowerShell Gallery: use it only for optional, explicit module acquisition;
  community packages are untrusted until reviewed by the operator.

## Boundaries

Claudit intentionally excludes:

- Password-based MFA sweep and ROPC probing.
- Secret validation against live third-party APIs.
- OPSEC/evasion behavior.
- Automatic remediation/fix mode.
- Stored API tokens, cloud keys or webhook secrets.

## Control levels

- `Formal`: offline policy/schema validation, prerequisites, declared scope and
  authentication plan. It cannot open a tenant or target connection.
- `Passive`: the normal read-only audit through provider APIs, public DNS and
  operator-approved SSH commands.
- `Active`: the passive audit plus a single TLS handshake for each explicitly
  authorized root domain and TCP connect checks for explicitly listed VPS
  ports. It has a separate confirmation gate, a 32-domain/16-port ceiling and
  a bounded per-probe timeout.

Active mode deliberately does not derive targets from inventory or public IP
lists. Enumeration and validation stay separate so scope cannot expand silently.

These are deliberate product boundaries. The tool should be safe to run from an
admin workstation as an auditor with read-only permissions and predictable
report output.

## New service coverage

- `Azure`: RBAC privilege review, Graph app permissions, storage exposure, Key
  Vault protection, public IP inventory.
- `Tailscale`: device lifecycle, auth-key hygiene, permissive ACL/grant rules.
- `Inventory`: normalized assets from AWS, Azure, GCP and Tailscale contexts.

All new services are wired through the existing catalog, wizard, preflight,
baseline and report model.
