# CODEX technical review — Claudit

## Remediation closure — release 0.3.0

**Closure timestamp:** 2026-07-25T08:10:33+02:00 (Europe/Rome)
**Repository state:** `main` at `03311fe4b7cc`, with an intentionally uncommitted remediation worktree.
**Decision applied:** option A — report schema v2, evidence provenance, stable privacy-preserving finding identity, versioned control catalog, OCSF/OSCAL interchange, and schema-v1 drift compatibility.

This section is the current disposition. The original 2026-07-19 review is retained below as a historical baseline; its present-tense defect statements are superseded by the closure evidence here.

### Current executive summary

Claudit 0.3.0 now fails closed when a required evaluation is skipped, denied, unavailable or malformed. `NotApplicable` is explicit and excluded from the coverage denominator only after positive applicability evidence. Incomplete/error runs use exit code `3`, and notifications cannot render a green success message when coverage is incomplete. Confirmed AWS, GCP, Entra, Azure Graph, DNSSEC, SSH, inventory, dashboard argv and OAuth cleanup defects have deterministic regression coverage.

The reporting boundary is now auditable: schema v2 carries producer/runtime/dependency/baseline provenance, per-service completeness, stable hashed resource identities and evidence hashes. A schema-v1 compatibility normalizer preserves drift comparison, including evidence changes under an unchanged aggregate status. Legacy skipped-only history is also reclassified as incomplete in the upgraded dashboard rather than retaining the former false-green label. `Format All` emits canonical JSON, HTML, Markdown, CSV, OCSF 1.8 JSONL, OSCAL 1.2.1 Assessment Results, the versioned control catalog and a SHA-256 artifact manifest.

The pre-0.3 Ubuntu upgrade path is now data-preserving. Before managed source replacement, the installer backs up the legacy baseline/profile, merges operator policy over current defaults, validates the merged baseline, rejects symlinked persistent paths, and imports regular legacy report files into an immutable compatibility tree without overwriting persistent history. Malformed legacy policy stops the upgrade before cleanup; the raw backup remains recoverable.

The tool remains a transparent verification layer, not a sole attestation of compliance. Live provider behavior, tenant-specific permissions and framework interpretation still require credential-gated validation and human governance; these are declared limits rather than green results.

### Finding closure matrix

| Finding | Status | Implemented evidence |
|---|---|---|
| CA-R01 incomplete evaluation/green notification | **Closed** | Blocking `Skipped`/`Error`, explicit `NotApplicable`, exit `3`, truthful notification regression tests. |
| CA-R02 provider read failures become secure | **Closed** | Typed CLI failure/malformed states; AWS/GCP/inventory paths preserve collection failure and completeness. |
| CA-R03 Entra CA proves only existence | **Closed for implemented scope** | All-users/all-apps enabled MFA policy, exclusions and admin/legacy-auth scope are evaluated; misleading presence-only pass removed. Full Graph What-If remains an opt-in strategic feature. |
| CA-R04 GCP default sinks pass central logging | **Closed** | `_Default`/`_Required` excluded; only usable user-defined export sinks satisfy the check. |
| CA-R05 GCP ingress ranges missed | **Closed** | Interval-aware SSH/RDP matching, with deterministic range fixture. |
| CA-R06 SSH target parsed as options | **Closed** | Strict target validation and explicit `--` boundary; adversarial and valid-target fixtures. |
| CA-R07 DNSSEC first-response ambiguity | **Closed** | Two-resolver consensus; `SERVFAIL`/disagreement is indeterminate, never cryptographic `Bogus`. |
| CA-R08 GuardDuty detector state ignored | **Closed** | `get-detector` status is required; detector ID presence alone cannot pass. |
| CA-R09 Graph pagination/partial omission | **Closed for correctness** | `@odata.nextLink` pagination and partial-error propagation; provider pagination fixture. N+1 optimization remains bounded performance debt. |
| CA-R10 supply-chain/reproducibility | **Mitigated to release gate** | Exact module lock, loaded-version provenance, dependency/baseline hashes, SHA-256 artifact manifest, exact-set Ubuntu upgrade and MIT `LICENSE`. Signed release provenance/SBOM remain release-engineering enhancements. |
| CA-R11 missing critical regressions | **Closed** | Suite expanded from 16 to 59 tests across result semantics, providers, identity/drift, schema, exports, governed exceptions/metadata, dashboard argv, OAuth hygiene and upgrades. |
| CA-R12 legacy upgrade can replace operator data | **Closed** | Pre-cleanup baseline/profile backup, recursive default merge, semantic validation, symlink refusal, non-overwriting report migration and schema-v1 dashboard normalization; dedicated offline upgrade regressions. |

### Current build and verification status

| Command/check | Result |
|---|---|
| PowerShell AST parse of all `.ps1`, `.psm1`, `.psd1` | **PASS** — 57 files, 0 parse errors. |
| `Invoke-Pester -Path .\\tests` with Pester 5.8.0 | **PASS** — 59 discovered, 59 passed, 0 failed/skipped; 14.12 s. |
| `Test-ModuleManifest .\\Claudit.psd1` | **PASS** — Claudit `0.3.0`. |
| Catalog, metadata and baseline import | **PASS** — control catalog `2026.07.0`, 88 unique controls, 8 metadata profiles, shipped baseline valid; full external-framework coverage explicitly `false`. |
| JSON v2 schema validation and OCSF/OSCAL projection tests | **PASS** — canonical report validates; exported object counts and pinned schema versions verified. |
| `wsl.exe --exec bash -n ...` | **PASS** — `install-ubuntu.sh` and `claudit.sh`. |
| `git diff --check` | **PASS** — no whitespace errors. |
| Focused secret-pattern scan excluding `.git` and this report | **PASS** — no matches. |
| `claudit.ps1 doctor` | **EXPECTED BLOCK** — 22 pass, 14 warning, 4 blocking failures; absent AWS/Azure/GCP CLIs and authorized Domain scope, exit `2`. |

No live cloud, tenant, DNS target, SSH host or notification endpoint was contacted. No dependency was installed, no external data/service was changed, and no commit or push was performed.

### Remaining limits and ordered next actions

1. **Credential-gated release acceptance:** execute the documented read-only matrix on disposable AWS/Azure/GCP/Entra scopes, including denied permissions, pagination, zero-resource scope and throttling. Store only redacted fixtures. This is an environment acceptance gate, not an unresolved offline code gap.
2. **Release integrity:** publish the `.sha256` manifest with the release archive; optionally add an SPDX/CycloneDX SBOM and signed build provenance when a reproducible distribution channel exists.
3. **Authoritative expansion, by explicit product decision:** native Security Hub/Defender for Cloud/SCC ingestion and organization traversal are not silently inferred from option A. Add them only with scope plans, allowlists, request budgets and fixture-scale tests.
4. **Maintainability:** split oversized dashboard/wizard/domain modules only along stable responsibility seams and only with unchanged behavior under tests. This is bounded P3 debt, not a release-integrity blocker.
5. **Compliance truthfulness:** external framework catalogs are referenced with revision/assurance metadata, but `FullFrameworkCoverage=false` is deliberate. Licensed/manual requirements must remain visible as gaps rather than being fabricated as automated coverage.

**Current disposition:** offline release gate passed for Claudit 0.3.0 as a stable, read-only, operator-supervised technical verification release. All reproduced false-green and legacy-upgrade data-preservation blockers are closed. Production assurance still requires the credential-gated acceptance matrix above and cannot be delegated solely to this tool.

## Historical baseline — 2026-07-19 (superseded)

**Review timestamp:** 2026-07-19T20:09:11+02:00 (Europe/Rome)
**Repository state reviewed:** `main` at `03311fe4b7cc`; no tracked changes. The only pre-existing worktree item was the untracked report from the earlier automation pass, overwritten by this authorized review.
**Scope:** tracked Claudit source, tests, documentation, installers and local runtime. Ignored operator artifacts (`cti-workbench/`, generated reports and the wizard profile) were excluded from product assessment.
**Method:** static review, current official-source comparison, existing tests, offline preflight, high-signal secret scan and isolated in-memory mocks. No credentials, live cloud/tenant calls, offensive traffic, external mutations, dependency installation, dashboard launch or application-code changes. Test/preflight temporary files were self-cleaned; the only retained repository write is this report.

## Executive summary

Claudit is a compact, dependency-light PowerShell 7 audit tool that performs read-only checks across Microsoft 365/Entra, Azure, AWS, GCP, Tailscale, VPS/SSH and DNS, then emits JSON/CSV/Markdown/HTML plus a loopback dashboard. Its strongest engineering is at the output boundary: centralized redaction, HTML encoding, CSV formula neutralization, atomic file writes, conservative dashboard request handling and a hardened systemd unit. The provider split and explicit control mapping are also good foundations for a solo-maintained FOSS tool.

The current release should nevertheless be treated as **alpha/private preview, not decision-grade assurance**. The main problem is not missing breadth but incorrect certainty: several collector failures and incomplete evaluations become `Pass`, while a run containing only `Skipped` findings reports overall `Pass` and exit code `0`. Nine deterministic observations reproduced false-green/ambiguous behavior across summary, notification, Conditional Access, AWS VPC Flow Logs, GuardDuty, GCP firewall ranges and logging sinks, DNSSEC resolver handling and SSH target parsing. A green report can therefore mean “secure”, “not evaluated”, “provider read failed” or merely “a control object exists”. This is a P1 integrity defect for an audit product.

No P0 was found. The existing 16 tests pass, the manifest is valid and all tracked PowerShell files parse, but tests cover mainly presentation and DNS parsing rather than provider semantics, orchestration, error contracts, authentication or SSH. `doctor` correctly blocks the present machine because AWS/Azure/GCP CLIs and a domain scope are absent.

The highest-value next move is a narrow correctness release: make evaluation state fail closed, preserve provider errors, fix the six confirmed false-green paths, and turn every repro in this report into a fixture-based test. Only then expand controls. A versioned control catalog, stable resource fingerprints and evidence provenance would subsequently make framework coverage and drift defensible without turning the project into a heavy platform.

### Facts, hypotheses and limits

- **Facts:** findings below marked “confirmed” were reproduced locally with deterministic mocks or direct offline commands; code locations and official API semantics were inspected. There are 87 unique implemented check IDs and each is mapped by `Get-CaControlIds` to at least one framework identifier. No high-confidence secret literal was found in tracked files.
- **Hypotheses:** live-provider impact and prevalence are inferred from code paths and documented API behavior; they were not measured against production tenants. Multi-account scale and throttling concerns are architectural risks, not benchmark results.
- **Limits:** no cloud credentials or authorized domain were supplied; therefore no live Microsoft Graph, Exchange, Azure, AWS, GCP, Tailscale, SSH-host or target-domain assessment was run. The web dashboard and temporary-browser OAuth flow were not launched. PSScriptAnalyzer was not installed locally. Ignored operator/reference artifacts are not part of this audit. Live-provider prevalence and permission behavior remain unmeasured.

## Product function and stack map

| Layer | Implementation | Review finding |
|---|---|---|
| Entry points | `claudit.ps1`, `claudit.psd1`, `claudit.psm1` | Clear PowerShell-native packaging; manifest version `0.2.0`, minimum PowerShell `7.2`. |
| Orchestration | `Invoke-ClauditAudit.ps1`, `Start-ClauditSafeAudit.ps1`, preflight and baseline validation | Formal/passive/active intent and confirmation gates are visible; result-state contract is too permissive. |
| Collectors | `src/Checks/*.ps1` for M365/Entra, Azure, AWS, GCP, Tailscale, VPS and DNS | Provider isolation is useful, but many checks conflate query success, applicability and secure state. |
| External interfaces | Microsoft Graph/Exchange modules; `az`, `aws`, `gcloud`, `tailscale`, `ssh`, DNS-over-HTTPS/native DNS | Minimal abstraction; CLI JSON is easy to inspect, but command failure handling is inconsistent. |
| Findings and policy | findings, summary, baselines, control mapping | 87 control IDs mapped; mappings are indicative and omit applicability/completeness metadata. `RequireMfaForAdmins` is defined but not enforced. |
| Outputs | JSON, CSV, Markdown, HTML, notifications | Strong output encoding/redaction; schema lacks run/tool provenance and stable resource identity. |
| Local UI | PowerShell TCP dashboard, static assets | Loopback binding, host/origin-style checks, tokenized JSON POST, request/body limits and CSP are solid. Main file is 1,112 lines. |
| Tests | Pester 5; 3 test files | 16/16 pass, but coverage is concentrated in dashboard sinks, DNS parsing and reports. |
| Deployment | `install-ubuntu.sh`, systemd unit and service wrapper | Service sandboxing is strong; module acquisition is unpinned and copy-over upgrades may retain stale files. |

### Dependency and maintenance observations

- Locally available: PowerShell `7.6.3`, Pester `5.8.0`, Microsoft Graph modules `2.38.0`, ExchangeOnlineManagement `3.10.0`, Windows OpenSSH. Missing: `aws`, `az`, `gcloud`, `dnsx`, `sh`, PSScriptAnalyzer.
- The installer requests latest gallery modules with `-Force -AllowClobber`; versions, hashes and provenance are not pinned. Optional gallery trust changes widen supply-chain trust.
- There is no repository `LICENSE` file although README and manifest claim MIT. The manifest `ProjectUri` is a placeholder.
- Version/documentation drift exists: manifest/README are `0.2.0`, report footer and `SECURITY.md` still reference `0.1`, and README names test files that do not exist.
- `src/Core/Dashboard.ps1` (1,112 lines), `Start-ClauditWizard.ps1` (588), and `src/Checks/Domain.ps1` (560) exceed the repository’s own approximate 500-line maintainability threshold.

## Build and test status

| Command/check | Result | Interpretation |
|---|---|---|
| `.\claudit.ps1 test` | **PASS** — Pester 5.8.0; 16 discovered, 16 passed, 0 failed/skipped; Pester time 12.88 s; process exit `0` | Existing regression suite is healthy but narrow. |
| `Test-ModuleManifest .\claudit.psd1` | **PASS** — version `0.2.0`, PowerShell `7.2` minimum | Package metadata parses and imports structurally. |
| PowerShell AST parse of every tracked `.ps1`, `.psm1`, `.psd1` | **PASS** — 0 parse errors | Syntax baseline is clean. |
| `.\claudit.ps1 doctor` | **BLOCKED AS EXPECTED** — 40 checks: 22 Pass, 14 Warning, 4 Fail/Blocking; exit `2` | Offline preflight correctly identified missing `aws`, `az`, `gcloud` and missing Domain scope. No live provider operation ran. |
| Deterministic mocked semantic probes | **FAIL** — 9/9 adverse fixtures reproduced defects CA-R01 through CA-R08 below | Current green-path semantics are not reliable enough for audit assurance. |
| High-signal tracked-secret scan | **PASS** — no AWS access-key, private-key, GitHub/Slack/Tailscale token literal pattern found | Useful hygiene signal only; not a substitute for history/entropy scanning. |

The test command did not alter tracked files. Existing tests do not exercise provider collectors end-to-end, summary exit semantics, notification severity, cloud API pagination, CLI error propagation, SSH target handling, or account/project/region selection.

## Bugs and risks

Severity is impact × realistic exploit/occurrence: **P0** immediate catastrophic failure; **P1** audit-integrity/security blocker; **P2** material but bounded; **P3** maintainability or low-impact correctness. No P0 was identified.

### P1 — release blockers

#### CA-R01 — Incomplete evaluation reports `Pass` and notifications can announce success

**Confirmed.** A result set containing one `Skipped` finding produces `Outcome=Pass`, `Coverage=0`, `NotEvaluated=1`, `RecommendedExitCode=0`. This contradicts the changelog/README claim that unevaluated results use exit `3`. A mocked Slack notification for `Error=1`, `Critical=0`, `High=0` rendered “✅ Claudit: no high-impact findings” and omitted errors, coverage and outcome.

**Repro:** construct `New-CaFinding -Status Skipped`, pipe it to `Get-CaSummary`; separately mock `Invoke-RestMethod` and invoke notification formatting with one execution error. No network is required.

**Impact:** automation and humans cannot distinguish secure from unevaluated or failed collection. This invalidates the product’s top-level assurance contract.

**Fix contract:** any required check in `Error` or unevaluated state must yield `Incomplete`/`Error`, a non-zero dedicated exit code, explicit coverage, and non-green notification wording. `Skipped` should remain non-failing only when applicability is positively established and recorded.

#### CA-R02 — Provider read failures are silently converted to secure results

**Confirmed.** Mocking AWS `describe-vpcs` to return `AccessDenied` makes AWS-011 return `Pass` (“All discovered VPCs have flow logs”). Equivalent continue-on-error patterns exist in GCP service-account keys, bucket IAM/uniform-access checks and inventory collection.

**Repro:** mock the AWS CLI adapter so every VPC read fails; invoke AWS-011. It returns `Pass` with zero evaluated VPCs.

**Impact:** missing permissions, throttling, malformed output or provider outages become false assurance. Inventory omissions also make downstream checks look complete.

**Fix contract:** adapters must return a typed state (`Ok`, `NotApplicable`, `Denied`, `Unavailable`, `Malformed`) plus scope; only `Ok` data may produce `Pass`. Track expected, queried and evaluated resource counts.

#### CA-R03 — Entra Conditional Access checks prove existence, not protection

**Confirmed.** With Security Defaults disabled and one enabled, unrelated narrow Conditional Access policy, ENTRA-001 returns `Pass`. ENTRA-003 similarly accepts the existence of a blocking policy without validating target population, applications, conditions or exclusions. The configured `RequireMfaForAdmins` baseline key is never consumed by a check.

**Impact:** privileged users or legacy authentication can remain unprotected while the audit is green.

**Gap:** Microsoft exposes scope-aware Conditional Access evaluation via the [Microsoft Graph evaluate API](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-evaluate?view=graph-rest-1.0); Maester uses scenario-based [Conditional Access What If tests](https://maester.dev/docs/ca-what-if/). Claudit currently performs only policy-count/name heuristics.

#### CA-R04 — GCP centralized logging check passes on default local sinks

**Confirmed by implementation and official semantics.** GCP-010 passes when sink count is greater than zero. Google creates `_Required` and `_Default` sinks for every resource, so the check does not demonstrate central/exported logging or satisfy `RequireCentralLogSink`. See [Google Cloud log routing](https://docs.cloud.google.com/logging/docs/routing/overview).

**Impact:** a project with no user-defined organization/folder/project export sink can pass a central-log control.

**Fix:** exclude system sinks; verify enabled user-defined destination, inclusion/exclusion filters, writer identity and organization/folder aggregation scope.

#### CA-R05 — GCP broad-ingress detector misses port ranges

**Confirmed.** An ingress rule from `0.0.0.0/0`, protocol TCP, ports `20-30` returns `Pass` because the implementation matches only exact strings `22` and `3389`.

**Impact:** exposed SSH/RDP contained in ranges is missed. Also normalize IPv6 `::/0`, omitted ports meaning all ports, multiple protocols and target scope.

### P2 — material bounded risks

#### CA-R06 — SSH target is parsed as local options

**Confirmed locally without network traffic.** Passing VPS target `-V` executes local `ssh -V`; the wrapper reports success and never runs the remote script. Target input is not constrained and no explicit option terminator/safe argv policy is enforced.

**Impact:** trusted interactive usage mainly causes incorrect evidence; if a wrapper accepts untrusted target strings, crafted SSH options such as proxy commands could cause local command execution. Treat as P1 in any service/multi-user deployment.

**Fix:** parse target into strict host/user/port fields, reject leading `-` and control characters, allow only explicit SSH options, and use argument arrays plus a safe option boundary supported by the local client.

#### CA-R07 — DNSSEC resolution stops after the first protocol response

**Confirmed.** When resolver one returns `SERVFAIL` and resolver two would return secure `NOERROR`, `Resolve-CaDnssecStatus` returns `Bogus` after one call. The second resolver is used only for transport failure. `SERVFAIL` is also stronger than evidence of cryptographic bogusness.

**Impact:** transient resolver faults produce false high-severity DNSSEC findings; resolver diversity documented by the product is not achieved.

**Fix:** query both independent resolvers, distinguish `Bogus`, `Indeterminate`, `Insecure` and transport failure, and record disagreement rather than collapsing all non-`NOERROR` responses.

#### CA-R08 — GuardDuty presence check ignores detector state

**Confirmed by fixture and API contract.** A mocked detector ID with no state produced `Pass`. AWS documents that [ListDetectors returns detector IDs](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_ListDetectors.html); enabled/disabled state and features come from [GetDetector](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_GetDetector.html).

**Impact:** a disabled or materially underconfigured detector can pass.

#### CA-R09 — Graph pagination and N+1 collection can omit privileged app grants

**Static evidence.** Azure/Entra application-permission collection performs per-service-principal requests, does not consistently follow `@odata.nextLink` for app-role assignments, and caps reported errors. Large tenants can be incomplete or throttled while findings remain non-blocking.

**Impact:** dangerous grants after the first page or behind partial query failures may be missed.

#### CA-R10 — Reproducibility and supply-chain integrity are weak

**Confirmed.** Runtime modules are installed as latest available versions, with no lock, hash, signed release verification, SBOM or build provenance. The module declares MIT but ships no license text.

**Impact:** two installations can execute different dependency graphs; compromise or incompatibility is difficult to attribute. [SLSA 1.2](https://slsa.dev/spec/v1.2/) defines current provenance expectations, while [OpenSSF Scorecard](https://scorecard.dev/) provides practical source/dependency/build checks.

#### CA-R11 — Critical behavior lacks regression coverage

**Confirmed.** No tests cover collector error propagation, result/exit semantics, cloud API pagination, authentication boundaries, region/project/account selection, command injection or SSH hardening. The current suite would remain green with CA-R01–CA-R08 present.

### P3 — debt and lower-impact issues

- **Version and documentation drift:** `0.1`/`0.2.0` inconsistencies, stale test inventory and placeholder repository URI reduce report provenance and support clarity.
- **No license artifact:** downstream users cannot reliably consume an otherwise “MIT” repository without the actual license grant.
- **Installer stale-file risk:** copy-over deployment does not establish an exact module file set; removed scripts can survive an upgrade.
- **Oversized modules:** dashboard/wizard/domain files have multiple responsibilities and widen review/test blast radius.
- **Report identity:** JSON lacks tool version/commit, baseline hash, selected scopes, per-provider completeness and stable per-resource finding fingerprints. Drift keyed mainly by `CheckId` can hide changes inside aggregated findings.
- **Output residuals:** local reports contain sensitive infrastructure metadata after redaction; filesystem permissions/encryption and retention remain operator responsibilities. Symlink-target and external-reference URL policies deserve explicit hardening tests.
- **Process argument portability:** the dashboard manually joins and quotes child-process arguments (`\"` replacement only). This is fragile across Windows/Unix parsing and for values ending in backslashes; use a native argument-list API or the same direct argv invocation used by the safe launcher, then add adversarial quoting fixtures.
- **OAuth profile cleanup:** temporary-browser auth calls `CloseMainWindow()` but does not wait for termination before best-effort recursive deletion. A locked profile can survive with session artifacts; verify deletion, wait with a short timeout, and report/secure any residual path.

## Security, privacy, supply chain and operability

### Effective controls already present

- Read-only operational posture, explicit active-mode gating and preflight checks.
- Central secret redaction before report serialization; HTML encoding and CSV formula-injection neutralization.
- Atomic report writes and bounded dashboard requests/body sizes.
- Dashboard bound to loopback with strict host checks, CSP, cross-site request checks, random token for state-changing JSON POSTs, and no obvious `innerHTML` sink.
- Hardened systemd unit: unprivileged account, `NoNewPrivileges`, strict filesystem protection, private temp/devices, restricted address families and empty capability set.
- Human-readable logs and simple deployment model; no unnecessary server/database stack.

### Residual concerns

- Provider authorization failures are an integrity problem, not just an availability warning; they must affect outcome and coverage.
- Cached AWS caller identity is not keyed by profile, creating cross-scope evidence risk in long-lived programmatic sessions.
- Default AWS region is `us-east-1`; Azure and GCP flows are largely single-subscription/project. “Multi-cloud” does not yet mean organization-wide or all-active-region coverage.
- Report retention, directory ACLs, encryption at rest and secure deletion are undocumented. Redaction cannot remove all business-sensitive resource names, topology and posture data.
- The service sandbox is stronger than the dependency acquisition path. Pinning and a release checksum/provenance file offer more value than adding a heavy CI platform.
- Notification output is currently unsafe for SOC triage because it hides execution failure and coverage.

## Gap against current standards and state of the art

| Reference/current practice | What mature implementations provide | Claudit gap |
|---|---|---|
| [NIST OSCAL Assessment Results](https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-results/) | Machine-readable scope, reviewed controls, observations, evidence, findings, risks and continuous-assessment interchange | Flat indicative mappings; no versioned catalog, applicability model, evidence provenance or assessment-result export. |
| [CSA CCM v4.1](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1) and [Continuous Audit Metrics Catalog](https://cloudsecurityalliance.org/artifacts/the-continuous-audit-metrics-catalog-v1-1) | Current 2026 vendor-neutral catalog, shared-responsibility/applicability guidance, machine-readable JSON/YAML/OSCAL and 34 measurable continuous-audit metrics | No metric cadence/freshness, responsibility owner, measurement formula, framework revision or completeness denominator. |
| [NIST CSF 2.0](https://www.nist.gov/cyberframework) | Govern/identify/protect/detect/respond/recover outcomes with profiles and risk context | Current mapping is control-ID decoration, not an auditable profile or outcome coverage statement. |
| [CISA SCuBA](https://www.cisa.gov/news-events/news/scuba-dives-deeper-help-federal-agencies-secure-their-cloud-environments-publishes-security) | Detailed M365 baselines spanning Entra and major Microsoft 365 services | Claudit covers a useful subset but lacks baseline versioning, exceptions and much of Teams/SharePoint/OneDrive/Defender/Power Platform breadth. |
| [Microsoft Graph CA evaluate](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-evaluate?view=graph-rest-1.0) / [Maester What-If](https://maester.dev/docs/ca-what-if/) | Scenario-based Conditional Access applicability/regression testing rather than object-presence checks | Claudit relies on coarse state/existence heuristics; no scenario fixtures or expected-policy regression suite. |
| [Prowler universal compliance model](https://docs.prowler.com/developer-guide/security-compliance-framework) | 85+ catalogs, multi-provider declarative mapping, schema validation and full catalogs where unautomated requirements remain visible with zero checks | Claudit mappings decorate findings but cannot express complete source-catalog coverage, manual requirements or provider-specific applicability. |
| [AWS Security Hub FSBP](https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html), [Defender for Cloud compliance](https://learn.microsoft.com/en-us/azure/defender-for-cloud/assign-regulatory-compliance-standards), [Google SCC posture](https://docs.cloud.google.com/security-command-center/docs/security-posture-overview) | Continuously updated, hierarchy-aware native posture/standards, exemptions and drift | Claudit samples a small account/subscription/project subset and should ingest authoritative native findings with freshness/context rather than clone their breadth. |
| [Microsoft Cloud Security Benchmark v2 preview](https://learn.microsoft.com/en-us/security/benchmark/azure/introduction) | More than 420 Azure Policy mappings plus expanded domains including AI security | Claudit lacks Policy assignment/effect/exemption evaluation and control revision metadata. |
| [OCSF 1.8](https://github.com/ocsf/ocsf-schema/releases/tag/1.8.0) and [OSCAL Assessment Results](https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-results/) | SOC-normalized security findings plus audit-grade scope/evidence/risk interchange | Current aggregated `CheckId` drift is too coarse; no resource identity, schema validation, producer metadata or interoperable envelope. |
| [SLSA 1.2](https://slsa.dev/spec/v1.2/) | Approved source/build tracks and provenance attestations | No pinned dependency set, release checksums, SBOM or provenance; installs are not reproducible. |

The strategic conclusion is not “add hundreds of checks”. Claudit’s niche can be a transparent, portable verification layer: normalize trustworthy evidence, expose incomplete coverage honestly, consume native cloud posture where it is authoritative, and add a small number of cross-cloud checks that native tools do not compose.

## Proposed features, ordered by value

| Feature | Security/operational value | Cost | Main risk and containment |
|---|---|---:|---|
| **Typed evaluation contract and completeness ledger** | Very high: eliminates false green; records expected/queried/evaluated/error counts per provider/control | Medium | Schema change; version JSON as v2 and keep a compatibility reader. |
| **Fixture/replay harness for provider adapters** | Very high: deterministic tests for denial, pagination, malformed JSON, throttling and edge policies without credentials | Medium | Fixtures can drift; record API/CLI version and refresh deliberately. |
| **Versioned control catalog** | High: explicit framework revision, applicability, evidence requirements, implementation status and zero-check gaps | Medium | Mapping maintenance; keep one plain data file and validate it, no DSL. |
| **Resource-scoped finding IDs plus OCSF/OSCAL export** | High: reliable drift/deduplication, SOC ingestion and audit-result interchange | Medium | Sensitive identifiers and schema churn; hash canonical provider/scope/resource keys, pin schema versions and document stability. |
| **Scenario-based Entra Conditional Access verification** | High: proves admin/MFA/legacy-auth outcomes instead of policy existence | Medium | API maturity/permissions; make opt-in, read-only, explicit scenarios with least privilege. |
| **Native posture ingestion** (Security Hub/Defender for Cloud/SCC) | High: organization-grade provider evidence without cloning enormous control catalogs | Medium | Trust/freshness differences; retain source, timestamp, standard version and provider status. |
| **Opt-in organization inventory and active-region discovery** | High for real estates: AWS accounts/regions, Azure management groups/subscriptions, GCP org/folders/projects | High | Cost, throttling and blast radius; bounded concurrency, budgets, allowlists and dry-run scope plan. |
| **Evidence provenance envelope** | Medium-high: tool/commit/module versions, baseline hash, scope, timestamps, completeness and artifact checksums | Low | Report schema growth; keep metadata compact and deterministic. |

Features deliberately deferred: remote multi-user dashboard, database, Kubernetes deployment, autonomous remediation and offensive validation. They expand threat surface and operational burden before evidence correctness is solved.

## Ordered roadmap with verifiable next actions

### R0 — Correctness release gate

1. Define outcomes `Pass`, `Fail`, `Incomplete`, `Error`, `NotApplicable`; prohibit `Pass` when required queries failed or zero applicable resources were actually evaluated.
2. Make a skipped-only run return `Incomplete` and a dedicated non-zero exit code; include errors/coverage/outcome in every notification.
3. Add Pester repros for CA-R01 and CA-R02 across a shared provider adapter contract.
4. **Acceptance:** all existing tests plus new state-table tests pass; a fault-injection matrix proves no denied/unavailable/malformed response can yield `Pass`.

### R1 — Close confirmed false negatives

1. Entra: evaluate policy scope/exclusions and add explicit admin-MFA and legacy-auth scenarios.
2. GCP: parse port intervals/IPv6/all-ports; exclude system logging sinks and validate aggregation destination.
3. AWS: call `GetDetector` and verify enabled state/features; preserve VPC read failures.
4. SSH/DNS: validate target argv; implement two-resolver consensus with indeterminate state.
5. Graph: follow pagination and make partial collection visible.
6. **Acceptance:** one deterministic failing fixture and one secure fixture for each defect CA-R03–CA-R09; no live credentials required.

### R2 — Make evidence auditable

1. Introduce JSON schema v2 with tool/commit/dependency versions, baseline digest, exact provider scopes, per-control completeness and resource fingerprint.
2. Move mappings into one versioned catalog with implemented/unimplemented requirements and applicability.
3. Add OCSF Compliance/Detection Finding export for SOC pipelines; add a minimal OSCAL assessment-results adapter only after schema v2 stabilizes. Keep SARIF optional for code-scanning integrations, not as the primary cloud-posture schema.
4. Pin supported module versions, publish checksums and add `LICENSE`; make upgrades produce an exact file set.
5. **Acceptance:** schema validation and golden-file tests; identical input yields stable fingerprints and deterministic metadata except timestamps/run ID.

### R3 — Expand only through authoritative leverage

1. Add read-only ingestion of native AWS/Azure/GCP posture findings with freshness and source metadata.
2. Add opt-in organization traversal and active-region discovery with a printed scope plan, allowlists, bounded concurrency and request budgets.
3. Expand SCuBA/CCM coverage only where Claudit can collect authoritative evidence; leave every uncovered requirement explicitly visible.
4. **Acceptance:** fixture-scale tests for pagination/throttling/partial permissions plus a documented, credential-gated manual test matrix; never require production mutation.

## Debt and residual risk after the roadmap

- Cloud APIs, default policies and framework revisions will continue to drift; control metadata needs an explicit review date and supported-version window.
- Read-only collection can still expose sensitive tenant topology and consume API quota. Organization mode requires least-privilege documentation, rate limits and operator-approved scope.
- Native posture products have delay, exclusions and licensing gaps; ingestion is evidence, not unquestioned truth.
- A small FOSS maintainer cannot validate every tenant shape. Fixture provenance, public bug templates and transparent “not evaluated” output are more defensible than claiming universal coverage.
- DNSSEC and SSH checks remain environment-sensitive; results should carry resolver/client version and raw bounded evidence.
- Even after code fixes, formal compliance still requires sampling, exception governance, human evidence and shared-responsibility interpretation. Claudit should state this in every compliance export.

## Final disposition

**Current:** technically promising, locally safe by default, but not suitable as a sole compliance or SOC assurance source because confirmed false-green paths compromise result integrity.
**Release gate:** complete R0 and R1 before calling `0.2.x` stable.
**Immediate next action:** implement the typed evaluation contract and convert CA-R01/CA-R02 into regression tests; this single seam prevents the broadest class of silent assurance failures.
