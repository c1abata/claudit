#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf -- "$tmp"' EXIT

bash -n "$root/claudit.sh" "$root/lib/core.sh" "$root/checks/"*.sh
test -x "$root/service/claudit-service.sh"
test ! -x "$root/service/claudit.service"
grep -Fqx 'ExecStart=/opt/claudit/service/claudit-service.sh' "$root/service/claudit.service"
"$root/install-ubuntu.sh" --dry-run >/dev/null
jq '(.Controls[] | select(.Id == "CA-DNS-000")).Service = "WrongService"' "$root/config/runtime-control-catalog.json" > "$tmp/bad-catalog.json"
if CLAUDIT_CONTROL_CATALOG="$tmp/bad-catalog.json" "$root/claudit.sh" formal --service Domain --domain example.com --output-directory "$tmp/bad-catalog" --format json >/dev/null 2>&1; then echo 'catalog service binding failed' >&2; exit 1; fi
"$root/claudit.sh" formal --service Domain --domain invalid_domain --output-directory "$tmp/report" --format json >/dev/null
jq -e '.schema == "claudit/bash-report-v2" and ([.findings[] | select(.id == "CA-DNS-000" and .status == "error")] | length == 1)' "$tmp/report/claudit-report.json" >/dev/null
CLAUDIT_DOH_FIXTURE="$root/tests/fixtures/domain/business-example.json" "$root/claudit.sh" passive --service Domain --domain example.com --output-directory "$tmp/domain" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-DNS-DMARC" and .status == "pass" and (.remediation | length > 0))] | length == 1) and .summary.coverage > 90' "$tmp/domain/claudit-report.json" >/dev/null
jq '(."_dmarc.example.com|TXT".Answer[0].data = "v=DMARC1; p=none") | (."example.com|TXT".Answer += [{"data":"v=spf1 -all"}])' "$root/tests/fixtures/domain/business-example.json" > "$tmp/domain-weak.json"
CLAUDIT_DOH_FIXTURE="$tmp/domain-weak.json" "$root/claudit.sh" passive --service Domain --domain example.com --output-directory "$tmp/domain-weak" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-DNS-DMARC" and .status == "warning")] | length == 1) and ([.findings[] | select(.id == "CA-DNS-SPF" and .status == "fail")] | length == 1)' "$tmp/domain-weak/claudit-report.json" >/dev/null
CLAUDIT_DOH_FIXTURE="$tmp/not-present.json" "$root/claudit.sh" passive --service Domain --domain example.com --output-directory "$tmp/domain-unavailable" --format json >/dev/null
jq -e '([.findings[] | select(.status == "unknown")] | length > 0) and .summary.not_assessed > 8 and .summary.coverage < 30' "$tmp/domain-unavailable/claudit-report.json" >/dev/null
PATH="$root/tests/fixtures/bin:$PATH" CLAUDIT_AWS_FIXTURE=empty "$root/claudit.sh" passive --service AWS --confirm-tenant-connection --output-directory "$tmp/aws-empty" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-AWS-TRAIL" and .status == "fail")] | length == 1)' "$tmp/aws-empty/claudit-report.json" >/dev/null
PATH="$root/tests/fixtures/bin:$PATH" CLAUDIT_AWS_FIXTURE=denied "$root/claudit.sh" passive --service AWS --confirm-tenant-connection --output-directory "$tmp/aws-denied" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-AWS-TRAIL" and .status == "unknown")] | length == 1) and .summary.not_assessed > 0' "$tmp/aws-denied/claudit-report.json" >/dev/null
PATH="$root/tests/fixtures/bin:$PATH" CLAUDIT_AWS_FIXTURE=malformed "$root/claudit.sh" passive --service AWS --confirm-tenant-connection --output-directory "$tmp/aws-malformed" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-AWS-TRAIL" and .status == "error")] | length == 1)' "$tmp/aws-malformed/claudit-report.json" >/dev/null
test -s "$tmp/report/claudit-ocsf.jsonl"
jq -e '."assessment-results".metadata["oscal-version"] == "1.2.1"' "$tmp/report/claudit-oscal-assessment-results.json" >/dev/null
if "$root/claudit.sh" active --service Domain --domain example.com --output-directory "$tmp/active" >/dev/null 2>&1; then echo 'active confirmation gate failed' >&2; exit 1; fi
cp "$tmp/report/claudit-report.json" "$tmp/changed.json"
jq '(.findings[] | select(.id == "CA-DNS-000")).status = "fail"' "$tmp/changed.json" > "$tmp/changed-next.json"
"$root/claudit.sh" compare --reference "$tmp/report/claudit-report.json" --difference "$tmp/changed-next.json" --output-directory "$tmp/drift" >/dev/null
jq -e '[.[] | select(.id == "CA-DNS-000" and .change == "Regressed")] | length == 1' "$tmp/drift/claudit-drift.json" >/dev/null
"$root/claudit.sh" passive --service Exchange --confirm-tenant-connection --exchange-fixture "$root/tests/fixtures/exchange/healthy.jsonl" --output-directory "$tmp/exchange" --format json >/dev/null
jq -e '[.findings[] | select(.id == "EXO-003" and .status == "fail" and .severity == "high")] | length == 1' "$tmp/exchange/claudit-report.json" >/dev/null
echo 'claudit Bash tests: pass'
