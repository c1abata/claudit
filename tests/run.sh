#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf -- "$tmp"' EXIT

bash -n "$root/claudit.sh" "$root/lib/core.sh" "$root/checks/"*.sh
python3 -m py_compile "$root/service/dashboard.py"
python3 -m unittest discover -s "$root/tests" -p "test_*.py"
node --check "$root/web/assets/operator-reports.js"
node --check "$root/web/assets/workspace.js"
test -x "$root/service/claudit-service.sh"
test ! -x "$root/service/claudit.service"
grep -Fqx 'ExecStart=/opt/claudit/service/claudit-service.sh' "$root/service/claudit.service"
"$root/install-ubuntu.sh" --dry-run >/dev/null
merged_baseline="$tmp/merged-baseline.json"
jq -s '.[0] * .[1]' \
  "$root/config/baseline.json" \
  <(jq '{AWS: (.AWS | .Regions = ["eu-west-1"]), Domain: {AuthorizedDomains: ["operator.example"]}}' "$root/config/baseline.json") \
  >"$merged_baseline"
jq -e '.AWS.Regions == ["eu-west-1"] and .Domain.AuthorizedDomains == ["operator.example"] and (.Domain.Resolver.Endpoint | type == "string")' "$merged_baseline" >/dev/null
"$root/claudit.sh" doctor --output-directory "$tmp/doctor" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-RT-001" and .status == "pass")] | length == 1)' "$tmp/doctor/claudit-report.json" >/dev/null
jq '(.Controls[] | select(.Id == "CA-DNS-000")).Service = "WrongService"' "$root/config/runtime-control-catalog.json" > "$tmp/bad-catalog.json"
if CLAUDIT_CONTROL_CATALOG="$tmp/bad-catalog.json" "$root/claudit.sh" formal --service Domain --domain example.com --output-directory "$tmp/bad-catalog" --format json >/dev/null 2>&1; then echo 'catalog service binding failed' >&2; exit 1; fi
"$root/claudit.sh" formal --service Domain --domain invalid_domain --output-directory "$tmp/report" --format json >/dev/null
jq -e '.schema == "claudit/bash-report-v2" and ([.findings[] | select(.id == "CA-DNS-000" and .status == "error")] | length == 1)' "$tmp/report/claudit-report.json" >/dev/null
"$root/claudit.sh" formal --service Domain --domain example.com --output-directory "$tmp/formal-domain" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-DNS-000" and .status == "pass")] | length == 1)' "$tmp/formal-domain/claudit-report.json" >/dev/null
CLAUDIT_DOH_FIXTURE="$root/tests/fixtures/domain/business-example.json" "$root/claudit.sh" passive --service Domain --domain example.com --output-directory "$tmp/domain" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-DNS-DMARC" and .status == "pass" and (.remediation | length > 0))] | length == 1) and .summary.coverage > 90' "$tmp/domain/claudit-report.json" >/dev/null
jq '(."_dmarc.example.com|TXT".Answer[0].data = "v=DMARC1; p=none") | (."example.com|TXT".Answer += [{"data":"v=spf1 -all","type":16}])' "$root/tests/fixtures/domain/business-example.json" > "$tmp/domain-weak.json"
CLAUDIT_DOH_FIXTURE="$tmp/domain-weak.json" "$root/claudit.sh" passive --service Domain --domain example.com --output-directory "$tmp/domain-weak" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-DNS-DMARC" and .status == "warning")] | length == 1) and ([.findings[] | select(.id == "CA-DNS-SPF" and .status == "fail")] | length == 1)' "$tmp/domain-weak/claudit-report.json" >/dev/null
CLAUDIT_DOH_FIXTURE="$tmp/not-present.json" "$root/claudit.sh" passive --service Domain --domain example.com --output-directory "$tmp/domain-unavailable" --format json >/dev/null
jq -e '([.findings[] | select(.status == "unknown")] | length >= 12) and .summary.not_assessed >= 12 and .summary.coverage < 40' "$tmp/domain-unavailable/claudit-report.json" >/dev/null
PATH="$root/tests/fixtures/bin:$PATH" CLAUDIT_AWS_FIXTURE=empty "$root/claudit.sh" passive --service AWS --confirm-tenant-connection --output-directory "$tmp/aws-empty" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-AWS-TRAIL" and .status == "fail")] | length == 1)' "$tmp/aws-empty/claudit-report.json" >/dev/null
PATH="$root/tests/fixtures/bin:$PATH" CLAUDIT_AWS_FIXTURE=denied "$root/claudit.sh" passive --service AWS --confirm-tenant-connection --output-directory "$tmp/aws-denied" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-AWS-TRAIL" and .status == "unknown")] | length == 1) and .summary.not_assessed > 0' "$tmp/aws-denied/claudit-report.json" >/dev/null
PATH="$root/tests/fixtures/bin:$PATH" CLAUDIT_AWS_FIXTURE=malformed "$root/claudit.sh" passive --service AWS --confirm-tenant-connection --output-directory "$tmp/aws-malformed" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-AWS-TRAIL" and .status == "error")] | length == 1)' "$tmp/aws-malformed/claudit-report.json" >/dev/null
PATH="$root/tests/fixtures/bin:$PATH" CLAUDIT_AWS_FIXTURE=healthy "$root/claudit.sh" passive --service AWS --confirm-tenant-connection --output-directory "$tmp/aws-healthy" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-AWS-ROOT-MFA" and .status == "pass")] | length == 1) and ([.findings[] | select(.id == "CA-AWS-PASSWORD-POLICY" and .status == "pass")] | length == 1) and ([.findings[] | select(.id == "CA-AWS-ACCESS-KEY-AGE" and .status == "pass")] | length == 1) and ([.findings[] | select(.id == "CA-AWS-TRAIL-PROTECTION" and .status == "pass")] | length == 1) and ([.findings[] | select(.id == "CA-AWS-SG-PUBLIC" and .status == "pass")] | length == 1) and ([.findings[] | select(.id == "CA-AWS-VPC-FLOW-LOGS" and .status == "pass")] | length == 1)' "$tmp/aws-healthy/claudit-report.json" >/dev/null
jq -e '(.account == "000000000000") and (.arn | startswith("arn:aws:"))' "$tmp/aws-healthy/claudit-aws-identity.json" >/dev/null
PATH="$root/tests/fixtures/bin:$PATH" CLAUDIT_AWS_FIXTURE=insecure "$root/claudit.sh" passive --service AWS --confirm-tenant-connection --output-directory "$tmp/aws-insecure" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-AWS-ROOT-MFA" and .status == "fail")] | length == 1) and ([.findings[] | select(.id == "CA-AWS-PASSWORD-POLICY" and .status == "fail")] | length == 1) and ([.findings[] | select(.id == "CA-AWS-ACCESS-KEY-AGE" and .status == "fail")] | length == 1) and ([.findings[] | select(.id == "CA-AWS-TRAIL-PROTECTION" and .status == "fail")] | length == 1) and ([.findings[] | select(.id == "CA-AWS-SG-PUBLIC" and .status == "fail")] | length == 1) and ([.findings[] | select(.id == "CA-AWS-VPC-FLOW-LOGS" and .status == "fail")] | length == 1)' "$tmp/aws-insecure/claudit-report.json" >/dev/null
PATH="$root/tests/fixtures/bin:$PATH" CLAUDIT_AWS_FIXTURE=paginated "$root/claudit.sh" passive --service AWS --confirm-tenant-connection --output-directory "$tmp/aws-paginated" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-AWS-ACCESS-KEY-AGE" and .status == "pass" and (.detail | contains("2 active")))] | length == 1) and ([.findings[] | select(.id == "CA-AWS-SG-PUBLIC" and .status == "pass")] | length == 1) and ([.findings[] | select(.id == "CA-AWS-VPC-FLOW-LOGS" and .status == "pass" and (.detail | contains("2 collected")))] | length == 1)' "$tmp/aws-paginated/claudit-report.json" >/dev/null
jq '.Azure.RequireStorageDefaultDeny = true' "$root/config/baseline.json" > "$tmp/azure-baseline.json"
PATH="$root/tests/fixtures/bin:$PATH" CLAUDIT_AZURE_FIXTURE=healthy "$root/claudit.sh" passive --service Azure --confirm-tenant-connection --baseline "$tmp/azure-baseline.json" --output-directory "$tmp/azure-healthy" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-AZ-ACTIVITY" and .status == "pass")] | length == 1) and ([.findings[] | select(.id == "CA-AZ-ROLE" and .status == "pass")] | length == 1) and ([.findings[] | select(.id == "CA-AZ-GRAPH-APP-ROLES" and .status == "pass")] | length == 1) and ([.findings[] | select(.id == "CA-AZ-STORAGE-NETWORK" and .status == "pass")] | length == 1) and ([.findings[] | select(.id == "CA-AZ-KEYVAULT-PURGE" and .status == "pass")] | length == 1)' "$tmp/azure-healthy/claudit-report.json" >/dev/null
jq -e '.subscription == "00000000-0000-0000-0000-000000000001" and .tenant == "00000000-0000-0000-0000-000000000002"' "$tmp/azure-healthy/claudit-azure-identity.json" >/dev/null
PATH="$root/tests/fixtures/bin:$PATH" CLAUDIT_AZURE_FIXTURE=insecure "$root/claudit.sh" passive --service Azure --confirm-tenant-connection --baseline "$tmp/azure-baseline.json" --output-directory "$tmp/azure-insecure" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-AZ-ACTIVITY" and .status == "fail")] | length == 1) and ([.findings[] | select(.id == "CA-AZ-ROLE" and .status == "fail")] | length == 1) and ([.findings[] | select(.id == "CA-AZ-GRAPH-APP-ROLES" and .status == "fail")] | length == 1) and ([.findings[] | select(.id == "CA-AZ-STORAGE-NETWORK" and .status == "fail")] | length == 1) and ([.findings[] | select(.id == "CA-AZ-KEYVAULT-PURGE" and .status == "fail")] | length == 1)' "$tmp/azure-insecure/claudit-report.json" >/dev/null
PATH="$root/tests/fixtures/bin:$PATH" CLAUDIT_AZURE_FIXTURE=denied "$root/claudit.sh" passive --service Azure --confirm-tenant-connection --output-directory "$tmp/azure-denied" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-AZ-002" and .status == "unknown")] | length == 1) and .summary.not_assessed > 0' "$tmp/azure-denied/claudit-report.json" >/dev/null
PATH="$root/tests/fixtures/bin:$PATH" CLAUDIT_AZURE_FIXTURE=malformed "$root/claudit.sh" passive --service Azure --confirm-tenant-connection --output-directory "$tmp/azure-malformed" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-AZ-002" and .status == "error")] | length == 1) and ([.findings[] | select(.id == "CA-AZ-ACTIVITY" and .status == "error")] | length == 1) and ([.findings[] | select(.id == "CA-AZ-ROLE" and .status == "error")] | length == 1)' "$tmp/azure-malformed/claudit-report.json" >/dev/null
PATH="$root/tests/fixtures/bin:$PATH" CLAUDIT_AZURE_FIXTURE=oversized "$root/claudit.sh" passive --service Azure --confirm-tenant-connection --output-directory "$tmp/azure-oversized" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-AZ-ACTIVITY" and .status == "unknown")] | length == 1) and ([.findings[] | select(.id == "CA-AZ-ROLE" and .status == "unknown")] | length == 1) and ([.findings[] | select(.id == "CA-AZ-KEYVAULT-PURGE" and .status == "unknown")] | length == 1)' "$tmp/azure-oversized/claudit-report.json" >/dev/null
PATH="$root/tests/fixtures/bin:$PATH" CLAUDIT_GCP_FIXTURE=healthy "$root/claudit.sh" passive --service GCP --gcp-project fixture --confirm-tenant-connection --output-directory "$tmp/gcp-healthy" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-GCP-LOGGING" and .status == "pass")] | length == 1) and ([.findings[] | select(.id == "CA-GCP-IAM-PRIMITIVE" and .status == "pass")] | length == 1) and ([.findings[] | select(.id == "CA-GCP-AUDIT-LOGS" and .status == "pass")] | length == 1) and ([.findings[] | select(.id == "CA-GCP-OSLOGIN" and .status == "pass")] | length == 1) and ([.findings[] | select(.id == "CA-GCP-SA-KEY-AGE" and .status == "pass")] | length == 1)' "$tmp/gcp-healthy/claudit-report.json" >/dev/null
PATH="$root/tests/fixtures/bin:$PATH" CLAUDIT_GCP_FIXTURE=insecure "$root/claudit.sh" passive --service GCP --gcp-project fixture --confirm-tenant-connection --output-directory "$tmp/gcp-insecure" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-GCP-LOGGING" and .status == "fail")] | length == 1) and ([.findings[] | select(.id == "CA-GCP-IAM-PRIMITIVE" and .status == "fail")] | length == 1) and ([.findings[] | select(.id == "CA-GCP-AUDIT-LOGS" and .status == "fail")] | length == 1) and ([.findings[] | select(.id == "CA-GCP-OSLOGIN" and .status == "fail")] | length == 1) and ([.findings[] | select(.id == "CA-GCP-SA-KEY-AGE" and .status == "fail")] | length == 1)' "$tmp/gcp-insecure/claudit-report.json" >/dev/null
PATH="$root/tests/fixtures/bin:$PATH" CLAUDIT_GCP_FIXTURE=denied "$root/claudit.sh" passive --service GCP --gcp-project fixture --confirm-tenant-connection --output-directory "$tmp/gcp-denied" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-GCP-002" and .status == "unknown")] | length == 1) and .summary.not_assessed > 0' "$tmp/gcp-denied/claudit-report.json" >/dev/null
PATH="$root/tests/fixtures/bin:$PATH" CLAUDIT_GCP_FIXTURE=malformed "$root/claudit.sh" passive --service GCP --gcp-project fixture --confirm-tenant-connection --output-directory "$tmp/gcp-malformed" --format json >/dev/null
jq -e '([.findings[] | select(.id == "CA-GCP-002" and .status == "error")] | length == 1) and ([.findings[] | select(.id == "CA-GCP-IAM-PRIMITIVE" and .status == "error")] | length == 1)' "$tmp/gcp-malformed/claudit-report.json" >/dev/null
test -s "$tmp/report/claudit-ocsf.jsonl"
jq -e '
  ."assessment-results" as $ar |
  $ar.metadata["oscal-version"] == "1.2.3" and
  ($ar["import-ap"].href | startswith("urn:uuid:")) and
  ($ar.results[0]["reviewed-controls"]["control-selections"][0]["include-controls"] | length > 0) and
  all($ar.results[0].observations[]; (.uuid | test("^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"))) and
  all($ar.results[0].findings[]; .target.status.reason == "pass" or .target.status.reason == "fail" or .target.status.reason == "other")
' "$tmp/report/claudit-oscal-assessment-results.json" >/dev/null
if "$root/claudit.sh" active --service Domain --domain example.com --output-directory "$tmp/active" >/dev/null 2>&1; then echo 'active confirmation gate failed' >&2; exit 1; fi
cp "$tmp/report/claudit-report.json" "$tmp/changed.json"
jq '(.findings[] | select(.id == "CA-DNS-000")).status = "fail"' "$tmp/changed.json" > "$tmp/changed-next.json"
"$root/claudit.sh" compare --reference "$tmp/report/claudit-report.json" --difference "$tmp/changed-next.json" --output-directory "$tmp/drift" >/dev/null
jq -e '[.[] | select(.id == "CA-DNS-000" and .change == "Regressed")] | length == 1' "$tmp/drift/claudit-drift.json" >/dev/null
"$root/claudit.sh" passive --service Exchange --confirm-tenant-connection --exchange-fixture "$root/tests/fixtures/exchange/healthy.jsonl" --output-directory "$tmp/exchange" --format json >/dev/null
jq -e '[.findings[] | select(.id == "EXO-003" and .status == "fail" and .severity == "high")] | length == 1' "$tmp/exchange/claudit-report.json" >/dev/null
echo 'claudit Bash tests: pass'
