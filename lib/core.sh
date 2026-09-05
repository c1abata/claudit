#!/usr/bin/env bash
# Shared runtime for Claudit. Keep this dependency-light: bash, curl and jq.

CLAUDIT_VERSION="0.4.0"
CLAUDIT_LEVEL="formal"
CLAUDIT_SERVICE=""
CLAUDIT_DOMAIN=""
CLAUDIT_VPS_TARGET=""
CLAUDIT_OUTPUT_DIRECTORY=""
CLAUDIT_FORMAT="all"
CLAUDIT_CONFIRM_ACTIVE=0
CLAUDIT_CONFIRM_CONNECTION=0
CLAUDIT_AWS_PROFILE=""
CLAUDIT_AWS_REGIONS=""
CLAUDIT_AZURE_SUBSCRIPTION=""
CLAUDIT_GCP_PROJECT=""
CLAUDIT_TAILSCALE_TAILNET="-"
CLAUDIT_BASELINE=""
CLAUDIT_FINDINGS_FILE=""
CLAUDIT_COMPARE_REFERENCE=""
CLAUDIT_COMPARE_DIFFERENCE=""
CLAUDIT_WEBHOOK_URL="${CLAUDIT_WEBHOOK_URL:-}"
CLAUDIT_WEBHOOK_TYPE="teams"
CLAUDIT_EXCHANGE_ORGANIZATION="${CLAUDIT_EXCHANGE_ORGANIZATION:-}"
CLAUDIT_EXCHANGE_TENANT_ID="${CLAUDIT_EXCHANGE_TENANT_ID:-}"
CLAUDIT_EXCHANGE_CLIENT_ID="${CLAUDIT_EXCHANGE_CLIENT_ID:-}"
CLAUDIT_EXCHANGE_CERTIFICATE_THUMBPRINT="${CLAUDIT_EXCHANGE_CERTIFICATE_THUMBPRINT:-}"
CLAUDIT_EXCHANGE_FIXTURE=""
CLAUDIT_DOH_FIXTURE="${CLAUDIT_DOH_FIXTURE:-}"

ca_die() { printf 'claudit: %s\n' "$*" >&2; exit 64; }
ca_log() { printf '%s claudit: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
ca_command_exists() { command -v "$1" >/dev/null 2>&1; }
ca_json_escape() { jq -Rn --arg value "$1" '$value'; }
ca_uuid_from_text() {
    local hash
    hash="$(printf '%s' "$1" | sha256sum | cut -d' ' -f1)"
    printf '%s-%s-%s-%s-%s' "${hash:0:8}" "${hash:8:4}" "${hash:12:4}" "${hash:16:4}" "${hash:20:12}"
}

ca_usage() {
    cat <<'EOF'
Usage: ./claudit.sh <command> [options]

Commands: doctor, formal, passive, active, audit, domain, vps, m365, all,
          wizard, dashboard, test, help

Common options:
  --service LIST              Comma-separated: Domain,VPS,AWS,Azure,GCP,Tailscale,M365
  --domain NAME               Authorized DNS domain to audit
  --vps-target HOST           Authorized VPS target
  --output-directory PATH     Report directory (default: ./reports)
  --format FORMAT             json, csv, markdown, html, or all
  --confirm-tenant-connection Allow authenticated cloud API queries
  --confirm-active-probes     Required for active network probes
  --aws-profile NAME          AWS CLI profile
  --aws-region LIST           AWS regions
  --azure-subscription ID     Azure subscription
  --gcp-project ID            Google Cloud project
  --baseline PATH             Optional baseline JSON
  --webhook-url URL           HTTPS Slack or Teams webhook (never persisted)
  --webhook-type TYPE         slack or teams (default: teams)
  --exchange-organization ID  Exchange organization for app-only execution
  --exchange-fixture PATH     Offline Exchange JSONL fixture (tests only)

Environment: CLAUDIT_GRAPH_TOKEN, CLAUDIT_TAILSCALE_TOKEN.
Only audit assets for which you have explicit authorization.
EOF
}

ca_require_runtime() {
    ca_command_exists jq || { printf 'claudit: jq is required.\n' >&2; return 1; }
    ca_command_exists curl || { printf 'claudit: curl is required.\n' >&2; return 1; }
}

ca_init_run() {
    local timestamp
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    CLAUDIT_OUTPUT_DIRECTORY="${CLAUDIT_OUTPUT_DIRECTORY:-$CLAUDIT_ROOT/reports/$timestamp}"
    mkdir -p -- "$CLAUDIT_OUTPUT_DIRECTORY"
    CLAUDIT_FINDINGS_FILE="$(mktemp "$CLAUDIT_OUTPUT_DIRECTORY/.findings.XXXXXX")"
    : > "$CLAUDIT_FINDINGS_FILE"
    trap '[[ -n "${CLAUDIT_FINDINGS_FILE:-}" ]] && rm -f -- "$CLAUDIT_FINDINGS_FILE"' EXIT
}

ca_baseline_path() { printf '%s' "${CLAUDIT_BASELINE:-$CLAUDIT_ROOT/config/baseline.json}"; }

ca_validate_baseline() {
    local path="$1" required section property
    [[ -f "$path" && ! -L "$path" ]] || ca_die "baseline '$path' must be a regular readable file"
    jq -e 'type == "object"' "$path" >/dev/null 2>&1 || ca_die "baseline '$path' is not valid JSON"
    for required in Entra Exchange SharePoint OneDrive Azure AWS GCP Tailscale Domain VPS Inventory; do
        jq -e --arg key "$required" '.[$key] | type == "object"' "$path" >/dev/null || ca_die "baseline '$path' lacks object '$required'"
    done
    while IFS=: read -r section property; do
        jq -e --arg section "$section" --arg property "$property" '.[$section][$property] != null' "$path" >/dev/null || ca_die "baseline '$path' lacks '$section.$property'"
    done <<'EOF'
Entra:RequireSecurityDefaultsOrConditionalAccess
Exchange:RequireModernAuthentication
SharePoint:MaxSharingCapability
OneDrive:RestrictUnmanagedDeviceSync
Azure:RequireStorageDefaultDeny
AWS:Regions
GCP:RequireCentralLogSink
Tailscale:DisallowReusableAuthKeys
Domain:AuthorizedDomains
VPS:AllowedPublicPorts
Inventory:MaxAssetsPerProvider
EOF
    jq -e '[.VPS.AllowedPublicPorts[] | type == "number" and . >= 1 and . <= 65535] | all' "$path" >/dev/null || ca_die "baseline '$path' has invalid VPS.AllowedPublicPorts"
}

ca_baseline_get() { jq -c "$1" "$(ca_baseline_path)"; }
ca_baseline_enabled() { [[ "$(ca_baseline_get "$1")" == true ]]; }

ca_finding() {
    local id="$1" service="$2" status="$3" severity="$4" title="$5" detail="$6"
    local finding_id evidence_sha256 control expected_service
    [[ "$status" =~ ^(pass|fail|warning|info|unknown|error|not_applicable)$ ]] || ca_die "invalid result state '$status' for $id"
    [[ "$severity" =~ ^(info|low|medium|high|critical)$ ]] || ca_die "invalid severity '$severity' for $id"
    control="$(ca_control_metadata "$id")" || ca_die "collector attempted uncatalogued control '$id'"
    expected_service="$(jq -r '.Service' <<<"$control")"
    [[ "$service" == "$expected_service" ]] || ca_die "collector emitted $id for service '$service'; catalog requires '$expected_service'"
    finding_id="$(printf '%s' "$service|$id" | sha256sum | cut -d' ' -f1)"
    evidence_sha256="$(printf '%s' "$detail" | sha256sum | cut -d' ' -f1)"
    jq -cn --arg id "$id" --arg service "$service" --arg status "$status" \
        --arg severity "$severity" --arg title "$title" --arg detail "$detail" \
        --arg level "$CLAUDIT_LEVEL" --arg observed "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg finding_id "$finding_id" --arg evidence_sha256 "$evidence_sha256" \
        --argjson control "$control" \
        '{id:$id,finding_id:$finding_id,evidence_sha256:$evidence_sha256,service:$service,status:$status,severity:$severity,title:$title,detail:$detail,control_level:$level,observed_at:$observed,category:$control.Category,remediation:$control.Remediation,catalog_level:$control.Level}' \
        >> "$CLAUDIT_FINDINGS_FILE"
}

ca_status_from_command() {
    local id="$1" service="$2" title="$3" command_label="$4"
    if ca_command_exists "$command_label"; then
        ca_finding "$id" "$service" pass info "$title" "Required CLI '$command_label' is available."
    else
        ca_finding "$id" "$service" unknown medium "$title" "Required CLI '$command_label' is not installed; check was not run."
    fi
}

ca_write_reports() {
    local json="$CLAUDIT_OUTPUT_DIRECTORY/claudit-report.json" csv="$CLAUDIT_OUTPUT_DIRECTORY/claudit-report.csv"
    local md="$CLAUDIT_OUTPUT_DIRECTORY/claudit-report.md" html="$CLAUDIT_OUTPUT_DIRECTORY/claudit-report.html"
    jq -s --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg version "$CLAUDIT_VERSION" --arg catalog "$(jq -r .Version "$CLAUDIT_CONTROL_CATALOG")" \
        '. as $findings | ($findings | length) as $total | {schema:"claudit/bash-report-v2",version:$version,catalog_version:$catalog,generated_at:$generated,findings:$findings,summary:{total:$total,failed:([$findings[]|select(.status=="fail")]|length),warnings:([$findings[]|select(.status=="warning")]|length),not_assessed:([$findings[]|select(.status=="unknown" or .status=="error")]|length),coverage:(if $total == 0 then 0 else (([$findings[]|select(.status!="unknown" and .status!="error")]|length) / $total * 100) end)}}' "$CLAUDIT_FINDINGS_FILE" > "$json"
    case "$CLAUDIT_FORMAT" in
        json) ;;
        csv|all) jq -r '(["id","service","status","severity","title","detail","control_level","observed_at"], (.findings[] | [.id,.service,.status,.severity,.title,.detail,.control_level,.observed_at])) | @csv' "$json" > "$csv" ;;&
        markdown|all) {
            printf '# Claudit report\n\nGenerated: %s\n\nCoverage: %.0f%% — failures: %s — not assessed: %s\n\n| ID | Service | Status | Severity | Title | Remediation |\n|---|---|---|---|---|---|\n' "$(jq -r .generated_at "$json")" "$(jq -r .summary.coverage "$json")" "$(jq -r .summary.failed "$json")" "$(jq -r .summary.not_assessed "$json")"
            jq -r '.findings[] | "| \(.id) | \(.service) | \(.status) | \(.severity) | \(.title | gsub("\\|"; "\\\\|")) | \(.remediation | gsub("\\|"; "\\\\|")) |"' "$json"
        } > "$md" ;;&
        html|all) {
            printf '%s\n' '<!doctype html><meta charset="utf-8"><title>Claudit report</title><style>body{font:14px system-ui;margin:2rem}table{border-collapse:collapse}td,th{border:1px solid #bbb;padding:.4rem;text-align:left} .fail{background:#fee}.unknown,.error{background:#fff5d6}</style><h1>Claudit report</h1><p>Coverage: '
            jq -r '(.summary.coverage|floor|tostring) + "% — failures: " + (.summary.failed|tostring) + " — not assessed: " + (.summary.not_assessed|tostring)' "$json"
            printf '%s\n' '</p><table><tr><th>ID</th><th>Service</th><th>Status</th><th>Severity</th><th>Title</th><th>Remediation</th></tr>'
            jq -r '.findings[] | "<tr class=\"\(.status|@html)\"><td>\(.id|@html)</td><td>\(.service|@html)</td><td>\(.status|@html)</td><td>\(.severity|@html)</td><td>\(.title|@html)</td><td>\(.remediation|@html)</td></tr>"' "$json"
            printf '%s\n' '</table>'
        } > "$html" ;;&
    esac
    ca_write_interchange "$json"
    cp -- "$CLAUDIT_CONTROL_CATALOG" "$CLAUDIT_OUTPUT_DIRECTORY/claudit-runtime-control-catalog.json"
    ca_send_notification "$json"
    ca_log "report written to $CLAUDIT_OUTPUT_DIRECTORY"
}

ca_parse_options() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --service) CLAUDIT_SERVICE="${2:?--service requires a value}"; shift 2 ;;
            --domain) CLAUDIT_DOMAIN="${2:?--domain requires a value}"; shift 2 ;;
            --vps-target) CLAUDIT_VPS_TARGET="${2:?--vps-target requires a value}"; shift 2 ;;
            --output-directory) CLAUDIT_OUTPUT_DIRECTORY="${2:?--output-directory requires a value}"; shift 2 ;;
            --format) CLAUDIT_FORMAT="${2:?--format requires a value}"; shift 2 ;;
            --aws-profile) CLAUDIT_AWS_PROFILE="${2:?--aws-profile requires a value}"; shift 2 ;;
            --aws-region) CLAUDIT_AWS_REGIONS="${2:?--aws-region requires a value}"; shift 2 ;;
            --azure-subscription) CLAUDIT_AZURE_SUBSCRIPTION="${2:?--azure-subscription requires a value}"; shift 2 ;;
            --gcp-project) CLAUDIT_GCP_PROJECT="${2:?--gcp-project requires a value}"; shift 2 ;;
            --tailscale-tailnet) CLAUDIT_TAILSCALE_TAILNET="${2:?--tailscale-tailnet requires a value}"; shift 2 ;;
            --baseline) CLAUDIT_BASELINE="${2:?--baseline requires a value}"; shift 2 ;;
            --webhook-url) CLAUDIT_WEBHOOK_URL="${2:?--webhook-url requires a value}"; shift 2 ;;
            --webhook-type) CLAUDIT_WEBHOOK_TYPE="${2:?--webhook-type requires a value}"; shift 2 ;;
            --reference) CLAUDIT_COMPARE_REFERENCE="${2:?--reference requires a value}"; shift 2 ;;
            --difference) CLAUDIT_COMPARE_DIFFERENCE="${2:?--difference requires a value}"; shift 2 ;;
            --exchange-organization) CLAUDIT_EXCHANGE_ORGANIZATION="${2:?--exchange-organization requires a value}"; shift 2 ;;
            --exchange-fixture) CLAUDIT_EXCHANGE_FIXTURE="${2:?--exchange-fixture requires a value}"; shift 2 ;;
            --confirm-tenant-connection) CLAUDIT_CONFIRM_CONNECTION=1; shift ;;
            --confirm-active-probes) CLAUDIT_CONFIRM_ACTIVE=1; shift ;;
            -h|--help) ca_usage; exit 0 ;;
            *) ca_die "unknown option '$1'" ;;
        esac
    done
}

ca_selected() { [[ -z "$CLAUDIT_SERVICE" || ",$CLAUDIT_SERVICE," == *",$1,"* || ",$CLAUDIT_SERVICE," == *",All,"* ]]; }

ca_run_audit() {
    ca_require_runtime || return
    ca_init_run
    ca_validate_control_catalog
    ca_validate_baseline "$(ca_baseline_path)"
    ca_finding CA-BASELINE-001 Runtime pass info 'Baseline validated' 'The baseline satisfies the Bash runtime contract.'
    if ca_selected Domain; then ca_check_domain; fi
    if ca_selected VPS; then ca_check_vps; fi
    if ca_selected AWS; then ca_check_aws; fi
    if ca_selected Azure; then ca_check_azure; fi
    if ca_selected GCP; then ca_check_gcp; fi
    if ca_selected Tailscale; then ca_check_tailscale; fi
    if ca_selected M365 || ca_selected Entra || ca_selected SharePoint || ca_selected OneDrive; then ca_check_m365; fi
    if ca_selected M365 || ca_selected Exchange; then ca_check_exchange; fi
    if ca_selected Inventory; then ca_check_inventory; fi
    ca_validate_emitted_controls
    ca_write_reports
}

ca_doctor() {
    ca_init_run
    ca_validate_control_catalog
    ca_status_from_command CA-RT-001 Runtime 'jq availability' jq
    ca_status_from_command CA-RT-002 Runtime 'curl availability' curl
    ca_status_from_command CA-AWS-001 AWS 'AWS CLI availability' aws
    ca_status_from_command CA-AZ-001 Azure 'Azure CLI availability' az
    ca_status_from_command CA-GCP-001 GCP 'Google Cloud CLI availability' gcloud
    ca_status_from_command CA-DNS-001 Domain 'DNS resolver availability' dig
    ca_status_from_command CA-VPS-001 VPS 'OpenSSH client availability' ssh
    ca_validate_emitted_controls
    ca_write_reports
}

ca_wizard() {
    local reply level
    printf 'Claudit guided audit — read-only, authorized scope only\n'
    read -r -p 'Services [Domain,VPS,AWS,Azure,GCP,Tailscale,M365,All]: ' CLAUDIT_SERVICE
    [[ -n "$CLAUDIT_SERVICE" ]] || ca_die 'a service selection is required'
    if [[ ",$CLAUDIT_SERVICE," == *",Domain,"* || "$CLAUDIT_SERVICE" == All ]]; then read -r -p 'Authorized business domain: ' CLAUDIT_DOMAIN; fi
    if [[ ",$CLAUDIT_SERVICE," == *",VPS,"* || "$CLAUDIT_SERVICE" == All ]]; then read -r -p 'Authorized VPS target: ' CLAUDIT_VPS_TARGET; fi
    read -r -p 'Control level [formal/passive/active] (default passive): ' level
    level="${level:-passive}"; [[ "$level" =~ ^(formal|passive|active)$ ]] || ca_die 'control level must be formal, passive or active'
    CLAUDIT_LEVEL="$level"
    if [[ "$CLAUDIT_LEVEL" != formal ]]; then read -r -p 'Permit read-only tenant/provider connections? [y/N] ' reply; [[ "$reply" =~ ^[Yy]$ ]] && CLAUDIT_CONFIRM_CONNECTION=1; fi
    if [[ "$CLAUDIT_LEVEL" == active ]]; then read -r -p 'Permit bounded active probes of declared targets only? [y/N] ' reply; [[ "$reply" =~ ^[Yy]$ ]] && CLAUDIT_CONFIRM_ACTIVE=1; [[ "$CLAUDIT_CONFIRM_ACTIVE" -eq 1 ]] || ca_die 'active probes were not confirmed'; fi
    printf 'Plan: level=%s services=%s domain=%s vps=%s\n' "$CLAUDIT_LEVEL" "$CLAUDIT_SERVICE" "${CLAUDIT_DOMAIN:-none}" "${CLAUDIT_VPS_TARGET:-none}"
    read -r -p 'Run this plan? [y/N] ' reply; [[ "$reply" =~ ^[Yy]$ ]] || { printf 'No audit was run.\n'; return 0; }
    ca_run_audit
}

# Check modules only define functions; loading them performs no network action.
# shellcheck source=checks/domain.sh
source "$CLAUDIT_ROOT/checks/domain.sh"
# shellcheck source=checks/providers.sh
source "$CLAUDIT_ROOT/checks/providers.sh"
# shellcheck source=checks/vps.sh
source "$CLAUDIT_ROOT/checks/vps.sh"
# shellcheck source=checks/m365.sh
source "$CLAUDIT_ROOT/checks/m365.sh"
# shellcheck source=checks/exchange.sh
source "$CLAUDIT_ROOT/checks/exchange.sh"
# shellcheck source=checks/inventory.sh
source "$CLAUDIT_ROOT/checks/inventory.sh"
# shellcheck source=lib/dashboard.sh
source "$CLAUDIT_ROOT/lib/dashboard.sh"
# shellcheck source=lib/interchange.sh
source "$CLAUDIT_ROOT/lib/interchange.sh"
# shellcheck source=lib/drift.sh
source "$CLAUDIT_ROOT/lib/drift.sh"
# shellcheck source=lib/notify.sh
source "$CLAUDIT_ROOT/lib/notify.sh"
# shellcheck source=lib/controls.sh
source "$CLAUDIT_ROOT/lib/controls.sh"

main() {
    local command="${1:-dashboard}"
    [[ $# -gt 0 ]] && shift
    case "$command" in
        help|-h|--help) ca_usage ;;
        doctor|preflight) ca_parse_options "$@"; ca_doctor ;;
        formal|passive|active|audit|run|all|m365|domain|vps)
            case "$command" in formal|passive|active) CLAUDIT_LEVEL="$command" ;; all) CLAUDIT_SERVICE="All" ;; m365) CLAUDIT_SERVICE="M365" ;; domain) CLAUDIT_SERVICE="Domain" ;; vps) CLAUDIT_SERVICE="VPS" ;; esac
            ca_parse_options "$@"
            [[ "$CLAUDIT_LEVEL" != active || "$CLAUDIT_CONFIRM_ACTIVE" -eq 1 ]] || ca_die 'active probes require --confirm-active-probes'
            ca_run_audit ;;
        wizard) ca_parse_options "$@"; ca_wizard ;;
        compare) ca_parse_options "$@"; ca_compare_reports "$CLAUDIT_COMPARE_REFERENCE" "$CLAUDIT_COMPARE_DIFFERENCE" ;;
        dashboard)
            ca_parse_options "$@"
            ca_start_dashboard ;;
        test) "$CLAUDIT_ROOT/tests/run.sh" ;;
        *) ca_die "unknown command '$command'; use ./claudit.sh help" ;;
    esac
}
