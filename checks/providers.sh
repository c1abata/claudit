#!/usr/bin/env bash
ca_check_aws() {
    local args=() region="${CLAUDIT_AWS_REGIONS%%,*}" response
    [[ -n "$CLAUDIT_AWS_PROFILE" ]] && args+=(--profile "$CLAUDIT_AWS_PROFILE")
    [[ -n "$region" ]] && args+=(--region "$region")
    if ! ca_command_exists aws; then ca_finding CA-AWS-001 AWS unknown medium 'AWS CLI unavailable' 'Install AWS CLI v2 to run AWS checks.'; return; fi
    if [[ "$CLAUDIT_CONFIRM_CONNECTION" -ne 1 ]]; then ca_finding CA-AWS-002 AWS unknown info 'AWS connection not confirmed' 'Use --confirm-tenant-connection to permit read-only AWS API calls.'; return; fi
    if aws "${args[@]}" sts get-caller-identity --output json >/dev/null 2>&1; then ca_finding CA-AWS-002 AWS pass info 'AWS identity verified' 'Read-only AWS CLI authentication succeeded.'; else ca_finding CA-AWS-002 AWS unknown high 'AWS identity unavailable' 'AWS CLI could not obtain caller identity.'; return; fi
    response="$(aws "${args[@]}" cloudtrail describe-trails --include-shadow-trails --output json 2>/dev/null)" || { ca_finding CA-AWS-TRAIL AWS unknown high 'CloudTrail collection unavailable' 'AWS could not return CloudTrail configuration; this is not evidence that trails are absent.'; return; }
    if ! jq -e '.trailList | type == "array"' >/dev/null 2>&1 <<<"$response"; then ca_finding CA-AWS-TRAIL AWS error high 'CloudTrail response malformed' 'AWS returned an unexpected CloudTrail response; the control was not assessed.'
    elif jq -e '.trailList | length > 0' >/dev/null <<<"$response"; then ca_finding CA-AWS-TRAIL AWS pass info 'CloudTrail configured' 'At least one CloudTrail trail is configured.'
    else ca_finding CA-AWS-TRAIL AWS fail high 'CloudTrail not configured' 'AWS returned a successful response with no CloudTrail trails.'; fi
}

ca_check_azure() {
    if ! ca_command_exists az; then ca_finding CA-AZ-001 Azure unknown medium 'Azure CLI unavailable' 'Install Azure CLI to run Azure checks.'; return; fi
    if [[ "$CLAUDIT_CONFIRM_CONNECTION" -ne 1 ]]; then ca_finding CA-AZ-002 Azure unknown info 'Azure connection not confirmed' 'Use --confirm-tenant-connection to permit read-only Azure API calls.'; return; fi
    local args=(); [[ -n "$CLAUDIT_AZURE_SUBSCRIPTION" ]] && args+=(--subscription "$CLAUDIT_AZURE_SUBSCRIPTION")
    if az account show "${args[@]}" --output json >/dev/null 2>&1; then ca_finding CA-AZ-002 Azure pass info 'Azure subscription context verified' 'Azure CLI returned the current subscription context.'; else ca_finding CA-AZ-002 Azure unknown high 'Azure subscription unavailable' 'Azure CLI could not read the selected subscription.'; return; fi
    if az monitor activity-log alert list "${args[@]}" --output json 2>/dev/null | jq -e 'length > 0' >/dev/null; then ca_finding CA-AZ-ACTIVITY Azure pass info 'Activity-log alerts configured' 'At least one activity-log alert is configured.'; else ca_finding CA-AZ-ACTIVITY Azure unknown medium 'No activity-log alert found' 'No activity-log alert was returned by Azure.'; fi
}

ca_check_gcp() {
    if ! ca_command_exists gcloud; then ca_finding CA-GCP-001 GCP unknown medium 'gcloud unavailable' 'Install Google Cloud CLI to run GCP checks.'; return; fi
    if [[ "$CLAUDIT_CONFIRM_CONNECTION" -ne 1 ]]; then ca_finding CA-GCP-002 GCP unknown info 'GCP connection not confirmed' 'Use --confirm-tenant-connection to permit read-only GCP API calls.'; return; fi
    [[ -n "$CLAUDIT_GCP_PROJECT" ]] || { ca_finding CA-GCP-002 GCP unknown medium 'GCP project required' 'Provide --gcp-project for GCP checks.'; return; }
    if gcloud projects describe "$CLAUDIT_GCP_PROJECT" --format=json >/dev/null 2>&1; then ca_finding CA-GCP-002 GCP pass info 'GCP project verified' 'gcloud can read the selected project.'; else ca_finding CA-GCP-002 GCP unknown high 'GCP project unavailable' 'gcloud cannot read the selected project.'; return; fi
    if gcloud logging sinks list --project "$CLAUDIT_GCP_PROJECT" --format=json 2>/dev/null | jq -e 'length > 0' >/dev/null; then ca_finding CA-GCP-LOGGING GCP pass info 'Logging sink configured' 'At least one project logging sink is configured.'; else ca_finding CA-GCP-LOGGING GCP unknown medium 'No logging sink found' 'No project logging sink was returned.'; fi
}

ca_check_tailscale() {
    if [[ "$CLAUDIT_CONFIRM_CONNECTION" -ne 1 ]]; then ca_finding CA-TS-001 Tailscale unknown info 'Tailscale connection not confirmed' 'Use --confirm-tenant-connection to permit read-only API calls.'; return; fi
    if [[ -z "${CLAUDIT_TAILSCALE_TOKEN:-}" ]]; then ca_finding CA-TS-001 Tailscale unknown medium 'Tailscale token unavailable' 'Set CLAUDIT_TAILSCALE_TOKEN outside the repository.'; return; fi
    if curl --fail --silent --show-error --max-time 15 -H "Authorization: Bearer $CLAUDIT_TAILSCALE_TOKEN" "https://api.tailscale.com/api/v2/tailnet/$CLAUDIT_TAILSCALE_TAILNET/devices" | jq -e . >/dev/null; then ca_finding CA-TS-001 Tailscale pass info 'Tailscale API reachable' 'The authorized tailnet device inventory was read successfully.'; else ca_finding CA-TS-001 Tailscale unknown high 'Tailscale API unavailable' 'The tailnet inventory could not be retrieved.'; fi
}
