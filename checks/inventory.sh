#!/usr/bin/env bash
# Inventory deliberately records only counts and provider context: no secrets,
# tenant names, IP addresses, or resource labels are emitted in the report.
ca_check_inventory() {
    local count response cap limit
    local -a aws_args=() az_args=()
    [[ -n "$CLAUDIT_AWS_PROFILE" ]] && aws_args=(--profile "$CLAUDIT_AWS_PROFILE")
    [[ -z "$CLAUDIT_AWS_REGIONS" ]] || aws_args+=(--region "$CLAUDIT_AWS_REGIONS")
    [[ -n "$CLAUDIT_AZURE_SUBSCRIPTION" ]] && az_args=(--subscription "$CLAUDIT_AZURE_SUBSCRIPTION")
    cap="$(ca_baseline_get '.Inventory.MaxAssetsPerProvider')"
    limit=$((cap + 1))
    if ca_command_exists aws && [[ "$CLAUDIT_CONFIRM_CONNECTION" -eq 1 ]]; then
        if response="$(ca_run_cli aws "${aws_args[@]}" ec2 describe-instances --max-items "$limit" --output json 2>/dev/null)" && jq -e '(.Reservations | type == "array") and all(.Reservations[]?; (.Instances | type == "array"))' >/dev/null 2>&1 <<<"$response"; then
            count="$(jq '[.Reservations[].Instances[]] | length' <<<"$response")"
            if (( count > cap )); then ca_finding CA-INV-AWS Inventory warning medium 'AWS inventory capped' "AWS has more than the $cap asset evidence limit; $limit EC2 instances were observed and the inventory is intentionally partial."; else ca_finding CA-INV-AWS Inventory pass info 'AWS inventory collected' "AWS reported $count EC2 instances within the $cap asset evidence limit."; fi
        else ca_finding CA-INV-AWS Inventory unknown medium 'AWS inventory unavailable' 'AWS inventory collection did not complete within the command deadline or returned malformed data.'; fi
    fi
    if ca_command_exists az && [[ "$CLAUDIT_CONFIRM_CONNECTION" -eq 1 ]]; then
        if response="$(ca_run_cli az resource list "${az_args[@]}" --query "[:$limit].id" --output json 2>/dev/null)" && jq -e 'type == "array" and all(.[]; type == "string")' >/dev/null 2>&1 <<<"$response"; then
            count="$(jq length <<<"$response")"
            if (( count > cap )); then ca_finding CA-INV-AZ Inventory warning medium 'Azure inventory capped' "Azure has more than the $cap asset evidence limit; $limit resource IDs were observed and the inventory is intentionally partial."; else ca_finding CA-INV-AZ Inventory pass info 'Azure inventory collected' "Azure reported $count resources within the $cap asset evidence limit."; fi
        else ca_finding CA-INV-AZ Inventory unknown medium 'Azure inventory unavailable' 'Azure inventory collection did not complete within the command deadline or returned malformed data.'; fi
    fi
    if ca_command_exists gcloud && [[ "$CLAUDIT_CONFIRM_CONNECTION" -eq 1 && -n "$CLAUDIT_GCP_PROJECT" ]]; then
        if response="$(ca_run_cli gcloud asset search-all-resources --scope="projects/$CLAUDIT_GCP_PROJECT" --limit "$limit" --format=json 2>/dev/null)" && jq -e 'type == "array" and all(.[]; type == "object")' >/dev/null 2>&1 <<<"$response"; then
            count="$(jq length <<<"$response")"
            if (( count > cap )); then ca_finding CA-INV-GCP Inventory warning medium 'GCP inventory capped' "GCP has more than the $cap asset evidence limit; $limit resources were observed and the inventory is intentionally partial."; else ca_finding CA-INV-GCP Inventory pass info 'GCP inventory collected' "GCP reported $count resources within the $cap asset evidence limit."; fi
        else ca_finding CA-INV-GCP Inventory unknown medium 'GCP inventory unavailable' 'GCP did not return a successful bounded resource collection.'; fi
    fi
}
