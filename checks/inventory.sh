#!/usr/bin/env bash
# Inventory deliberately records only counts and provider context: no secrets,
# tenant names, IP addresses, or resource labels are emitted in the report.
ca_check_inventory() {
    local count
    local -a aws_args=() az_args=()
    [[ -n "$CLAUDIT_AWS_PROFILE" ]] && aws_args=(--profile "$CLAUDIT_AWS_PROFILE")
    [[ -n "$CLAUDIT_AZURE_SUBSCRIPTION" ]] && az_args=(--subscription "$CLAUDIT_AZURE_SUBSCRIPTION")
    if ca_command_exists aws && [[ "$CLAUDIT_CONFIRM_CONNECTION" -eq 1 ]]; then
        count="$(aws "${aws_args[@]}" ec2 describe-instances --query 'length(Reservations[].Instances[])' --output text 2>/dev/null || true)"
        if [[ "$count" =~ ^[0-9]+$ ]]; then ca_finding CA-INV-AWS Inventory pass info 'AWS inventory collected' "AWS reported $count EC2 instances."; else ca_finding CA-INV-AWS Inventory unknown medium 'AWS inventory unavailable' 'AWS inventory collection did not complete.'; fi
    fi
    if ca_command_exists az && [[ "$CLAUDIT_CONFIRM_CONNECTION" -eq 1 ]]; then
        count="$(az resource list "${az_args[@]}" --query 'length(@)' -o tsv 2>/dev/null || true)"
        if [[ "$count" =~ ^[0-9]+$ ]]; then ca_finding CA-INV-AZ Inventory pass info 'Azure inventory collected' "Azure reported $count resources."; else ca_finding CA-INV-AZ Inventory unknown medium 'Azure inventory unavailable' 'Azure inventory collection did not complete.'; fi
    fi
    if ca_command_exists gcloud && [[ "$CLAUDIT_CONFIRM_CONNECTION" -eq 1 && -n "$CLAUDIT_GCP_PROJECT" ]]; then
        count="$(gcloud asset search-all-resources --scope="projects/$CLAUDIT_GCP_PROJECT" --format='value(name)' 2>/dev/null | wc -l | tr -d ' ')"
        ca_finding CA-INV-GCP Inventory pass info 'GCP inventory collected' "GCP reported $count resources."
    fi
}
