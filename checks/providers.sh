#!/usr/bin/env bash
ca_check_aws() {
    local args=() region="${CLAUDIT_AWS_REGIONS%%,*}" response identity account_summary password_policy groups='[]' token='' page=0
    local users='[]' user_token='' user_page=0 user key_response created created_epoch age_days stale_keys=0 active_keys=0 now_epoch
    local vpcs='[]' flow_logs='[]' vpc_token='' flow_token='' vpc_page=0 flow_page=0 missing_flow_logs
    [[ -n "$CLAUDIT_AWS_PROFILE" ]] && args+=(--profile "$CLAUDIT_AWS_PROFILE")
    [[ -n "$region" ]] && args+=(--region "$region")
    if ! ca_command_exists aws; then ca_finding CA-AWS-001 AWS unknown medium 'AWS CLI unavailable' 'Install AWS CLI v2 to run AWS checks.'; return; fi
    if [[ "$CLAUDIT_CONFIRM_CONNECTION" -ne 1 ]]; then ca_finding CA-AWS-002 AWS unknown info 'AWS connection not confirmed' 'Use --confirm-tenant-connection to permit read-only AWS API calls.'; return; fi
    if ! identity="$(ca_run_cli aws "${args[@]}" sts get-caller-identity --output json 2>/dev/null)"; then ca_finding CA-AWS-002 AWS unknown high 'AWS identity unavailable' 'AWS CLI could not obtain caller identity within the command deadline.'; return
    elif ! jq -e '(.Account | type == "string" and test("^[0-9]{12}$")) and (.Arn | type == "string" and startswith("arn:aws:"))' >/dev/null 2>&1 <<<"$identity"; then ca_finding CA-AWS-002 AWS error high 'AWS identity malformed' 'AWS returned an identity response that cannot be bound to an account.'; return
    fi
    jq -cn --arg account "$(jq -r .Account <<<"$identity")" --arg arn "$(jq -r .Arn <<<"$identity")" --arg region "$region" '{account:$account,arn:$arn,region:$region}' > "$CLAUDIT_OUTPUT_DIRECTORY/claudit-aws-identity.json"
    ca_finding CA-AWS-002 AWS pass info 'AWS identity verified' 'Read-only AWS CLI authentication succeeded for the selected account context; see claudit-aws-identity.json.'

    if ! account_summary="$(ca_run_cli aws "${args[@]}" iam get-account-summary --output json 2>/dev/null)"; then ca_finding CA-AWS-ROOT-MFA AWS unknown high 'AWS root MFA collection unavailable' 'AWS could not return the account summary within the command deadline; root MFA remains unassessed.'
    elif ! jq -e '.SummaryMap.AccountMFAEnabled | type == "number" and (. == 0 or . == 1)' >/dev/null 2>&1 <<<"$account_summary"; then ca_finding CA-AWS-ROOT-MFA AWS error high 'AWS root MFA response malformed' 'AWS returned an unexpected root MFA summary value.'
    elif ! ca_baseline_enabled '.AWS.RequireRootMfa'; then ca_finding CA-AWS-ROOT-MFA AWS info info 'AWS root MFA policy not required' 'The local baseline does not require root MFA.'
    elif jq -e '.SummaryMap.AccountMFAEnabled == 1' >/dev/null <<<"$account_summary"; then ca_finding CA-AWS-ROOT-MFA AWS pass info 'AWS root MFA enabled' 'The AWS account summary reports root-user MFA enabled.'
    else ca_finding CA-AWS-ROOT-MFA AWS fail critical 'AWS root MFA disabled' 'The AWS account summary reports that root-user MFA is not enabled.'; fi

    if ! password_policy="$(ca_run_cli aws "${args[@]}" iam get-account-password-policy --output json 2>&1)"; then
        if grep -q 'NoSuchEntity' <<<"$password_policy"; then ca_finding CA-AWS-PASSWORD-POLICY AWS fail high 'AWS IAM password policy absent' 'AWS reports that no account password policy is configured.'
        else ca_finding CA-AWS-PASSWORD-POLICY AWS unknown high 'AWS IAM password policy unavailable' 'AWS could not return the account password policy.'; fi
    elif ! jq -e '.PasswordPolicy as $policy | ($policy.MinimumPasswordLength | type == "number") and ($policy.MaxPasswordAge | type == "number") and ($policy.PasswordReusePrevention | type == "number")' >/dev/null 2>&1 <<<"$password_policy"; then ca_finding CA-AWS-PASSWORD-POLICY AWS error high 'AWS IAM password policy malformed' 'AWS returned an unexpected account password policy.'
    elif jq -e --argjson minimum "$(ca_baseline_get '.AWS.MinPasswordLength')" --argjson maximum_age "$(ca_baseline_get '.AWS.MaxPasswordAgeDays')" --argjson reuse "$(ca_baseline_get '.AWS.PasswordReusePrevention')" '.PasswordPolicy | .MinimumPasswordLength >= $minimum and .MaxPasswordAge <= $maximum_age and .PasswordReusePrevention >= $reuse' >/dev/null <<<"$password_policy"; then ca_finding CA-AWS-PASSWORD-POLICY AWS pass info 'AWS IAM password policy meets baseline' 'Minimum length, maximum age and reuse prevention meet the configured baseline.'
    else ca_finding CA-AWS-PASSWORD-POLICY AWS fail high 'AWS IAM password policy below baseline' 'One or more IAM password policy values do not meet the configured baseline.'; fi

    while :; do
        user_page=$((user_page + 1))
        local -a user_args=("${args[@]}" iam list-users --max-items 100 --output json)
        [[ -n "$user_token" ]] && user_args+=(--starting-token "$user_token")
        if ! response="$(ca_run_cli aws "${user_args[@]}" 2>/dev/null)"; then ca_finding CA-AWS-ACCESS-KEY-AGE AWS unknown high 'AWS IAM user collection unavailable' 'AWS could not return IAM users within the command deadline; access-key age remains unassessed.'; users=''; break; fi
        if ! jq -e '(.Users | type == "array") and all(.Users[]?; (.UserName | type == "string" and length > 0)) and ((.NextToken? // null) | type == "string" or type == "null")' >/dev/null 2>&1 <<<"$response"; then ca_finding CA-AWS-ACCESS-KEY-AGE AWS error high 'AWS IAM user response malformed' 'AWS returned an unexpected IAM user page.'; users=''; break; fi
        users="$(jq -cn --argjson previous "$users" --argjson page "$response" '$previous + $page.Users')"
        user_token="$(jq -r '.NextToken // empty' <<<"$response")"
        [[ -z "$user_token" ]] && break
        if (( user_page >= 10 )); then ca_finding CA-AWS-ACCESS-KEY-AGE AWS unknown high 'AWS IAM user collection incomplete' 'IAM user pagination exceeded the ten-page safety bound; access-key age remains unassessed.'; users=''; break; fi
    done
    if [[ -n "$users" ]]; then
        now_epoch="$(date -u +%s)"
        while IFS= read -r user; do
            if ! key_response="$(ca_run_cli aws "${args[@]}" iam list-access-keys --user-name "$user" --output json 2>/dev/null)"; then ca_finding CA-AWS-ACCESS-KEY-AGE AWS unknown high 'AWS access-key collection unavailable' 'AWS could not return access-key metadata for every collected IAM user within the command deadline.'; users=''; break; fi
            if ! jq -e '(.AccessKeyMetadata | type == "array") and all(.AccessKeyMetadata[]?; (.Status | type == "string") and (.CreateDate | type == "string"))' >/dev/null 2>&1 <<<"$key_response"; then ca_finding CA-AWS-ACCESS-KEY-AGE AWS error high 'AWS access-key response malformed' 'AWS returned unexpected access-key metadata.'; users=''; break; fi
            while IFS= read -r created; do
                active_keys=$((active_keys + 1))
                created_epoch="$(date -u -d "$created" +%s 2>/dev/null || true)"
                if [[ ! "$created_epoch" =~ ^[0-9]+$ ]] || (( created_epoch > now_epoch )); then ca_finding CA-AWS-ACCESS-KEY-AGE AWS error high 'AWS access-key timestamp malformed' 'An active access key has an invalid or future creation timestamp.'; users=''; break 2; fi
                age_days=$(((now_epoch - created_epoch) / 86400))
                (( age_days <= $(ca_baseline_get '.AWS.MaxAccessKeyAgeDays') )) || stale_keys=$((stale_keys + 1))
            done < <(jq -r '.AccessKeyMetadata[]? | select(.Status == "Active") | .CreateDate' <<<"$key_response")
        done < <(jq -r '.[].UserName' <<<"$users")
        if [[ -n "$users" ]]; then
            if (( stale_keys == 0 )); then ca_finding CA-AWS-ACCESS-KEY-AGE AWS pass info 'AWS access-key ages within baseline' "Assessed $active_keys active IAM user access key(s); none exceed the configured maximum age."
            else ca_finding CA-AWS-ACCESS-KEY-AGE AWS fail high 'Stale AWS access keys found' "$stale_keys of $active_keys active IAM user access key(s) exceed the configured maximum age."; fi
        fi
    fi

    response="$(ca_run_cli aws "${args[@]}" cloudtrail describe-trails --include-shadow-trails --output json 2>/dev/null)" || { ca_finding CA-AWS-TRAIL AWS unknown high 'CloudTrail collection unavailable' 'AWS could not return CloudTrail configuration within the command deadline; this is not evidence that trails are absent.'; return; }
    if ! jq -e '.trailList | type == "array"' >/dev/null 2>&1 <<<"$response"; then
        ca_finding CA-AWS-TRAIL AWS error high 'CloudTrail response malformed' 'AWS returned an unexpected CloudTrail response; the control was not assessed.'
        ca_finding CA-AWS-TRAIL-PROTECTION AWS error high 'CloudTrail protection response malformed' 'AWS returned no usable trail properties for policy evaluation.'
    elif ! jq -e '.trailList | length > 0' >/dev/null <<<"$response"; then
        ca_finding CA-AWS-TRAIL AWS fail high 'CloudTrail not configured' 'AWS returned a successful response with no CloudTrail trails.'
        ca_finding CA-AWS-TRAIL-PROTECTION AWS fail high 'Protected CloudTrail not configured' 'No CloudTrail trail exists to satisfy the configured multi-region and validation policy.'
    else
        ca_finding CA-AWS-TRAIL AWS pass info 'CloudTrail configured' 'At least one CloudTrail trail is configured.'
        if ! jq -e 'all(.trailList[]; (.IsMultiRegionTrail | type == "boolean") and (.LogFileValidationEnabled | type == "boolean"))' >/dev/null 2>&1 <<<"$response"; then
            ca_finding CA-AWS-TRAIL-PROTECTION AWS error high 'CloudTrail protection response malformed' 'A returned trail lacks boolean multi-region or log-file-validation evidence.'
        elif jq -e --argjson multi "$(ca_baseline_get '.AWS.RequireMultiRegionCloudTrail')" --argjson validation "$(ca_baseline_get '.AWS.RequireCloudTrailLogFileValidation')" '[.trailList[] | select((($multi | not) or .IsMultiRegionTrail) and (($validation | not) or .LogFileValidationEnabled))] | length > 0' >/dev/null <<<"$response"; then
            ca_finding CA-AWS-TRAIL-PROTECTION AWS pass info 'Protected CloudTrail configured' 'A returned CloudTrail trail satisfies the configured multi-region and log-file-validation policy.'
        else ca_finding CA-AWS-TRAIL-PROTECTION AWS fail high 'CloudTrail protection incomplete' 'No returned CloudTrail trail satisfies the configured multi-region and log-file-validation policy.'; fi
    fi

    while :; do
        page=$((page + 1))
        local -a page_args=("${args[@]}" ec2 describe-security-groups --max-items 100 --output json)
        [[ -n "$token" ]] && page_args+=(--starting-token "$token")
        if ! response="$(ca_run_cli aws "${page_args[@]}" 2>/dev/null)"; then ca_finding CA-AWS-SG-PUBLIC AWS unknown high 'Security-group collection unavailable' 'AWS could not return security groups within the command deadline; public ingress remains unassessed.'; return; fi
        if ! jq -e '(.SecurityGroups | type == "array") and ((.NextToken? // null) | type == "string" or type == "null")' >/dev/null 2>&1 <<<"$response"; then ca_finding CA-AWS-SG-PUBLIC AWS error high 'Security-group response malformed' 'AWS returned an unexpected security-group page.'; return; fi
        groups="$(jq -cn --argjson previous "$groups" --argjson page "$response" '$previous + $page.SecurityGroups')"
        token="$(jq -r '.NextToken // empty' <<<"$response")"
        [[ -z "$token" ]] && break
        if (( page >= 10 )); then ca_finding CA-AWS-SG-PUBLIC AWS unknown high 'Security-group collection incomplete' 'Security-group pagination exceeded the ten-page safety bound; public ingress remains unassessed.'; return; fi
    done
    if ! jq -e 'all(.[]; (.GroupId | type == "string") and ((.IpPermissions // []) | type == "array"))' >/dev/null 2>&1 <<<"$groups"; then ca_finding CA-AWS-SG-PUBLIC AWS error high 'Security-group data malformed' 'A returned security group lacks a stable identifier or valid ingress list.'; return; fi

    while :; do
        vpc_page=$((vpc_page + 1))
        local -a vpc_args=("${args[@]}" ec2 describe-vpcs --max-items 100 --output json)
        [[ -n "$vpc_token" ]] && vpc_args+=(--starting-token "$vpc_token")
        if ! response="$(ca_run_cli aws "${vpc_args[@]}" 2>/dev/null)"; then ca_finding CA-AWS-VPC-FLOW-LOGS AWS unknown high 'VPC collection unavailable' 'AWS could not return VPCs within the command deadline; flow-log coverage remains unassessed.'; vpcs=''; break; fi
        if ! jq -e '(.Vpcs | type == "array") and all(.Vpcs[]?; (.VpcId | type == "string" and length > 0)) and ((.NextToken? // null) | type == "string" or type == "null")' >/dev/null 2>&1 <<<"$response"; then ca_finding CA-AWS-VPC-FLOW-LOGS AWS error high 'VPC response malformed' 'AWS returned an unexpected VPC page.'; vpcs=''; break; fi
        vpcs="$(jq -cn --argjson previous "$vpcs" --argjson page "$response" '$previous + $page.Vpcs')"
        vpc_token="$(jq -r '.NextToken // empty' <<<"$response")"
        [[ -z "$vpc_token" ]] && break
        if (( vpc_page >= 10 )); then ca_finding CA-AWS-VPC-FLOW-LOGS AWS unknown high 'VPC collection incomplete' 'VPC pagination exceeded the ten-page safety bound; flow-log coverage remains unassessed.'; vpcs=''; break; fi
    done
    if [[ -n "$vpcs" ]]; then
        while :; do
            flow_page=$((flow_page + 1))
            local -a flow_args=("${args[@]}" ec2 describe-flow-logs --max-items 100 --output json)
            [[ -n "$flow_token" ]] && flow_args+=(--starting-token "$flow_token")
            if ! response="$(ca_run_cli aws "${flow_args[@]}" 2>/dev/null)"; then ca_finding CA-AWS-VPC-FLOW-LOGS AWS unknown high 'VPC Flow Log collection unavailable' 'AWS could not return VPC Flow Logs within the command deadline; coverage remains unassessed.'; vpcs=''; break; fi
            if ! jq -e '(.FlowLogs | type == "array") and all(.FlowLogs[]?; (.ResourceId | type == "string") and (.FlowLogStatus | type == "string") and (.DeliverLogsStatus | type == "string")) and ((.NextToken? // null) | type == "string" or type == "null")' >/dev/null 2>&1 <<<"$response"; then ca_finding CA-AWS-VPC-FLOW-LOGS AWS error high 'VPC Flow Log response malformed' 'AWS returned an unexpected VPC Flow Log page.'; vpcs=''; break; fi
            flow_logs="$(jq -cn --argjson previous "$flow_logs" --argjson page "$response" '$previous + $page.FlowLogs')"
            flow_token="$(jq -r '.NextToken // empty' <<<"$response")"
            [[ -z "$flow_token" ]] && break
            if (( flow_page >= 10 )); then ca_finding CA-AWS-VPC-FLOW-LOGS AWS unknown high 'VPC Flow Log collection incomplete' 'Flow Log pagination exceeded the ten-page safety bound; coverage remains unassessed.'; vpcs=''; break; fi
        done
    fi
    if [[ -n "$vpcs" ]]; then
        if ! ca_baseline_enabled '.AWS.RequireVpcFlowLogs'; then ca_finding CA-AWS-VPC-FLOW-LOGS AWS info info 'VPC Flow Log policy not required' 'The local baseline does not require VPC Flow Logs.'
        else
            missing_flow_logs="$(jq -n --argjson vpcs "$vpcs" --argjson logs "$flow_logs" '[$vpcs[] | .VpcId as $id | select(any($logs[]; .ResourceId == $id and .FlowLogStatus == "ACTIVE" and .DeliverLogsStatus == "SUCCESS") | not)] | length')"
            if [[ "$missing_flow_logs" == 0 ]]; then ca_finding CA-AWS-VPC-FLOW-LOGS AWS pass info 'VPC Flow Logs cover collected VPCs' "All $(jq length <<<"$vpcs") collected VPC(s) have an active, successfully delivering Flow Log."
            else ca_finding CA-AWS-VPC-FLOW-LOGS AWS fail high 'VPC Flow Log coverage incomplete' "$missing_flow_logs collected VPC(s) lack an active, successfully delivering Flow Log."; fi
        fi
    fi
    if ! ca_baseline_enabled '.AWS.BlockPublicAdministrativeIngress'; then ca_finding CA-AWS-SG-PUBLIC AWS info info 'Public ingress policy not required' 'The local baseline does not require public administrative ingress restrictions.'; return; fi
    local public_exposure
    public_exposure="$(jq --argjson allowed "$(ca_baseline_get '.AWS.AllowedPublicIngressPorts')" '[.[] | .IpPermissions[]? | . as $rule | select((([($rule.IpRanges // [])[]?.CidrIp, ($rule.Ipv6Ranges // [])[]?.CidrIpv6] | index("0.0.0.0/0") or index("::/0"))) and (($rule.IpProtocol != "tcp") or (($rule.FromPort | type) != "number") or (($rule.ToPort | type) != "number") or ($rule.FromPort != $rule.ToPort) or ($allowed | index($rule.FromPort) | not)))] | length' <<<"$groups")"
    if [[ "$public_exposure" == 0 ]]; then ca_finding CA-AWS-SG-PUBLIC AWS pass info 'Public security-group ingress constrained' 'All collected public ingress is limited to the configured single TCP ports.'
    else ca_finding CA-AWS-SG-PUBLIC AWS fail high 'Public administrative security-group ingress found' "Collected security groups contain $public_exposure public ingress rule(s) outside the configured allow-list."; fi
}

ca_check_azure() {
    if ! ca_command_exists az; then ca_finding CA-AZ-001 Azure unknown medium 'Azure CLI unavailable' 'Install Azure CLI to run Azure checks.'; return; fi
    if [[ "$CLAUDIT_CONFIRM_CONNECTION" -ne 1 ]]; then ca_finding CA-AZ-002 Azure unknown info 'Azure connection not confirmed' 'Use --confirm-tenant-connection to permit read-only Azure API calls.'; return; fi
    local args=(); [[ -n "$CLAUDIT_AZURE_SUBSCRIPTION" ]] && args+=(--subscription "$CLAUDIT_AZURE_SUBSCRIPTION")
    local identity role_assignments storage_accounts key_vaults subscription required_categories covered_categories missing_categories provider_cap
    provider_cap="$(ca_baseline_get '.Inventory.MaxAssetsPerProvider')"
    if ! identity="$(ca_run_cli az account show "${args[@]}" --output json 2>/dev/null)"; then ca_finding CA-AZ-002 Azure unknown high 'Azure subscription unavailable' 'Azure CLI could not read the selected subscription within the command deadline.'; return
    elif jq -e '(.id | type == "string" and length > 0) and (.tenantId | type == "string" and length > 0)' >/dev/null 2>&1 <<<"$identity"; then
        subscription="$(jq -r .id <<<"$identity")"
        jq -cn --arg subscription "$subscription" --arg tenant "$(jq -r .tenantId <<<"$identity")" '{subscription:$subscription,tenant:$tenant}' > "$CLAUDIT_OUTPUT_DIRECTORY/claudit-azure-identity.json"
        ca_finding CA-AZ-002 Azure pass info 'Azure subscription context verified' 'Azure CLI returned a bound subscription and tenant context; see claudit-azure-identity.json.'
    else ca_finding CA-AZ-002 Azure error high 'Azure subscription response malformed' 'Azure returned no usable subscription and tenant identity.'; fi
    local response
    required_categories="$(ca_baseline_get '.Azure.RequiredActivityLogCategories')"
    if ! response="$(ca_run_cli az monitor activity-log alert list "${args[@]}" --output json 2>/dev/null)"; then ca_finding CA-AZ-ACTIVITY Azure unknown medium 'Activity-log collection unavailable' 'Azure did not return a successful collection within the command deadline.'
    elif ! jq -e '
      def leaf_valid:
        type == "object" and (.field | type == "string" and length > 0) and
        (((has("equals") and (.equals | type == "string" and length > 0))) or
         ((has("containsAny") and (.containsAny | type == "array" and length > 0 and all(.[]; type == "string" and length > 0)))));
      def condition_valid:
        type == "object" and
        (if has("anyOf") then (.anyOf | type == "array" and length > 0 and all(.[]; leaf_valid)) else leaf_valid end);
      type == "array" and all(.[];
        (.properties.enabled | type == "boolean") and
        (.properties.scopes | type == "array" and all(.[]; type == "string" and length > 0)) and
        (.properties.condition.allOf | type == "array" and length > 0 and all(.[]; condition_valid)) and
        (.properties.actions.actionGroups | type == "array" and all(.[]; .actionGroupId | type == "string")))
    ' >/dev/null 2>&1 <<<"$response"; then ca_finding CA-AZ-ACTIVITY Azure error medium 'Activity-log response malformed' 'Azure returned an Activity Log alert without valid enabled, scope, condition or action-group fields.'
    elif (( $(jq length <<<"$response") > provider_cap )); then ca_finding CA-AZ-ACTIVITY Azure unknown high 'Activity-log collection exceeds evidence bound' "More than $provider_cap Activity Log alerts were returned; narrow the authorized scope before evaluation."
    elif [[ -z "${subscription:-}" ]]; then ca_finding CA-AZ-ACTIVITY Azure unknown high 'Activity-log scope unverified' 'The subscription identity was unavailable, so alert scope could not be bound to the selected subscription.'
    elif [[ "$(jq 'length' <<<"$required_categories")" == 0 ]]; then ca_finding CA-AZ-ACTIVITY Azure info info 'Activity-log category policy not required' 'The local baseline does not require Activity Log alert categories.'
    else
        covered_categories="$(jq -c --arg subscription "$subscription" '
          def leaves: if has("anyOf") then .anyOf[] else . end;
          ("subscriptions/" + ($subscription | ascii_downcase)) as $scope |
          [.[] | select(
              .properties.enabled == true and
              any(.properties.scopes[]; (ascii_downcase | ltrimstr("/") | startswith($scope))) and
              any(.properties.actions.actionGroups[]; (.actionGroupId | length) > 0)) |
            .properties.condition.allOf[] | leaves |
            select((.field | ascii_downcase) == "category") |
            (.equals // .containsAny[]?) | ascii_downcase] | unique
        ' <<<"$response")"
        missing_categories="$(jq -c --argjson covered "$covered_categories" '[.[] as $category | select(($covered | index($category | ascii_downcase)) == null) | $category]' <<<"$required_categories")"
        if [[ "$(jq 'length' <<<"$missing_categories")" == 0 ]]; then
            ca_finding CA-AZ-ACTIVITY Azure pass info 'Activity-log alert coverage verified' "Enabled, actionable alerts scoped to subscription $subscription cover all required categories: $(jq -r 'join(", ")' <<<"$required_categories")."
        else
            ca_finding CA-AZ-ACTIVITY Azure fail high 'Activity-log alert coverage incomplete' "No enabled, actionable alert scoped to subscription $subscription covers: $(jq -r 'join(", ")' <<<"$missing_categories")."
        fi
    fi

    if ! role_assignments="$(ca_run_cli az role assignment list "${args[@]}" --all --include-inherited --output json 2>/dev/null)"; then ca_finding CA-AZ-ROLE Azure unknown high 'Azure role collection unavailable' 'Azure could not return role assignments within the command deadline; privileged access remains unassessed.'
    elif ! jq -e 'type == "array" and all(.[]; (.roleDefinitionName | type == "string") and (.principalId | type == "string"))' >/dev/null 2>&1 <<<"$role_assignments"; then ca_finding CA-AZ-ROLE Azure error high 'Azure role response malformed' 'Azure returned an unexpected role-assignment response.'
    elif (( $(jq length <<<"$role_assignments") > provider_cap )); then ca_finding CA-AZ-ROLE Azure unknown high 'Azure role collection exceeds evidence bound' "More than $provider_cap role assignments were returned; narrow scope before privileged-role evaluation."
    elif jq -e --argjson roles "$(ca_baseline_get '.Azure.HighRiskAzureRoles')" --argjson allowed "$(ca_baseline_get '.Azure.AllowedPrivilegedPrincipalIds')" '[.[] | . as $assignment | select(($roles | index($assignment.roleDefinitionName)) and ($allowed | index($assignment.principalId) | not))] | length == 0' >/dev/null <<<"$role_assignments"; then ca_finding CA-AZ-ROLE Azure pass info 'Azure privileged roles constrained' 'No collected high-risk Azure role assignment is outside the configured principal allow-list.'
    else ca_finding CA-AZ-ROLE Azure fail high 'Unapproved Azure privileged role assignment' 'One or more collected high-risk Azure role assignments are outside the configured principal allow-list.'; fi

    if ! storage_accounts="$(ca_run_cli az storage account list "${args[@]}" --output json 2>/dev/null)"; then ca_finding CA-AZ-STORAGE-NETWORK Azure unknown high 'Azure storage collection unavailable' 'Azure could not return storage accounts within the command deadline; network defaults remain unassessed.'
    elif ! jq -e 'type == "array" and all(.[]; (.networkRuleSet.defaultAction | type == "string"))' >/dev/null 2>&1 <<<"$storage_accounts"; then ca_finding CA-AZ-STORAGE-NETWORK Azure error high 'Azure storage response malformed' 'A returned storage account lacks a network default-action value.'
    elif (( $(jq length <<<"$storage_accounts") > provider_cap )); then ca_finding CA-AZ-STORAGE-NETWORK Azure unknown high 'Azure storage collection exceeds evidence bound' "More than $provider_cap storage accounts were returned; narrow scope before evaluation."
    elif ! ca_baseline_enabled '.Azure.RequireStorageDefaultDeny'; then ca_finding CA-AZ-STORAGE-NETWORK Azure info info 'Azure storage default-deny policy not required' 'The local baseline does not require storage default action Deny.'
    elif jq -e 'all(.[]; .networkRuleSet.defaultAction == "Deny")' >/dev/null <<<"$storage_accounts"; then ca_finding CA-AZ-STORAGE-NETWORK Azure pass info 'Azure storage network default deny enabled' 'All collected storage accounts report network default action Deny.'
    else ca_finding CA-AZ-STORAGE-NETWORK Azure fail high 'Azure storage network default allow found' 'One or more collected storage accounts do not report network default action Deny.'; fi

    if ! key_vaults="$(ca_run_cli az keyvault list "${args[@]}" --output json 2>/dev/null)"; then ca_finding CA-AZ-KEYVAULT-PURGE Azure unknown high 'Key Vault collection unavailable' 'Azure could not return Key Vaults within the command deadline; purge protection remains unassessed.'
    elif ! jq -e 'type == "array" and all(.[]; (.properties.enablePurgeProtection | type == "boolean"))' >/dev/null 2>&1 <<<"$key_vaults"; then ca_finding CA-AZ-KEYVAULT-PURGE Azure error high 'Key Vault response malformed' 'A returned Key Vault lacks a boolean purge-protection value.'
    elif (( $(jq length <<<"$key_vaults") > provider_cap )); then ca_finding CA-AZ-KEYVAULT-PURGE Azure unknown high 'Key Vault collection exceeds evidence bound' "More than $provider_cap Key Vaults were returned; narrow scope before evaluation."
    elif ! ca_baseline_enabled '.Azure.RequireKeyVaultPurgeProtection'; then ca_finding CA-AZ-KEYVAULT-PURGE Azure info info 'Key Vault purge-protection policy not required' 'The local baseline does not require Key Vault purge protection.'
    elif jq -e 'all(.[]; .properties.enablePurgeProtection == true)' >/dev/null <<<"$key_vaults"; then ca_finding CA-AZ-KEYVAULT-PURGE Azure pass info 'Key Vault purge protection enabled' 'All collected Key Vaults report purge protection enabled.'
    else ca_finding CA-AZ-KEYVAULT-PURGE Azure fail high 'Key Vault purge protection disabled' 'One or more collected Key Vaults do not report purge protection enabled.'; fi
}

ca_check_gcp() {
    if ! ca_command_exists gcloud; then ca_finding CA-GCP-001 GCP unknown medium 'gcloud unavailable' 'Install Google Cloud CLI to run GCP checks.'; return; fi
    if [[ "$CLAUDIT_CONFIRM_CONNECTION" -ne 1 ]]; then ca_finding CA-GCP-002 GCP unknown info 'GCP connection not confirmed' 'Use --confirm-tenant-connection to permit read-only GCP API calls.'; return; fi
    [[ -n "$CLAUDIT_GCP_PROJECT" ]] || { ca_finding CA-GCP-002 GCP unknown medium 'GCP project required' 'Provide --gcp-project for GCP checks.'; return; }
    local response project iam metadata service_accounts service_account key_response key_created key_epoch key_age now_epoch stale_keys=0 active_keys=0 provider_cap provider_limit
    provider_cap="$(ca_baseline_get '.Inventory.MaxAssetsPerProvider')"; provider_limit=$((provider_cap + 1))
    if ! project="$(ca_run_cli gcloud projects describe "$CLAUDIT_GCP_PROJECT" --format=json 2>/dev/null)"; then ca_finding CA-GCP-002 GCP unknown high 'GCP project unavailable' 'gcloud cannot read the selected project within the command deadline.'; return
    elif jq -e --arg project "$CLAUDIT_GCP_PROJECT" '(.projectId | type == "string") and .projectId == $project and (.projectNumber | type == "string" or type == "number")' >/dev/null 2>&1 <<<"$project"; then
        jq -cn --arg project "$(jq -r .projectId <<<"$project")" --arg number "$(jq -r .projectNumber <<<"$project")" '{project:$project,project_number:$number}' > "$CLAUDIT_OUTPUT_DIRECTORY/claudit-gcp-identity.json"
        ca_finding CA-GCP-002 GCP pass info 'GCP project verified' 'gcloud returned the selected project identity; see claudit-gcp-identity.json.'
    else ca_finding CA-GCP-002 GCP error high 'GCP project response malformed' 'gcloud returned no usable selected project identity.'; fi
    if ! response="$(ca_run_cli gcloud logging sinks list --project "$CLAUDIT_GCP_PROJECT" --limit "$provider_limit" --format=json 2>/dev/null)"; then ca_finding CA-GCP-LOGGING GCP unknown medium 'Logging sink collection unavailable' 'GCP did not return a successful collection within the command deadline.'
    elif ! jq -e 'type == "array" and all(.[]; (.name | type == "string") and (.destination | type == "string") and ((.disabled? // false) | type == "boolean"))' >/dev/null 2>&1 <<<"$response"; then ca_finding CA-GCP-LOGGING GCP error medium 'Logging response malformed' 'A returned logging sink lacks a valid name, destination or disabled state.'
    elif (( $(jq length <<<"$response") > provider_cap )); then ca_finding CA-GCP-LOGGING GCP unknown high 'Logging sink collection exceeds evidence bound' "More than $provider_cap logging sinks were returned; narrow scope before evaluation."
    elif ! ca_baseline_enabled '.GCP.RequireCentralLogSink'; then ca_finding CA-GCP-LOGGING GCP info info 'Central logging sink policy not required' 'The local baseline does not require a central logging sink.'
    elif jq -e '[.[] | select((.name | startswith("_") | not) and (.disabled? // false) == false and (.destination | length > 0))] | length > 0' >/dev/null <<<"$response"; then ca_finding CA-GCP-LOGGING GCP pass info 'Central logging sink configured' 'At least one enabled user-managed logging sink has an explicit destination.'
    else ca_finding CA-GCP-LOGGING GCP fail high 'Central logging sink missing' 'No enabled user-managed logging sink with an explicit destination was returned.'; fi

    if ! iam="$(ca_run_cli gcloud projects get-iam-policy "$CLAUDIT_GCP_PROJECT" --format=json 2>/dev/null)"; then ca_finding CA-GCP-IAM-PRIMITIVE GCP unknown high 'GCP IAM collection unavailable' 'gcloud could not return the project IAM policy within the command deadline.'
    elif ! jq -e '(.bindings | type == "array") and all(.bindings[]?; (.role | type == "string") and (.members | type == "array") and all(.members[]?; type == "string"))' >/dev/null 2>&1 <<<"$iam"; then ca_finding CA-GCP-IAM-PRIMITIVE GCP error high 'GCP IAM response malformed' 'gcloud returned an unexpected IAM policy response.'
    elif jq -e --argjson allowed "$(ca_baseline_get '.GCP.AllowedPrimitiveRoleMembers')" '[.bindings[]? | select(.role == "roles/owner" or .role == "roles/editor" or .role == "roles/viewer") | .members[]? | . as $member | select($allowed | index($member) | not)] | length == 0' >/dev/null <<<"$iam"; then ca_finding CA-GCP-IAM-PRIMITIVE GCP pass info 'GCP primitive IAM roles constrained' 'No collected primitive IAM role member is outside the configured allow-list.'
    else ca_finding CA-GCP-IAM-PRIMITIVE GCP fail high 'Unapproved GCP primitive IAM member' 'A collected primitive IAM role has a member outside the configured allow-list.'; fi

    if ! jq -e '(.auditConfigs // []) | type == "array" and all(.[]; (.service | type == "string") and (.auditLogConfigs | type == "array") and all(.auditLogConfigs[]?; (.logType | type == "string")))' >/dev/null 2>&1 <<<"$iam"; then ca_finding CA-GCP-AUDIT-LOGS GCP error high 'GCP audit-log response malformed' 'The IAM policy has malformed audit configuration evidence.'
    elif jq -e --argjson required "$(ca_baseline_get '.GCP.RequiredAuditLogTypes')" '([.auditConfigs[]? | select(.service == "allServices") | .auditLogConfigs[]?.logType] | unique) as $enabled | ($required - $enabled | length == 0)' >/dev/null <<<"$iam"; then ca_finding CA-GCP-AUDIT-LOGS GCP pass info 'GCP required audit logs enabled' 'The allServices audit configuration contains every log type required by the baseline.'
    else ca_finding CA-GCP-AUDIT-LOGS GCP fail high 'GCP required audit logs incomplete' 'The allServices audit configuration is missing one or more required log types.'; fi

    if ! metadata="$(ca_run_cli gcloud compute project-info describe --project "$CLAUDIT_GCP_PROJECT" --format=json 2>/dev/null)"; then ca_finding CA-GCP-OSLOGIN GCP unknown high 'GCP OS Login collection unavailable' 'gcloud could not return project common instance metadata within the command deadline.'
    elif ! jq -e '(.commonInstanceMetadata.items | type == "array") and all(.commonInstanceMetadata.items[]?; (.key | type == "string") and (.value | type == "string"))' >/dev/null 2>&1 <<<"$metadata"; then ca_finding CA-GCP-OSLOGIN GCP error high 'GCP OS Login response malformed' 'gcloud returned unexpected project common instance metadata.'
    elif ! ca_baseline_enabled '.GCP.RequireOsLogin'; then ca_finding CA-GCP-OSLOGIN GCP info info 'GCP OS Login policy not required' 'The local baseline does not require OS Login.'
    elif jq -e '[.commonInstanceMetadata.items[]? | select(.key == "enable-oslogin") | .value | ascii_downcase] | index("true") != null' >/dev/null <<<"$metadata"; then ca_finding CA-GCP-OSLOGIN GCP pass info 'GCP OS Login enabled' 'Project common instance metadata enables OS Login.'
    else ca_finding CA-GCP-OSLOGIN GCP fail high 'GCP OS Login disabled' 'Project common instance metadata does not enable OS Login.'; fi

    if ! service_accounts="$(ca_run_cli gcloud iam service-accounts list --project "$CLAUDIT_GCP_PROJECT" --limit "$provider_limit" --format=json 2>/dev/null)"; then ca_finding CA-GCP-SA-KEY-AGE GCP unknown high 'GCP service-account collection unavailable' 'gcloud could not return service accounts within the command deadline; key age remains unassessed.'
    elif ! jq -e 'type == "array" and all(.[]; (.email | type == "string" and length > 0))' >/dev/null 2>&1 <<<"$service_accounts"; then ca_finding CA-GCP-SA-KEY-AGE GCP error high 'GCP service-account response malformed' 'gcloud returned unexpected service-account data.'
    elif (( $(jq length <<<"$service_accounts") > provider_cap )); then ca_finding CA-GCP-SA-KEY-AGE GCP unknown high 'GCP service-account collection exceeds evidence bound' "More than $provider_cap service accounts were returned; key age remains unassessed."
    else
        now_epoch="$(date -u +%s)"
        while IFS= read -r service_account; do
            if ! key_response="$(ca_run_cli gcloud iam service-accounts keys list --iam-account "$service_account" --managed-by=user --limit "$provider_limit" --format=json 2>/dev/null)"; then ca_finding CA-GCP-SA-KEY-AGE GCP unknown high 'GCP service-account key collection unavailable' 'gcloud could not return all user-managed service-account keys within the command deadline.'; service_accounts=''; break; fi
            if ! jq -e 'type == "array" and all(.[]; (.validAfterTime | type == "string") and ((.disabled? // false) | type == "boolean"))' >/dev/null 2>&1 <<<"$key_response"; then ca_finding CA-GCP-SA-KEY-AGE GCP error high 'GCP service-account key response malformed' 'gcloud returned unexpected service-account key metadata.'; service_accounts=''; break; fi
            if (( $(jq length <<<"$key_response") > provider_cap )); then ca_finding CA-GCP-SA-KEY-AGE GCP unknown high 'GCP service-account key collection exceeds evidence bound' "More than $provider_cap keys were returned for one service account; key age remains unassessed."; service_accounts=''; break; fi
            while IFS= read -r key_created; do
                active_keys=$((active_keys + 1))
                key_epoch="$(date -u -d "$key_created" +%s 2>/dev/null || true)"
                if [[ ! "$key_epoch" =~ ^[0-9]+$ ]] || (( key_epoch > now_epoch )); then ca_finding CA-GCP-SA-KEY-AGE GCP error high 'GCP service-account key timestamp malformed' 'An enabled user-managed key has an invalid or future creation timestamp.'; service_accounts=''; break 2; fi
                key_age=$(((now_epoch - key_epoch) / 86400))
                (( key_age <= $(ca_baseline_get '.GCP.MaxServiceAccountKeyAgeDays') )) || stale_keys=$((stale_keys + 1))
            done < <(jq -r '.[] | select((.disabled? // false) == false) | .validAfterTime' <<<"$key_response")
        done < <(jq -r '.[].email' <<<"$service_accounts")
        if [[ -n "$service_accounts" ]]; then
            if (( stale_keys == 0 )); then ca_finding CA-GCP-SA-KEY-AGE GCP pass info 'GCP service-account key ages within baseline' "Assessed $active_keys enabled user-managed service-account key(s); none exceed the configured maximum age."
            else ca_finding CA-GCP-SA-KEY-AGE GCP fail high 'Stale GCP service-account keys found' "$stale_keys of $active_keys enabled user-managed service-account key(s) exceed the configured maximum age."; fi
        fi
    fi
}

ca_check_tailscale() {
    if [[ "$CLAUDIT_CONFIRM_CONNECTION" -ne 1 ]]; then ca_finding CA-TS-001 Tailscale unknown info 'Tailscale connection not confirmed' 'Use --confirm-tenant-connection to permit read-only API calls.'; return; fi
    if [[ -z "${CLAUDIT_TAILSCALE_TOKEN:-}" ]]; then ca_finding CA-TS-001 Tailscale unknown medium 'Tailscale token unavailable' 'Set CLAUDIT_TAILSCALE_TOKEN outside the repository.'; return; fi
    if curl --fail --silent --show-error --max-time 15 -H "Authorization: Bearer $CLAUDIT_TAILSCALE_TOKEN" "https://api.tailscale.com/api/v2/tailnet/$CLAUDIT_TAILSCALE_TAILNET/devices" | jq -e . >/dev/null; then ca_finding CA-TS-001 Tailscale pass info 'Tailscale API reachable' 'The authorized tailnet device inventory was read successfully.'; else ca_finding CA-TS-001 Tailscale unknown high 'Tailscale API unavailable' 'The tailnet inventory could not be retrieved.'; fi
}
