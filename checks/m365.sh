#!/usr/bin/env bash
ca_graph_get() { curl --fail --silent --show-error --max-time 20 -H "Authorization: Bearer $1" -H 'Accept: application/json' "https://graph.microsoft.com/v1.0$2"; }
ca_graph_get_all() {
    local token="$1" path="$2" response next page=0 values='[]'
    while :; do
        page=$((page + 1))
        response="$(ca_graph_get "$token" "$path")" || return 1
        jq -e '(.value | type == "array") and ((.["@odata.nextLink"]? // null) | type == "string" or type == "null")' >/dev/null 2>&1 <<<"$response" || return 2
        values="$(jq -cn --argjson previous "$values" --argjson current "$response" '$previous + $current.value')"
        next="$(jq -r '.["@odata.nextLink"] // empty' <<<"$response")"
        [[ -z "$next" ]] && break
        [[ "$next" == https://graph.microsoft.com/v1.0/* ]] || return 2
        (( page < 10 )) || return 3
        path="${next#https://graph.microsoft.com/v1.0}"
    done
    jq -cn --argjson values "$values" '{value:$values}'
}
ca_check_m365() {
    local token response graph_status auth_policy security_defaults ca_policies role_defs role_assignments role_id
    if [[ "$CLAUDIT_CONFIRM_CONNECTION" -ne 1 ]]; then ca_finding CA-M365-001 M365 unknown info 'Microsoft 365 connection not confirmed' 'Use --confirm-tenant-connection to permit Microsoft Graph calls.'; return; fi
    token="${CLAUDIT_GRAPH_TOKEN:-}"
    if [[ -z "$token" ]] && ca_command_exists az; then token="$(ca_run_cli az account get-access-token --resource-type ms-graph --query accessToken -o tsv 2>/dev/null || true)"; fi
    if [[ -z "$token" ]]; then ca_finding CA-M365-001 M365 unknown high 'Microsoft Graph token unavailable' 'Set CLAUDIT_GRAPH_TOKEN or authenticate with Azure CLI; no secret is stored by Claudit.'; return; fi
    response="$(ca_graph_get "$token" "/organization?\$select=id,displayName" 2>/dev/null || true)"
    # Used by report scope and finding identity after this collector returns.
    # shellcheck disable=SC2034
    if jq -e '.value | length == 1 and (.[0].id | type == "string" and length > 0)' >/dev/null 2>&1 <<<"$response"; then CLAUDIT_M365_TENANT_ID="$(jq -r '.value[0].id' <<<"$response")"; ca_finding CA-M365-001 M365 pass info 'Microsoft Graph organization access verified' 'Microsoft Graph returned one bound authorized organization.'; else ca_finding CA-M365-001 M365 unknown high 'Microsoft Graph organization unavailable' 'Graph did not return one unambiguous authorized organization.'; return; fi
    if ca_selected M365 || ca_selected Entra; then
    auth_policy="$(ca_graph_get "$token" '/policies/authorizationPolicy' 2>/dev/null || true)"
    if jq -e '.allowedToSignUpEmailBasedSubscriptions == false' >/dev/null 2>&1 <<<"$auth_policy"; then ca_finding CA-ENTRA-001 Entra pass info 'Self-service email subscriptions restricted' 'Authorization policy disables email-based self-service subscriptions.'; elif jq -e '.allowedToSignUpEmailBasedSubscriptions | type == "boolean"' >/dev/null 2>&1 <<<"$auth_policy"; then ca_finding CA-ENTRA-001 Entra fail medium 'Self-service email subscriptions allowed' 'Authorization policy permits email-based self-service subscriptions.'; else ca_finding CA-ENTRA-001 Entra unknown medium 'Authorization policy not verified' 'The authorization policy is unavailable or malformed.'; fi
    security_defaults="$(ca_graph_get "$token" '/policies/identitySecurityDefaultsEnforcementPolicy' 2>/dev/null || true)"
    if ca_policies="$(ca_graph_get_all "$token" "/identity/conditionalAccess/policies?\$select=id,state,conditions,grantControls" 2>/dev/null)"; then
        if ! jq -e 'all(.value[]; (.state | type == "string") and (.conditions | type == "object") and (.grantControls | type == "object" or type == "null"))' >/dev/null 2>&1 <<<"$ca_policies"; then
            ca_finding CA-ENTRA-CA Entra error high 'Conditional Access response malformed' 'A returned Conditional Access policy lacks the fields required for evaluation.'
            ca_finding CA-ENTRA-MFA-ADMINS Entra error high 'Privileged MFA response malformed' 'Conditional Access evidence cannot be evaluated for privileged-role MFA.'
            ca_finding CA-ENTRA-LEGACY Entra error high 'Legacy authentication response malformed' 'Conditional Access evidence cannot be evaluated for legacy authentication blocking.'
        else
            if ! ca_baseline_enabled '.Entra.RequireSecurityDefaultsOrConditionalAccess'; then ca_finding CA-ENTRA-CA Entra info info 'Identity foundation policy not required' 'The local baseline does not require Security Defaults or Conditional Access.'
            elif jq -e '.isEnabled == true' >/dev/null 2>&1 <<<"$security_defaults" || jq -e '[.value[] | select(.state == "enabled")] | length > 0' >/dev/null <<<"$ca_policies"; then ca_finding CA-ENTRA-CA Entra pass info 'Identity foundation policy enabled' 'Security Defaults or at least one enabled Conditional Access policy was returned.'
            elif jq -e '.isEnabled | type == "boolean"' >/dev/null 2>&1 <<<"$security_defaults"; then ca_finding CA-ENTRA-CA Entra fail high 'Identity foundation policy absent' 'Security Defaults are disabled and no enabled Conditional Access policy was returned.'
            else ca_finding CA-ENTRA-CA Entra unknown high 'Security Defaults unavailable' 'Conditional Access is empty and the Security Defaults setting could not be verified.'; fi

            if ! ca_baseline_enabled '.Entra.RequireMfaForAdmins'; then ca_finding CA-ENTRA-MFA-ADMINS Entra info info 'Privileged MFA policy not required' 'The local baseline does not require MFA for administrators.'
            elif jq -e '.isEnabled == true' >/dev/null 2>&1 <<<"$security_defaults" || jq -e '[.value[] | select(.state == "enabled" and ((((.conditions.users.includeUsers // []) | index("All")) != null) or (((.conditions.users.includeRoles // []) | index("62e90394-69f5-4237-9190-012177145e10")) != null)) and (((.grantControls.builtInControls // []) | index("mfa")) != null or (.grantControls.authenticationStrength != null)))] | length > 0' >/dev/null <<<"$ca_policies"; then ca_finding CA-ENTRA-MFA-ADMINS Entra pass info 'Global Administrator MFA policy present' 'Security Defaults or an enabled policy for all users or the Global Administrator role requires MFA or authentication strength.'
            else ca_finding CA-ENTRA-MFA-ADMINS Entra fail critical 'Privileged-role MFA policy absent' 'No enabled privileged-role Conditional Access MFA policy and no enabled Security Defaults policy was returned.'; fi

            if ! ca_baseline_enabled '.Entra.BlockLegacyAuthentication'; then ca_finding CA-ENTRA-LEGACY Entra info info 'Legacy authentication block not required' 'The local baseline does not require a tenant-wide legacy authentication block.'
            elif jq -e '.isEnabled == true' >/dev/null 2>&1 <<<"$security_defaults" || jq -e '[.value[] | select(.state == "enabled" and (((.conditions.users.includeUsers // []) | index("All")) != null) and (((.conditions.clientAppTypes // []) | index("exchangeActiveSync")) != null) and (((.conditions.clientAppTypes // []) | index("other")) != null) and (((.grantControls.builtInControls // []) | index("block")) != null))] | length > 0' >/dev/null <<<"$ca_policies"; then ca_finding CA-ENTRA-LEGACY Entra pass info 'Legacy authentication blocked' 'Security Defaults or an enabled all-user Conditional Access policy blocks the legacy client types.'
            else ca_finding CA-ENTRA-LEGACY Entra fail high 'Legacy authentication not blocked' 'No complete enabled policy blocks legacy client types for all users.'; fi
        fi
    else
        graph_status=$?
        case "$graph_status" in
            1) graph_status='collection unavailable' ;;
            2) graph_status='malformed response or untrusted continuation' ;;
            3) graph_status='ten-page bound exceeded' ;;
        esac
        ca_finding CA-ENTRA-CA Entra unknown high 'Conditional Access collection incomplete' "Conditional Access evaluation stopped: $graph_status."
        ca_finding CA-ENTRA-MFA-ADMINS Entra unknown high 'Privileged MFA collection incomplete' "Privileged-role MFA evaluation stopped: $graph_status."
        ca_finding CA-ENTRA-LEGACY Entra unknown high 'Legacy authentication collection incomplete' "Legacy authentication evaluation stopped: $graph_status."
    fi

    if jq -e '(.allowInvitesFrom | type == "string") and (.defaultUserRolePermissions.allowedToCreateApps | type == "boolean") and (.permissionGrantPolicyIdsAssignedToDefaultUserRole | type == "array")' >/dev/null 2>&1 <<<"$auth_policy"; then
        if jq -e --argjson allowed "$(ca_baseline_get '.Entra.AllowedInviteFrom')" '.allowInvitesFrom as $actual | $allowed | index($actual) != null' >/dev/null <<<"$auth_policy"; then ca_finding CA-ENTRA-INVITES Entra pass info 'Guest invitation policy within baseline' 'The tenant invitation setting is explicitly allowed by the baseline.'; else ca_finding CA-ENTRA-INVITES Entra fail medium 'Guest invitation policy too broad' 'The tenant invitation setting is outside the baseline allow-list.'; fi
        if jq -e --argjson expected "$(ca_baseline_get '.Entra.AllowUsersToRegisterApplications')" '.defaultUserRolePermissions.allowedToCreateApps == $expected' >/dev/null <<<"$auth_policy"; then ca_finding CA-ENTRA-APP-REG Entra pass info 'Application registration policy matches baseline' 'Default-user application creation matches the configured policy.'; else ca_finding CA-ENTRA-APP-REG Entra fail high 'Application registration policy differs' 'Default-user application creation differs from the configured policy.'; fi
        if ca_baseline_enabled '.Entra.AllowUsersToConsentForApps'; then
            if jq -e '.permissionGrantPolicyIdsAssignedToDefaultUserRole | length > 0' >/dev/null <<<"$auth_policy"; then ca_finding CA-ENTRA-CONSENT Entra pass info 'User application consent policy present' 'At least one permission grant policy is assigned to the default user role.'; else ca_finding CA-ENTRA-CONSENT Entra fail medium 'User application consent unavailable' 'The baseline allows user consent but no default-user permission grant policy is assigned.'; fi
        elif jq -e '.permissionGrantPolicyIdsAssignedToDefaultUserRole | length == 0' >/dev/null <<<"$auth_policy"; then ca_finding CA-ENTRA-CONSENT Entra pass info 'User application consent disabled' 'No permission grant policy is assigned to the default user role.'
        else ca_finding CA-ENTRA-CONSENT Entra fail high 'User application consent enabled' 'One or more permission grant policies permit default-user consent contrary to baseline.'; fi
    else
        ca_finding CA-ENTRA-INVITES Entra unknown medium 'Guest invitation policy unavailable' 'Authorization policy fields required for guest invitation evaluation are unavailable.'
        ca_finding CA-ENTRA-APP-REG Entra unknown medium 'Application registration policy unavailable' 'Authorization policy fields required for application registration evaluation are unavailable.'
        ca_finding CA-ENTRA-CONSENT Entra unknown medium 'Application consent policy unavailable' 'Authorization policy fields required for user consent evaluation are unavailable.'
    fi

    role_defs="$(ca_graph_get "$token" "/roleManagement/directory/roleDefinitions?\$filter=displayName%20eq%20'Global%20Administrator'%26\$select=id,displayName" 2>/dev/null || true)"
    if jq -e '.value | type == "array" and length == 1 and (.[0].id | type == "string" and length > 0)' >/dev/null 2>&1 <<<"$role_defs"; then
        role_id="$(jq -r '.value[0].id' <<<"$role_defs")"
        if role_assignments="$(ca_graph_get_all "$token" "/roleManagement/directory/roleAssignments?\$filter=roleDefinitionId%20eq%20'$role_id'%26\$select=id,principalId,roleDefinitionId" 2>/dev/null)" && jq -e --arg role "$role_id" 'all(.value[]; (.id | type == "string") and (.principalId | type == "string") and .roleDefinitionId == $role)' >/dev/null 2>&1 <<<"$role_assignments"; then
            if (( $(jq '.value | length' <<<"$role_assignments") <= $(ca_baseline_get '.Entra.MaxGlobalAdministrators') )); then ca_finding CA-ENTRA-GLOBAL-ADMINS Entra pass info 'Global Administrator count within baseline' "The complete bounded collection is within the configured maximum of $(ca_baseline_get '.Entra.MaxGlobalAdministrators')."; else ca_finding CA-ENTRA-GLOBAL-ADMINS Entra fail critical 'Too many Global Administrators' 'The complete bounded role-assignment collection exceeds the configured maximum.'; fi
        else ca_finding CA-ENTRA-GLOBAL-ADMINS Entra unknown high 'Global Administrator assignments unavailable' 'The complete bounded Global Administrator assignment collection could not be verified.'; fi
    else ca_finding CA-ENTRA-GLOBAL-ADMINS Entra unknown high 'Global Administrator role unavailable' 'Microsoft Graph did not return one unambiguous Global Administrator role definition.'; fi
    fi
    if ca_selected M365 || ca_selected SharePoint || ca_selected OneDrive; then
    response="$(ca_graph_get "$token" '/admin/sharepoint/settings' 2>/dev/null || true)"
    if jq -e 'type == "object" and (.error == null) and (.sharingCapability | type == "string")' >/dev/null 2>&1 <<<"$response"; then
        local expected_sharing actual_sharing expected_rank actual_rank
        expected_sharing="$(ca_baseline_get '.SharePoint.MaxSharingCapability' | tr -d '"')"
        actual_sharing="$(jq -r '.sharingCapability // empty' <<<"$response")"
        case "$expected_sharing" in disabled) expected_rank=0;; existingExternalUserSharingOnly) expected_rank=1;; externalUserSharingOnly) expected_rank=2;; externalUserAndGuestSharing) expected_rank=3;; *) expected_rank=99;; esac
        case "$actual_sharing" in disabled) actual_rank=0;; existingExternalUserSharingOnly) actual_rank=1;; externalUserSharingOnly) actual_rank=2;; externalUserAndGuestSharing) actual_rank=3;; *) actual_rank=99;; esac
        if (( actual_rank == 99 || expected_rank == 99 )); then ca_finding CA-SPO-SHARING SharePoint unknown medium 'SharePoint sharing value unrecognized' 'The expected or observed sharing enum cannot be evaluated.'; elif (( actual_rank <= expected_rank )); then ca_finding CA-SPO-SHARING SharePoint pass info 'SharePoint sharing within baseline' "Tenant sharing capability '$actual_sharing' does not exceed baseline '$expected_sharing'."; else ca_finding CA-SPO-SHARING SharePoint fail high 'SharePoint sharing exceeds baseline' "Tenant sharing capability '$actual_sharing' exceeds baseline '$expected_sharing'."; fi
        if ca_baseline_enabled '.SharePoint.BlockLegacyAuthProtocols'; then if ! jq -e '.isLegacyAuthProtocolsEnabled | type == "boolean"' >/dev/null <<<"$response"; then ca_finding CA-SPO-LEGACY SharePoint unknown medium 'Setting unavailable' 'Graph omitted or malformed isLegacyAuthProtocolsEnabled.'; elif jq -e '.isLegacyAuthProtocolsEnabled == false'  >/dev/null <<<"$response"; then ca_finding CA-SPO-LEGACY SharePoint pass info 'SharePoint legacy authentication restricted' 'SharePoint settings report legacy authentication disabled.'; else ca_finding CA-SPO-LEGACY SharePoint fail medium 'SharePoint legacy authentication enabled' 'Tenant settings do not confirm that legacy authentication is disabled.'; fi; else ca_finding CA-SPO-LEGACY SharePoint info info 'SharePoint legacy-auth control disabled' 'Baseline does not require this control.'; fi
        if ca_baseline_enabled '.SharePoint.RequireReauthAcceptingUserMatchesInvited'; then if ! jq -e '.isRequireAcceptingUserToMatchInvitedUserEnabled | type == "boolean"' >/dev/null <<<"$response"; then ca_finding CA-SPO-INVITE SharePoint unknown medium 'Setting unavailable' 'Graph omitted or malformed isRequireAcceptingUserToMatchInvitedUserEnabled.'; elif jq -e '.isRequireAcceptingUserToMatchInvitedUserEnabled == true'  >/dev/null <<<"$response"; then ca_finding CA-SPO-INVITE SharePoint pass info 'Guest acceptance identity enforced' 'SharePoint requires the accepting user to match the invited user.'; else ca_finding CA-SPO-INVITE SharePoint fail medium 'Guest acceptance identity not enforced' 'SharePoint does not confirm invited-user identity enforcement.'; fi; else ca_finding CA-SPO-INVITE SharePoint info info 'SharePoint guest-match control disabled' 'Baseline does not require this control.'; fi
        if ca_baseline_enabled '.OneDrive.RestrictUnmanagedDeviceSync'; then if ! jq -e '.isUnmanagedSyncAppForTenantRestricted | type == "boolean"' >/dev/null <<<"$response"; then ca_finding CA-OD-SYNC OneDrive unknown medium 'Setting unavailable' 'Graph omitted or malformed isUnmanagedSyncAppForTenantRestricted.'; elif jq -e '.isUnmanagedSyncAppForTenantRestricted == true'  >/dev/null <<<"$response"; then ca_finding CA-OD-SYNC OneDrive pass info 'OneDrive unmanaged sync restricted' 'Tenant settings restrict sync on unmanaged devices.'; else ca_finding CA-OD-SYNC OneDrive fail high 'OneDrive unmanaged sync unrestricted' 'Tenant settings do not confirm unmanaged-device sync restriction.'; fi; else ca_finding CA-OD-SYNC OneDrive info info 'OneDrive unmanaged-sync control disabled' 'Baseline does not require this control.'; fi
        if ca_baseline_enabled '.OneDrive.RequireBlockedSyncFileExtensions'; then if ! jq -e '.excludedFileExtensionsForSyncApp | type == "array"' >/dev/null <<<"$response"; then ca_finding CA-OD-EXTENSIONS OneDrive unknown medium 'Blocked extensions unavailable' 'Graph omitted or malformed the blocked extension list.'; elif jq -e '.excludedFileExtensionsForSyncApp | length > 0' >/dev/null <<<"$response"; then ca_finding CA-OD-EXTENSIONS OneDrive pass info 'OneDrive sync file extensions blocked' 'Tenant settings contain blocked sync file extensions.'; else ca_finding CA-OD-EXTENSIONS OneDrive fail medium 'OneDrive sync file extensions unrestricted' 'No blocked sync file extensions were returned.'; fi; else ca_finding CA-OD-EXTENSIONS OneDrive info info 'OneDrive extension control disabled' 'Baseline does not require this control.'; fi
        local min_retention retention
        min_retention="$(ca_baseline_get '.OneDrive.MinDeletedUserRetentionDays')"
        retention="$(jq -r '.deletedUserPersonalSiteRetentionPeriodInDays // empty' <<<"$response")"
        if [[ "$retention" =~ ^[0-9]+$ ]] && (( retention >= min_retention )); then ca_finding CA-OD-RETENTION OneDrive pass info 'Deleted-user OneDrive retention meets baseline' "Retention is $retention day(s), minimum is $min_retention."; elif [[ "$retention" =~ ^[0-9]+$ ]]; then ca_finding CA-OD-RETENTION OneDrive fail medium 'Deleted-user OneDrive retention below baseline' "Retention is $retention day(s), below minimum $min_retention."; else ca_finding CA-OD-RETENTION OneDrive unknown medium 'Deleted-user OneDrive retention unavailable' 'The Graph setting was not returned.'; fi
    else
        ca_finding CA-SPO-LEGACY SharePoint unknown medium 'SharePoint settings unavailable' 'Graph SharePoint administration scope is absent or the endpoint is unavailable.'
        ca_finding CA-SPO-SHARING SharePoint unknown medium 'SharePoint sharing setting unavailable' 'Graph SharePoint administration scope is absent or the endpoint is unavailable.'
        ca_finding CA-SPO-INVITE SharePoint unknown medium 'SharePoint guest setting unavailable' 'Graph SharePoint administration scope is absent or the endpoint is unavailable.'
        ca_finding CA-OD-SYNC OneDrive unknown medium 'OneDrive sync setting unavailable' 'Graph SharePoint administration scope is absent or the endpoint is unavailable.'
        ca_finding CA-OD-EXTENSIONS OneDrive unknown medium 'OneDrive extension setting unavailable' 'Graph SharePoint administration scope is absent or the endpoint is unavailable.'
        ca_finding CA-OD-RETENTION OneDrive unknown medium 'OneDrive retention setting unavailable' 'Graph SharePoint administration scope is absent or the endpoint is unavailable.'
    fi
    fi
    if ca_selected M365 || ca_selected OneDrive; then
    response="$(ca_graph_get "$token" "/drives?\$top=1" 2>/dev/null || true)"
    if jq -e '.value | type == "array"' >/dev/null 2>&1 <<<"$response"; then ca_finding CA-OD-ACCESS OneDrive pass info 'OneDrive API scope verified' 'Microsoft Graph returned the authorized drive collection.'; else ca_finding CA-OD-ACCESS OneDrive unknown medium 'OneDrive API scope unavailable' 'Graph could not retrieve the authorized drive collection.'; fi
    fi
}
