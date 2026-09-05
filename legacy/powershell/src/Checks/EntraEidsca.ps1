<#
    EntraEidsca.ps1 - EIDSCA-style Entra ID checks (Entra ID Security Config
    Analyzer, popularised by Maester). These read raw Graph policy endpoints via
    Invoke-CaGraphRequest because they have no first-class cmdlet.

    All functions are named Test-CaEntra* so Get-CaEntraFindings auto-discovers
    them alongside the directory-management checks. Read-only.
#>

function Test-CaEntraAuthenticatorNumberMatching {
    Invoke-CaCheck -Service Entra -CheckId 'ENTRA-010' -Title 'Microsoft Authenticator number matching enforced' -Body {
        $policy = Invoke-CaGraphRequest -Uri 'policies/authenticationMethodsPolicy'
        $auth = $policy.authenticationMethodConfigurations | Where-Object { $_.id -eq 'MicrosoftAuthenticator' }
        if (-not $auth) {
            return New-CaFinding -Service Entra -CheckId 'ENTRA-010' -Title 'Microsoft Authenticator number matching enforced' -Status Skipped `
                -SkippedReason 'Microsoft Authenticator configuration not present.' -Detail 'No MicrosoftAuthenticator method configuration returned.'
        }
        if ($auth.state -ne 'enabled') {
            return New-CaFinding -Service Entra -CheckId 'ENTRA-010' -Title 'Microsoft Authenticator number matching enforced' -Status Info `
                -Detail "Microsoft Authenticator method state is '$($auth.state)'." -Evidence $auth.state
        }
        $nm = $null
        if ($auth.featureSettings -and $auth.featureSettings.numberMatchingRequiredState) {
            $nm = $auth.featureSettings.numberMatchingRequiredState.state
        }
        if ($nm -eq 'enabled') {
            New-CaFinding -Service Entra -CheckId 'ENTRA-010' -Title 'Microsoft Authenticator number matching enforced' -Status Pass `
                -Detail 'Number matching is enabled for all users.' -Evidence $nm
        }
        else {
            New-CaFinding -Service Entra -CheckId 'ENTRA-010' -Title 'Microsoft Authenticator number matching enforced' -Status Fail -Severity High `
                -Detail "Number matching state is '$nm' (expected 'enabled')." -Evidence $nm `
                -Recommendation 'Enforce Authenticator number matching for all users to defeat MFA fatigue/push-bombing.' `
                -Reference 'https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-number-match'
        }
    }
}

function Test-CaEntraAuthenticatorAppContext {
    Invoke-CaCheck -Service Entra -CheckId 'ENTRA-011' -Title 'Authenticator shows application and location context' -Body {
        $policy = Invoke-CaGraphRequest -Uri 'policies/authenticationMethodsPolicy'
        $auth = $policy.authenticationMethodConfigurations | Where-Object { $_.id -eq 'MicrosoftAuthenticator' }
        if (-not $auth -or $auth.state -ne 'enabled') {
            return New-CaFinding -Service Entra -CheckId 'ENTRA-011' -Title 'Authenticator shows application and location context' -Status Skipped `
                -SkippedReason 'Microsoft Authenticator not enabled.' -Detail 'Authenticator method not enabled; context settings not applicable.'
        }
        $appState = $null; $geoState = $null
        if ($auth.featureSettings) {
            if ($auth.featureSettings.displayAppInformationRequiredState) { $appState = $auth.featureSettings.displayAppInformationRequiredState.state }
            if ($auth.featureSettings.displayLocationInformationRequiredState) { $geoState = $auth.featureSettings.displayLocationInformationRequiredState.state }
        }
        if ($appState -eq 'enabled' -and $geoState -eq 'enabled') {
            New-CaFinding -Service Entra -CheckId 'ENTRA-011' -Title 'Authenticator shows application and location context' -Status Pass `
                -Detail 'Application name and geographic location are shown in push approvals.' -Evidence @{ App = $appState; Geo = $geoState }
        }
        else {
            New-CaFinding -Service Entra -CheckId 'ENTRA-011' -Title 'Authenticator shows application and location context' -Status Warning -Severity Medium `
                -Detail "App context='$appState', location context='$geoState' (both should be 'enabled')." -Evidence @{ App = $appState; Geo = $geoState } `
                -Recommendation 'Enable app name and geographic location in Authenticator push to help users spot rogue prompts.' `
                -Reference 'https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-additional-context'
        }
    }
}

function Test-CaEntraAuthMethodsMigration {
    Invoke-CaCheck -Service Entra -CheckId 'ENTRA-012' -Title 'Authentication methods policy migration complete' -Body {
        $policy = Invoke-CaGraphRequest -Uri 'policies/authenticationMethodsPolicy'
        $state = [string]$policy.policyMigrationState
        if ($state -eq 'migrationComplete') {
            New-CaFinding -Service Entra -CheckId 'ENTRA-012' -Title 'Authentication methods policy migration complete' -Status Pass `
                -Detail 'Legacy MFA/SSPR settings have been migrated to the converged Authentication methods policy.' -Evidence $state
        }
        elseif ([string]::IsNullOrEmpty($state)) {
            New-CaFinding -Service Entra -CheckId 'ENTRA-012' -Title 'Authentication methods policy migration complete' -Status Info `
                -Detail 'Migration state not reported by the tenant.' -Evidence $state
        }
        else {
            New-CaFinding -Service Entra -CheckId 'ENTRA-012' -Title 'Authentication methods policy migration complete' -Status Warning -Severity Low `
                -Detail "Migration state is '$state'. Legacy MFA/SSPR policies may still be authoritative." -Evidence $state `
                -Recommendation 'Complete the migration to the converged Authentication methods policy and mark migration complete.' `
                -Reference 'https://learn.microsoft.com/entra/identity/authentication/how-to-authentication-methods-manage'
        }
    }
}

function Test-CaEntraAdminConsentWorkflow {
    Invoke-CaCheck -Service Entra -CheckId 'ENTRA-013' -Title 'Admin consent request workflow enabled' -Body {
        $policy = Invoke-CaGraphRequest -Uri 'policies/adminConsentRequestPolicy'
        $enabled = [bool]$policy.isEnabled
        if ($enabled) {
            New-CaFinding -Service Entra -CheckId 'ENTRA-013' -Title 'Admin consent request workflow enabled' -Status Pass `
                -Detail 'Users can request admin consent for apps, avoiding risky self-consent.' -Evidence $true
        }
        else {
            New-CaFinding -Service Entra -CheckId 'ENTRA-013' -Title 'Admin consent request workflow enabled' -Status Warning -Severity Low `
                -Detail 'Admin consent request workflow is disabled; pair with restricted user consent (ENTRA-006).' -Evidence $false `
                -Recommendation 'Enable the admin consent workflow so users can request, rather than self-grant, app permissions.' `
                -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/configure-admin-consent-workflow'
        }
    }
}

function Test-CaEntraBlockLegacyPowerShell {
    Invoke-CaCheck -Service Entra -CheckId 'ENTRA-014' -Title 'Legacy AAD/MSOnline PowerShell access blocked' -Body {
        $policy = Invoke-CaGraphRequest -Uri 'policies/authorizationPolicy'
        # authorizationPolicy is a single object at /policies/authorizationPolicy.
        $blocked = [bool]$policy.blockMsolPowerShell
        if ($blocked) {
            New-CaFinding -Service Entra -CheckId 'ENTRA-014' -Title 'Legacy AAD/MSOnline PowerShell access blocked' -Status Pass `
                -Detail 'blockMsolPowerShell = True.' -Evidence $true
        }
        else {
            New-CaFinding -Service Entra -CheckId 'ENTRA-014' -Title 'Legacy AAD/MSOnline PowerShell access blocked' -Status Info `
                -Detail 'Legacy MSOnline PowerShell access is not blocked. The MSOnline/AzureAD modules are deprecated; prefer blocking once tooling is migrated to Microsoft Graph.' -Evidence $false `
                -Recommendation 'After migrating scripts to Microsoft Graph, set blockMsolPowerShell to true.' `
                -Reference 'https://learn.microsoft.com/powershell/microsoftgraph/migration-steps'
        }
    }
}
