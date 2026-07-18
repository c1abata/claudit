<#
    Entra.ps1 - Entra ID (Azure AD) read-only checks via Microsoft Graph.

    Every public check is named Test-CaEntra* and is auto-discovered by
    Get-CaEntraFindings. Each wraps its body in Invoke-CaCheck so a single
    failure degrades to an Error finding instead of aborting the audit.
#>

function Test-CaEntraSecurityBaseline {
    Invoke-CaCheck -Service Entra -CheckId 'ENTRA-001' -Title 'Security Defaults or Conditional Access enforced' -Body {
        Assert-CaGraph
        $bl = Get-CaBaseline
        $sd = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
        $caCount = 0
        if (-not $sd.IsEnabled) {
            $caCount = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop | Where-Object { $_.State -eq 'enabled' }).Count
        }

        $protected = $sd.IsEnabled -or $caCount -gt 0
        if (-not $bl.Entra.RequireSecurityDefaultsOrConditionalAccess) {
            return New-CaFinding -Service Entra -CheckId 'ENTRA-001' -Title 'Security Defaults or Conditional Access enforced' -Status Info -Detail 'Baseline does not require this control.'
        }
        if ($protected) {
            New-CaFinding -Service Entra -CheckId 'ENTRA-001' -Title 'Security Defaults or Conditional Access enforced' -Status Pass `
                -Detail "Security Defaults enabled=$($sd.IsEnabled); enabled CA policies=$caCount." -Evidence $sd.IsEnabled
        }
        else {
            New-CaFinding -Service Entra -CheckId 'ENTRA-001' -Title 'Security Defaults or Conditional Access enforced' -Status Fail -Severity Critical `
                -Detail 'Neither Security Defaults nor any enabled Conditional Access policy is present.' `
                -Recommendation 'Enable Security Defaults, or deploy Conditional Access requiring MFA.' `
                -Reference 'https://learn.microsoft.com/entra/fundamentals/security-defaults'
        }
    }
}

function Test-CaEntraGlobalAdminCount {
    Invoke-CaCheck -Service Entra -CheckId 'ENTRA-002' -Title 'Number of Global Administrators within limit' -Body {
        Assert-CaGraph
        $bl = Get-CaBaseline
        $role = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" -ErrorAction Stop
        $members = @()
        if ($role) { $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction Stop }
        $count = ($members | Measure-Object).Count
        $max = [int]$bl.Entra.MaxGlobalAdministrators

        if ($count -eq 0) {
            New-CaFinding -Service Entra -CheckId 'ENTRA-002' -Title 'Number of Global Administrators within limit' -Status Warning -Severity Medium `
                -Detail 'Could not resolve any Global Administrators (role may not be activated).' -Evidence $count
        }
        elseif ($count -le $max) {
            New-CaFinding -Service Entra -CheckId 'ENTRA-002' -Title 'Number of Global Administrators within limit' -Status Pass `
                -Detail "$count Global Administrators (limit $max)." -Evidence $count
        }
        else {
            New-CaFinding -Service Entra -CheckId 'ENTRA-002' -Title 'Number of Global Administrators within limit' -Status Fail -Severity High `
                -Detail "$count Global Administrators exceeds the baseline of $max." -Evidence $count `
                -Recommendation 'Reduce standing Global Admins; use PIM eligible assignments and least-privileged roles.' `
                -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices'
        }
    }
}

function Test-CaEntraLegacyAuthBlocked {
    Invoke-CaCheck -Service Entra -CheckId 'ENTRA-003' -Title 'Legacy authentication blocked by Conditional Access' -Body {
        Assert-CaGraph
        $bl = Get-CaBaseline
        if (-not $bl.Entra.BlockLegacyAuthentication) {
            return New-CaFinding -Service Entra -CheckId 'ENTRA-003' -Title 'Legacy authentication blocked by Conditional Access' -Status Info -Detail 'Baseline does not require this control.'
        }
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        $blocking = $policies | Where-Object {
            $_.State -eq 'enabled' -and
            $_.Conditions.ClientAppTypes -and
            ($_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or $_.Conditions.ClientAppTypes -contains 'other') -and
            $_.GrantControls.BuiltInControls -contains 'block'
        }
        if ($blocking) {
            New-CaFinding -Service Entra -CheckId 'ENTRA-003' -Title 'Legacy authentication blocked by Conditional Access' -Status Pass `
                -Detail "Found $($blocking.Count) enabled CA policy blocking legacy clients." -Evidence ($blocking.DisplayName -join '; ')
        }
        else {
            New-CaFinding -Service Entra -CheckId 'ENTRA-003' -Title 'Legacy authentication blocked by Conditional Access' -Status Fail -Severity High `
                -Detail 'No enabled Conditional Access policy blocks legacy authentication protocols.' `
                -Recommendation 'Create a CA policy targeting legacy clients (Other clients / ActiveSync) with Block.' `
                -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication'
        }
    }
}

function Test-CaEntraUserAppRegistration {
    Invoke-CaCheck -Service Entra -CheckId 'ENTRA-004' -Title 'Standard users cannot register applications' -Body {
        Assert-CaGraph
        $bl = Get-CaBaseline
        $auth = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $allowed = [bool]$auth.DefaultUserRolePermissions.AllowedToCreateApps
        $expected = [bool]$bl.Entra.AllowUsersToRegisterApplications

        if ($allowed -eq $expected) {
            New-CaFinding -Service Entra -CheckId 'ENTRA-004' -Title 'Standard users cannot register applications' -Status Pass `
                -Detail "AllowedToCreateApps=$allowed matches baseline." -Evidence $allowed
        }
        else {
            New-CaFinding -Service Entra -CheckId 'ENTRA-004' -Title 'Standard users cannot register applications' -Status Fail -Severity Medium `
                -Detail "Users can register applications (AllowedToCreateApps=$allowed); baseline expects $expected." -Evidence $allowed `
                -Recommendation 'Set "Users can register applications" to No in Entra > User settings.' `
                -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/delegate-app-roles'
        }
    }
}

function Test-CaEntraGuestInvitePolicy {
    Invoke-CaCheck -Service Entra -CheckId 'ENTRA-005' -Title 'Guest invitation policy restricted' -Body {
        Assert-CaGraph
        $bl = Get-CaBaseline
        $auth = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $value = [string]$auth.AllowInvitesFrom
        $allowed = @($bl.Entra.AllowedInviteFrom)

        if ($allowed -contains $value) {
            New-CaFinding -Service Entra -CheckId 'ENTRA-005' -Title 'Guest invitation policy restricted' -Status Pass `
                -Detail "AllowInvitesFrom=$value." -Evidence $value
        }
        else {
            New-CaFinding -Service Entra -CheckId 'ENTRA-005' -Title 'Guest invitation policy restricted' -Status Fail -Severity Medium `
                -Detail "AllowInvitesFrom=$value is broader than baseline ($($allowed -join ', '))." -Evidence $value `
                -Recommendation 'Restrict who can invite guests to admins and the guest-inviter role.' `
                -Reference 'https://learn.microsoft.com/entra/external-id/external-collaboration-settings-configure'
        }
    }
}

function Test-CaEntraUserConsentToApps {
    Invoke-CaCheck -Service Entra -CheckId 'ENTRA-006' -Title 'User consent to applications restricted' -Body {
        Assert-CaGraph
        $bl = Get-CaBaseline
        $auth = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        # Empty PermissionGrantPoliciesAssigned => users cannot consent.
        $assigned = @($auth.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned)
        $usersCanConsent = $assigned.Count -gt 0
        $expected = [bool]$bl.Entra.AllowUsersToConsentForApps

        if ($usersCanConsent -eq $expected) {
            New-CaFinding -Service Entra -CheckId 'ENTRA-006' -Title 'User consent to applications restricted' -Status Pass `
                -Detail "Users can consent=$usersCanConsent matches baseline." -Evidence ($assigned -join ', ')
        }
        else {
            New-CaFinding -Service Entra -CheckId 'ENTRA-006' -Title 'User consent to applications restricted' -Status Fail -Severity High `
                -Detail "User app-consent is $usersCanConsent (policies: $($assigned -join ', ')); baseline expects $expected." -Evidence ($assigned -join ', ') `
                -Recommendation 'Disable user consent or restrict to verified publishers/low-impact permissions; require admin consent workflow.' `
                -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent'
        }
    }
}

function Test-CaEntraRiskyAppCredentials {
    Invoke-CaCheck -Service Entra -CheckId 'ENTRA-007' -Title 'Service principals without expired/expiring credentials' -Body {
        Assert-CaGraph
        $now = [DateTime]::UtcNow
        $soon = $now.AddDays(30)
        $apps = Get-MgServicePrincipal -All -Property 'displayName,appId,keyCredentials,passwordCredentials' -ErrorAction Stop
        $expired = @()
        $expiring = @()
        foreach ($a in $apps) {
            foreach ($c in @($a.PasswordCredentials) + @($a.KeyCredentials)) {
                if (-not $c.EndDateTime) { continue }
                if ($c.EndDateTime -lt $now) { $expired += $a.DisplayName }
                elseif ($c.EndDateTime -lt $soon) { $expiring += $a.DisplayName }
            }
        }
        $expired = $expired | Sort-Object -Unique
        $expiring = $expiring | Sort-Object -Unique

        if ($expired.Count -eq 0 -and $expiring.Count -eq 0) {
            New-CaFinding -Service Entra -CheckId 'ENTRA-007' -Title 'Service principals without expired/expiring credentials' -Status Pass `
                -Detail 'No service principal credentials are expired or expiring within 30 days.'
        }
        else {
            New-CaFinding -Service Entra -CheckId 'ENTRA-007' -Title 'Service principals without expired/expiring credentials' -Status Warning -Severity Medium `
                -Detail "Expired: $($expired.Count); expiring <=30d: $($expiring.Count)." -Evidence @{ Expired = $expired; Expiring = $expiring } `
                -Recommendation 'Rotate or remove stale app credentials; prefer certificate or managed-identity auth.' `
                -Reference 'https://learn.microsoft.com/entra/identity-platform/howto-create-service-principal-portal'
        }
    }
}

function Get-CaEntraFindings {
    [CmdletBinding()]
    param()
    Get-CaFindingsByPrefix -Prefix 'Test-CaEntra*'
}

function Test-CaEntraGuestVolume {
    Invoke-CaCheck -Service Entra -CheckId 'ENTRA-008' -Title 'Guest account inventory' -Body {
        Assert-CaGraph
        $guests = Get-MgUser -All -Filter "userType eq 'Guest'" -Property 'displayName,userType,accountEnabled' -ErrorAction Stop
        $count = ($guests | Measure-Object).Count
        $enabled = ($guests | Where-Object { $_.AccountEnabled } | Measure-Object).Count
        New-CaFinding -Service Entra -CheckId 'ENTRA-008' -Title 'Guest account inventory' -Status Info `
            -Detail "$count guest accounts ($enabled enabled). Review periodically for stale external access." -Evidence $count `
            -Reference 'https://learn.microsoft.com/entra/identity/users/users-bulk-download'
    }
}
