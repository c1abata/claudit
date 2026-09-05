<#
    Entra.ps1 - Entra ID (Azure AD) read-only checks via Microsoft Graph.

    Every public check is named Test-CaEntra* and is auto-discovered by
    Get-CaEntraFindings. Each wraps its body in Invoke-CaCheck so a single
    failure degrades to an Error finding instead of aborting the audit.
#>

function Test-CaConditionalAccessCoversAllUsersAndApps {
    param([Parameter(Mandatory)]$Policy)

    $users = $Policy.Conditions.Users
    $apps = $Policy.Conditions.Applications
    if ($null -eq $users -or $null -eq $apps) { return $false }

    $allUsers = @($users.IncludeUsers) -contains 'All'
    $allApps = @($apps.IncludeApplications) -contains 'All'
    $hasExclusions = @($users.ExcludeUsers).Count -gt 0 -or
        @($users.ExcludeGroups).Count -gt 0 -or
        @($users.ExcludeRoles).Count -gt 0 -or
        @($apps.ExcludeApplications).Count -gt 0
    return $allUsers -and $allApps -and -not $hasExclusions
}

function Test-CaConditionalAccessRequiresMfa {
    param([Parameter(Mandatory)]$Policy)

    $controls = @($Policy.GrantControls.BuiltInControls)
    return ($controls -contains 'mfa') -or
        ($controls -contains 'authenticationStrength') -or
        ($null -ne $Policy.GrantControls.AuthenticationStrength)
}

function Get-CaBroadMfaPolicies {
    param([Parameter(Mandatory)][object[]]$Policies)

    @($Policies | Where-Object {
        $_.State -eq 'enabled' -and
        (Test-CaConditionalAccessCoversAllUsersAndApps -Policy $_) -and
        (Test-CaConditionalAccessRequiresMfa -Policy $_)
    })
}

function Test-CaEntraSecurityBaseline {
    Invoke-CaCheck -Service Entra -CheckId 'ENTRA-001' -Title 'Security Defaults or Conditional Access enforced' -Body {
        Assert-CaGraph
        $bl = Get-CaBaseline
        $sd = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
        $policies = @()
        $broadMfa = @()
        if (-not $sd.IsEnabled) {
            $policies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
            $broadMfa = @(Get-CaBroadMfaPolicies -Policies $policies)
        }

        if (-not $bl.Entra.RequireSecurityDefaultsOrConditionalAccess) {
            return New-CaFinding -Service Entra -CheckId 'ENTRA-001' -Title 'Security Defaults or Conditional Access enforced' -Status Info -Detail 'Baseline does not require this control.'
        }
        if ($sd.IsEnabled -or $broadMfa.Count -gt 0) {
            New-CaFinding -Service Entra -CheckId 'ENTRA-001' -Title 'Security Defaults or Conditional Access enforced' -Status Pass `
                -Detail "Security Defaults enabled=$($sd.IsEnabled); broad MFA CA policies=$($broadMfa.Count)." `
                -Evidence @{ SecurityDefaults=[bool]$sd.IsEnabled; BroadMfaPolicies=@($broadMfa.DisplayName) }
        }
        elseif (@($policies | Where-Object State -eq 'enabled').Count -gt 0) {
            New-CaFinding -Service Entra -CheckId 'ENTRA-001' -Title 'Security Defaults or Conditional Access enforced' -Status Investigate -Severity High `
                -Detail 'Enabled Conditional Access policies exist, but static scope analysis did not prove tenant-wide MFA coverage without exclusions.' `
                -Evidence @($policies | Where-Object State -eq 'enabled' | Select-Object DisplayName, State) `
                -Recommendation 'Validate representative administrative and user sign-in scenarios with the Microsoft Graph Conditional Access evaluate API.'
        }
        else {
            New-CaFinding -Service Entra -CheckId 'ENTRA-001' -Title 'Security Defaults or Conditional Access enforced' -Status Fail -Severity Critical `
                -Detail 'Neither Security Defaults nor any enabled Conditional Access policy is present.' `
                -Recommendation 'Enable Security Defaults, or deploy Conditional Access requiring MFA.' `
                -Reference 'https://learn.microsoft.com/entra/fundamentals/security-defaults'
        }
    }
}

function Test-CaEntraAdminMfaCoverage {
    Invoke-CaCheck -Service Entra -CheckId 'ENTRA-009' -Title 'Administrative access requires MFA' -Body {
        Assert-CaGraph
        $bl = Get-CaBaseline
        if (-not [bool]$bl.Entra.RequireMfaForAdmins) {
            return New-CaFinding -Service Entra -CheckId 'ENTRA-009' -Title 'Administrative access requires MFA' -Status Info -Detail 'Baseline does not require this control.'
        }

        $sd = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
        if ($sd.IsEnabled) {
            return New-CaFinding -Service Entra -CheckId 'ENTRA-009' -Title 'Administrative access requires MFA' -Status Pass `
                -Detail 'Security Defaults is enabled and requires privileged roles to use MFA.' -Evidence $true
        }

        $policies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
        $broadMfa = @(Get-CaBroadMfaPolicies -Policies $policies)
        if ($broadMfa.Count -gt 0) {
            New-CaFinding -Service Entra -CheckId 'ENTRA-009' -Title 'Administrative access requires MFA' -Status Pass `
                -Detail "$($broadMfa.Count) enabled policy/policies require MFA for all users and applications without exclusions." `
                -Evidence @($broadMfa.DisplayName)
        }
        else {
            New-CaFinding -Service Entra -CheckId 'ENTRA-009' -Title 'Administrative access requires MFA' -Status Investigate -Severity Critical `
                -Detail 'Static policy inspection did not prove complete administrative MFA coverage.' `
                -Evidence @($policies | Where-Object State -eq 'enabled' | Select-Object DisplayName, State) `
                -Recommendation 'Run Conditional Access evaluate scenarios for every active privileged role member and document approved break-glass exclusions.' `
                -Reference 'https://learn.microsoft.com/graph/api/conditionalaccessroot-evaluate?view=graph-rest-1.0'
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
        $sd = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
        if ($sd.IsEnabled) {
            return New-CaFinding -Service Entra -CheckId 'ENTRA-003' -Title 'Legacy authentication blocked by Conditional Access' -Status Pass `
                -Detail 'Security Defaults is enabled and blocks legacy authentication.' -Evidence $true
        }

        $policies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
        $candidates = @($policies | Where-Object {
            $_.State -eq 'enabled' -and
            $_.Conditions.ClientAppTypes -and
            ($_.Conditions.ClientAppTypes -contains 'exchangeActiveSync') -and
            ($_.Conditions.ClientAppTypes -contains 'other') -and
            $_.GrantControls.BuiltInControls -contains 'block'
        })
        $blocking = @($candidates | Where-Object { Test-CaConditionalAccessCoversAllUsersAndApps -Policy $_ })
        if ($blocking) {
            New-CaFinding -Service Entra -CheckId 'ENTRA-003' -Title 'Legacy authentication blocked by Conditional Access' -Status Pass `
                -Detail "Found $($blocking.Count) enabled CA policy blocking legacy clients." -Evidence ($blocking.DisplayName -join '; ')
        }
        elseif ($candidates.Count -gt 0) {
            New-CaFinding -Service Entra -CheckId 'ENTRA-003' -Title 'Legacy authentication blocked by Conditional Access' -Status Investigate -Severity High `
                -Detail 'Legacy-auth blocking policies exist, but scope or exclusions prevent proof of complete user/application coverage.' `
                -Evidence @($candidates.DisplayName) `
                -Recommendation 'Remove unintended exclusions or validate every excluded identity/application as an approved exception.'
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
