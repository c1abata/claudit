<#
    Baseline.ps1 - loads the expected-state baseline used by the checks.

    The baseline is plain JSON so a non-developer admin can edit thresholds
    without touching PowerShell. It is cached per-session.
#>

$script:CaBaseline = $null
$script:CaBaselinePath = $null

$script:CaBaselineRequiredProperties = [ordered]@{
    Entra      = @('RequireSecurityDefaultsOrConditionalAccess', 'RequireMfaForAdmins', 'BlockLegacyAuthentication', 'MaxGlobalAdministrators', 'AllowUsersToRegisterApplications', 'AllowedInviteFrom', 'AllowUsersToConsentForApps')
    Exchange   = @('RequireModernAuthentication', 'BlockSmtpClientAuthentication', 'DisablePop3', 'DisableImap4', 'BlockExternalAutoForwarding', 'RequireDkimOnAllDomains', 'RequireOrganizationAuditEnabled')
    SharePoint = @('MaxSharingCapability', 'BlockLegacyAuthProtocols', 'RequireReauthAcceptingUserMatchesInvited')
    OneDrive   = @('RestrictUnmanagedDeviceSync', 'RequireBlockedSyncFileExtensions', 'MinDeletedUserRetentionDays')
    Azure      = @('HighRiskAzureRoles', 'AllowedPrivilegedPrincipalIds', 'HighRiskGraphAppRoles', 'RequireStorageDefaultDeny', 'RequireKeyVaultPurgeProtection')
    AWS        = @('Regions', 'MinPasswordLength', 'MaxPasswordAgeDays', 'PasswordReusePrevention', 'MaxAccessKeyAgeDays', 'RequireVpcFlowLogs')
    GCP        = @('Organization', 'AllowedPrimitiveRoleMembers', 'MaxServiceAccountKeyAgeDays', 'RequiredAuditLogTypes', 'RequireOsLogin', 'RequireCentralLogSink')
    Tailscale  = @('Tailnet', 'MaxStaleDeviceDays', 'MaxAuthKeyExpiryDays', 'DisallowReusableAuthKeys', 'DisallowPreauthorizedAuthKeys', 'DisallowAllowAllAcl')
    Domain     = @('AuthorizedDomains', 'Subdomains')
    VPS        = @('AllowedPublicPorts', 'MaxPendingUpdates', 'RequireFirewall', 'RequireAuthLog', 'RequireSshPasswordAuthenticationDisabled', 'RequireSshRootLoginDisabled')
    Inventory  = @('MaxAssetsPerProvider')
}

function Get-CaBaselineValue {
    param(
        [Parameter(Mandatory)]$Baseline,
        [Parameter(Mandatory)][string]$Path
    )

    $value = $Baseline
    foreach ($segment in ($Path -split '\.')) {
        if ($null -eq $value -or $value.PSObject.Properties.Name -notcontains $segment) { return $null }
        $value = $value.$segment
    }
    if ($value -is [array]) { return ,$value }
    return $value
}

function Assert-CaBaseline {
    param(
        [Parameter(Mandatory)]$Baseline,
        [Parameter(Mandatory)][string]$SourcePath
    )

    $issues = [System.Collections.Generic.List[string]]::new()
    foreach ($sectionName in $script:CaBaselineRequiredProperties.Keys) {
        if ($Baseline.PSObject.Properties.Name -notcontains $sectionName -or $null -eq $Baseline.$sectionName) {
            $issues.Add("missing section '$sectionName'")
            continue
        }
        foreach ($propertyName in $script:CaBaselineRequiredProperties[$sectionName]) {
            if ($Baseline.$sectionName.PSObject.Properties.Name -notcontains $propertyName -or $null -eq $Baseline.$sectionName.$propertyName) {
                $issues.Add("missing property '$sectionName.$propertyName'")
            }
        }
    }

    $booleanPaths = @(
        'Entra.RequireSecurityDefaultsOrConditionalAccess', 'Entra.RequireMfaForAdmins',
        'Entra.BlockLegacyAuthentication', 'Entra.AllowUsersToRegisterApplications',
        'Entra.AllowUsersToConsentForApps', 'Exchange.RequireModernAuthentication',
        'Exchange.BlockSmtpClientAuthentication', 'Exchange.DisablePop3', 'Exchange.DisableImap4',
        'Exchange.BlockExternalAutoForwarding', 'Exchange.RequireDkimOnAllDomains',
        'Exchange.RequireOrganizationAuditEnabled', 'SharePoint.BlockLegacyAuthProtocols',
        'SharePoint.RequireReauthAcceptingUserMatchesInvited', 'OneDrive.RestrictUnmanagedDeviceSync',
        'OneDrive.RequireBlockedSyncFileExtensions', 'Azure.RequireStorageDefaultDeny',
        'Azure.RequireKeyVaultPurgeProtection', 'AWS.RequireVpcFlowLogs', 'GCP.RequireOsLogin',
        'GCP.RequireCentralLogSink', 'Tailscale.DisallowReusableAuthKeys',
        'Tailscale.DisallowPreauthorizedAuthKeys', 'Tailscale.DisallowAllowAllAcl',
        'Domain.RequireDnssec', 'Domain.EnableDnsx',
        'VPS.RequireFirewall', 'VPS.RequireAuthLog',
        'VPS.RequireSshPasswordAuthenticationDisabled', 'VPS.RequireSshRootLoginDisabled'
    )
    foreach ($path in $booleanPaths) {
        $value = Get-CaBaselineValue -Baseline $Baseline -Path $path
        if ($null -ne $value -and $value -isnot [bool]) { $issues.Add("'$path' must be a JSON boolean") }
    }

    $integerMinimums = [ordered]@{
        'Entra.MaxGlobalAdministrators'        = 1
        'OneDrive.MinDeletedUserRetentionDays' = 0
        'AWS.MinPasswordLength'                 = 1
        'AWS.MaxPasswordAgeDays'                = 1
        'AWS.PasswordReusePrevention'           = 0
        'AWS.MaxAccessKeyAgeDays'               = 1
        'GCP.MaxServiceAccountKeyAgeDays'       = 1
        'Tailscale.MaxStaleDeviceDays'          = 1
        'Tailscale.MaxAuthKeyExpiryDays'        = 1
        'Domain.DnsxRateLimit'                  = 1
        'Domain.DnsxTimeoutSeconds'             = 1
        'VPS.MaxPendingUpdates'                 = 0
        'Inventory.MaxAssetsPerProvider'        = 1
    }
    foreach ($path in $integerMinimums.Keys) {
        $value = Get-CaBaselineValue -Baseline $Baseline -Path $path
        $isInteger = $value -is [int] -or $value -is [long]
        if ($null -ne $value -and (-not $isInteger -or [long]$value -lt $integerMinimums[$path] -or [long]$value -gt [int]::MaxValue)) {
            $issues.Add("'$path' must be an integer >= $($integerMinimums[$path])")
        }
    }

    $arrayPaths = @(
        'Entra.AllowedInviteFrom', 'Azure.HighRiskAzureRoles', 'Azure.AllowedPrivilegedPrincipalIds',
        'Azure.HighRiskGraphAppRoles', 'AWS.Regions', 'GCP.AllowedPrimitiveRoleMembers',
        'GCP.RequiredAuditLogTypes', 'Domain.AuthorizedDomains', 'Domain.Subdomains',
        'Domain.DkimSelectors', 'Domain.DnsxResolvers', 'VPS.AllowedPublicPorts'
    )
    foreach ($path in $arrayPaths) {
        $value = Get-CaBaselineValue -Baseline $Baseline -Path $path
        if ($null -ne $value -and ($value -is [string] -or $value -isnot [System.Collections.IEnumerable])) {
            $issues.Add("'$path' must be a JSON array")
        }
    }

    $sharing = [string](Get-CaBaselineValue -Baseline $Baseline -Path 'SharePoint.MaxSharingCapability')
    if ($sharing -and $sharing.ToLowerInvariant() -notin @('disabled', 'existingexternalusersharingonly', 'externalusersharingonly', 'externaluserandguestsharing')) {
        $issues.Add("'SharePoint.MaxSharingCapability' has unsupported value '$sharing'")
    }

    $allowedPorts = Get-CaBaselineValue -Baseline $Baseline -Path 'VPS.AllowedPublicPorts'
    foreach ($port in $allowedPorts) {
        $parsedPort = 0
        if (-not [int]::TryParse([string]$port, [ref]$parsedPort) -or $parsedPort -lt 1 -or $parsedPort -gt 65535) {
            $issues.Add("'VPS.AllowedPublicPorts' contains invalid port '$port'")
        }
    }

    if ($issues.Count -gt 0) {
        throw "Invalid Claudit baseline '$SourcePath': $($issues -join '; ')."
    }
}

function Get-CaBaseline {
    [CmdletBinding()]
    param(
        # Override path; defaults to config/baseline.json next to the module.
        [string]$Path,
        [switch]$Force
    )

    $requestedPath = if ($Path) { $Path } else { Join-Path $PSScriptRoot '..\..\config\baseline.json' }
    $item = Get-Item -LiteralPath $requestedPath -ErrorAction Stop
    if ($item.PSIsContainer) { throw "Claudit baseline path is a directory: $requestedPath" }
    $resolvedPath = $item.FullName

    if ($script:CaBaseline -and -not $Force -and $script:CaBaselinePath -eq $resolvedPath) {
        return $script:CaBaseline
    }

    $raw = Get-Content -LiteralPath $resolvedPath -Raw -Encoding UTF8 -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { throw "Claudit baseline is empty: $resolvedPath" }
    try {
        $loaded = $raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Invalid JSON in Claudit baseline '$resolvedPath': $($_.Exception.Message)"
    }
    Assert-CaBaseline -Baseline $loaded -SourcePath $resolvedPath
    $script:CaBaseline = $loaded
    $script:CaBaselinePath = $resolvedPath
    return $script:CaBaseline
}

# Ordered permissiveness of SharePoint/OneDrive external sharing. Higher = more open.
$script:CaSharingRank = @{
    'disabled'                       = 0
    'existingExternalUserSharingOnly' = 1
    'externalUserSharingOnly'        = 2
    'externalUserAndGuestSharing'    = 3
}
