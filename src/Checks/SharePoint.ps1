<#
    SharePoint.ps1 - SharePoint Online tenant checks via Microsoft Graph
    (Get-MgAdminSharePointSetting). Tenant-level, read-only.

    Deep per-site analysis (broken inheritance, anonymous links per site) requires
    PnP.PowerShell and is intentionally out of scope for the first beta to keep the
    suite dependency-light and fast. The tenant ceiling checked here is the control
    that actually bounds per-site risk.
#>

function Get-CaSharePointFindings {
    [CmdletBinding()]
    param()
    Get-CaFindingsByPrefix -Prefix 'Test-CaSharePoint*'
}

function Get-CaSharePointSetting {
    # Single Graph call shared by the SharePoint/OneDrive tenant checks.
    Assert-CaGraph
    Get-MgAdminSharePointSetting -ErrorAction Stop
}

function Test-CaSharePointSharingCapability {
    Invoke-CaCheck -Service SharePoint -CheckId 'SPO-001' -Title 'External sharing capability within baseline' -Body {
        $bl = Get-CaBaseline
        $s = Get-CaSharePointSetting
        $current = [string]$s.SharingCapability
        $max = [string]$bl.SharePoint.MaxSharingCapability

        $curRank = $script:CaSharingRank[$current]
        $maxRank = $script:CaSharingRank[$max]

        if ($null -eq $curRank) {
            return New-CaFinding -Service SharePoint -CheckId 'SPO-001' -Title 'External sharing capability within baseline' -Status Warning -Severity Low `
                -Detail "Unrecognized SharingCapability value '$current'." -Evidence $current
        }
        if ($curRank -le $maxRank) {
            New-CaFinding -Service SharePoint -CheckId 'SPO-001' -Title 'External sharing capability within baseline' -Status Pass `
                -Detail "SharingCapability=$current is within baseline ceiling '$max'." -Evidence $current
        }
        else {
            $sev = if ($current -eq 'externalUserAndGuestSharing') { 'High' } else { 'Medium' }
            New-CaFinding -Service SharePoint -CheckId 'SPO-001' -Title 'External sharing capability within baseline' -Status Fail -Severity $sev `
                -Detail "SharingCapability=$current is more permissive than baseline '$max' (Anyone/anonymous links may be possible)." -Evidence $current `
                -Recommendation "Lower org-wide external sharing to '$max' or stricter in the SharePoint admin center." `
                -Reference 'https://learn.microsoft.com/sharepoint/turn-external-sharing-on-or-off'
        }
    }
}

function Test-CaSharePointLegacyAuth {
    Invoke-CaCheck -Service SharePoint -CheckId 'SPO-002' -Title 'Legacy authentication protocols disabled' -Body {
        $bl = Get-CaBaseline
        if (-not $bl.SharePoint.BlockLegacyAuthProtocols) {
            return New-CaFinding -Service SharePoint -CheckId 'SPO-002' -Title 'Legacy authentication protocols disabled' -Status Info -Detail 'Baseline does not require this control.'
        }
        $s = Get-CaSharePointSetting
        if (-not $s.IsLegacyAuthProtocolsEnabled) {
            New-CaFinding -Service SharePoint -CheckId 'SPO-002' -Title 'Legacy authentication protocols disabled' -Status Pass -Detail 'IsLegacyAuthProtocolsEnabled = False.' -Evidence $false
        }
        else {
            New-CaFinding -Service SharePoint -CheckId 'SPO-002' -Title 'Legacy authentication protocols disabled' -Status Fail -Severity High `
                -Detail 'Legacy authentication protocols are enabled for SharePoint/OneDrive.' -Evidence $true `
                -Recommendation 'Disable legacy auth so Conditional Access can govern access (Set-SPOTenant -LegacyAuthProtocolsEnabled $false).' `
                -Reference 'https://learn.microsoft.com/sharepoint/control-access-from-unmanaged-devices'
        }
    }
}

function Test-CaSharePointReauthMatchInvited {
    Invoke-CaCheck -Service SharePoint -CheckId 'SPO-003' -Title 'Guests must sign in with the invited identity' -Body {
        $bl = Get-CaBaseline
        if (-not $bl.SharePoint.RequireReauthAcceptingUserMatchesInvited) {
            return New-CaFinding -Service SharePoint -CheckId 'SPO-003' -Title 'Guests must sign in with the invited identity' -Status Info -Detail 'Baseline does not require this control.'
        }
        $s = Get-CaSharePointSetting
        if ($s.IsRequireAcceptingUserToMatchInvitedUserEnabled) {
            New-CaFinding -Service SharePoint -CheckId 'SPO-003' -Title 'Guests must sign in with the invited identity' -Status Pass -Detail 'Invited-user match is enforced.' -Evidence $true
        }
        else {
            New-CaFinding -Service SharePoint -CheckId 'SPO-003' -Title 'Guests must sign in with the invited identity' -Status Fail -Severity Medium `
                -Detail 'Sharing invitations can be redeemed by an identity other than the invited one.' -Evidence $false `
                -Recommendation 'Require that the accepting user matches the invited user to prevent invite forwarding.' `
                -Reference 'https://learn.microsoft.com/sharepoint/external-sharing-overview'
        }
    }
}

function Test-CaSharePointDomainRestriction {
    Invoke-CaCheck -Service SharePoint -CheckId 'SPO-004' -Title 'External sharing domain restriction posture' -Body {
        $s = Get-CaSharePointSetting
        $mode = [string]$s.SharingDomainRestrictionMode
        if ($mode -and $mode -ne 'none') {
            New-CaFinding -Service SharePoint -CheckId 'SPO-004' -Title 'External sharing domain restriction posture' -Status Pass `
                -Detail "Domain restriction active (mode=$mode)." -Evidence $mode
        }
        else {
            New-CaFinding -Service SharePoint -CheckId 'SPO-004' -Title 'External sharing domain restriction posture' -Status Info `
                -Detail 'No allow/block domain restriction configured. This is informational; apply only if your policy requires domain allow/deny lists.' -Evidence $mode `
                -Recommendation 'Consider an allow-list of partner domains if external sharing is enabled.' `
                -Reference 'https://learn.microsoft.com/sharepoint/restricted-domains-sharing'
        }
    }
}
