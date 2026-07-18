<#
    OneDrive.ps1 - OneDrive for Business tenant checks. These settings live on the
    same Graph admin SharePoint object (Get-MgAdminSharePointSetting) but govern
    the OneDrive sync client and personal-site behaviour, so they are grouped here.
    Read-only.
#>

function Get-CaOneDriveFindings {
    [CmdletBinding()]
    param()
    Get-CaFindingsByPrefix -Prefix 'Test-CaOneDrive*'
}

function Test-CaOneDriveUnmanagedSync {
    Invoke-CaCheck -Service OneDrive -CheckId 'OD-001' -Title 'Sync restricted to managed (domain-joined) devices' -Body {
        $bl = Get-CaBaseline
        if (-not $bl.OneDrive.RestrictUnmanagedDeviceSync) {
            return New-CaFinding -Service OneDrive -CheckId 'OD-001' -Title 'Sync restricted to managed (domain-joined) devices' -Status Info -Detail 'Baseline does not require this control.'
        }
        $s = Get-CaSharePointSetting
        if ($s.IsUnmanagedSyncAppForTenantRestricted) {
            New-CaFinding -Service OneDrive -CheckId 'OD-001' -Title 'Sync restricted to managed (domain-joined) devices' -Status Pass -Detail 'Unmanaged-device sync is restricted.' -Evidence $true
        }
        else {
            New-CaFinding -Service OneDrive -CheckId 'OD-001' -Title 'Sync restricted to managed (domain-joined) devices' -Status Fail -Severity Medium `
                -Detail 'The sync client is allowed on unmanaged/unjoined devices.' -Evidence $false `
                -Recommendation 'Restrict syncing to domain-joined / compliant devices (Set-SPOTenant -IsUnmanagedSyncAppForTenantRestricted $true).' `
                -Reference 'https://learn.microsoft.com/sharepoint/allow-syncing-only-on-specific-domains'
        }
    }
}

function Test-CaOneDriveBlockedFileExtensions {
    Invoke-CaCheck -Service OneDrive -CheckId 'OD-002' -Title 'Sync of high-risk file extensions blocked' -Body {
        $bl = Get-CaBaseline
        if (-not $bl.OneDrive.RequireBlockedSyncFileExtensions) {
            return New-CaFinding -Service OneDrive -CheckId 'OD-002' -Title 'Sync of high-risk file extensions blocked' -Status Info -Detail 'Baseline does not require this control.'
        }
        $s = Get-CaSharePointSetting
        $blocked = @($s.ExcludedFileExtensionsForSyncApp | Where-Object { $_ })
        if ($blocked.Count -gt 0) {
            New-CaFinding -Service OneDrive -CheckId 'OD-002' -Title 'Sync of high-risk file extensions blocked' -Status Pass `
                -Detail "$($blocked.Count) extension(s) excluded from sync." -Evidence ($blocked -join ', ')
        }
        else {
            New-CaFinding -Service OneDrive -CheckId 'OD-002' -Title 'Sync of high-risk file extensions blocked' -Status Warning -Severity Low `
                -Detail 'No file extensions are excluded from the sync client.' -Evidence '' `
                -Recommendation 'Exclude risky extensions (e.g. pst, exe, vbs) from sync if policy requires.' `
                -Reference 'https://learn.microsoft.com/sharepoint/block-file-types-on-sync'
        }
    }
}

function Test-CaOneDriveDeletedUserRetention {
    Invoke-CaCheck -Service OneDrive -CheckId 'OD-003' -Title 'Deleted-user OneDrive retention meets minimum' -Body {
        $bl = Get-CaBaseline
        $min = [int]$bl.OneDrive.MinDeletedUserRetentionDays
        $s = Get-CaSharePointSetting
        $days = [int]$s.DeletedUserPersonalSiteRetentionPeriodInDays
        if ($days -ge $min) {
            New-CaFinding -Service OneDrive -CheckId 'OD-003' -Title 'Deleted-user OneDrive retention meets minimum' -Status Pass `
                -Detail "Retention is $days day(s) (minimum $min)." -Evidence $days
        }
        else {
            New-CaFinding -Service OneDrive -CheckId 'OD-003' -Title 'Deleted-user OneDrive retention meets minimum' -Status Fail -Severity Medium `
                -Detail "Deleted-user OneDrive retention is $days day(s), below the baseline minimum of $min." -Evidence $days `
                -Recommendation 'Increase OneDrive retention for deleted users to retain data for recovery/legal hold.' `
                -Reference 'https://learn.microsoft.com/sharepoint/set-retention'
        }
    }
}
