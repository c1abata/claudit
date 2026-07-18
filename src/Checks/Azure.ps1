<#
    Azure.ps1 - read-only Azure subscription posture checks via az CLI.

    The module deliberately stays on the official Azure CLI instead of adding a
    hard Az PowerShell dependency. Checks are inspired by service-principal
    privilege review, cloud recon and compliance evidence tools, but remain
    defensive: list/read calls only, no remediation and no credential storage.
#>

function Get-CaAzureFindings {
    [CmdletBinding()]
    param()
    Get-CaFindingsByPrefix -Prefix 'Test-CaAzure*'
}

function Get-CaAzureBaseArgs {
    $opt = Get-CaProviderOption -Provider Azure
    $args = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($opt.Subscription)) {
        $args.Add('--subscription')
        $args.Add($opt.Subscription)
    }
    return @($args)
}

function Invoke-CaAzJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [switch]$AllowFailure
    )

    $args = [System.Collections.Generic.List[string]]::new()
    foreach ($a in (Get-CaAzureBaseArgs)) { $args.Add($a) }
    foreach ($a in $Arguments) { $args.Add($a) }
    $args.Add('--output')
    $args.Add('json')

    Invoke-CaExternalJson -Command 'az' -Arguments @($args) -AllowFailure:$AllowFailure
}

function Invoke-CaAzRestJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [switch]$AllowFailure
    )

    Invoke-CaExternalJson -Command 'az' -Arguments @('rest', '--method', 'get', '--url', $Uri, '--output', 'json') -AllowFailure:$AllowFailure
}

function Get-CaAzureAccount {
    $account = Invoke-CaAzJson -Arguments @('account', 'show')
    if (-not $account) { throw 'Azure CLI account context is empty. Run az login first.' }
    return $account
}

function Get-CaAzureProperty {
    param(
        $Object,
        [Parameter(Mandatory)][string]$Name
    )
    if ($null -eq $Object) { return $null }
    if ($Object.PSObject.Properties.Name -contains $Name) { return $Object.$Name }
    return $null
}

function Test-CaAzureContext {
    Invoke-CaCheck -Service Azure -CheckId 'AZURE-001' -Title 'Azure CLI context resolved' -Body {
        $account = Get-CaAzureAccount
        $opt = Get-CaProviderOption -Provider Azure
        if (-not [string]::IsNullOrWhiteSpace($opt.Tenant) -and [string]$account.tenantId -ne [string]$opt.Tenant) {
            return New-CaFinding -Service Azure -CheckId 'AZURE-001' -Title 'Azure CLI context resolved' -Status Warning -Severity Medium `
                -Detail "Current az tenant is $($account.tenantId), expected $($opt.Tenant). Run az login --tenant or az account set before audit." `
                -Evidence $account
        }
        New-CaFinding -Service Azure -CheckId 'AZURE-001' -Title 'Azure CLI context resolved' -Status Info `
            -Detail "Subscription=$($account.name) [$($account.id)]; Tenant=$($account.tenantId); User=$($account.user.name)." `
            -Evidence $account
    }
}

function Test-CaAzurePrivilegedServicePrincipals {
    Invoke-CaCheck -Service Azure -CheckId 'AZURE-002' -Title 'Service principals do not hold high-risk Azure roles' -Body {
        $bl = Get-CaBaseline
        $roles = ConvertTo-CaStringList $bl.Azure.HighRiskAzureRoles
        $allowed = ConvertTo-CaStringList $bl.Azure.AllowedPrivilegedPrincipalIds
        if ($roles.Count -eq 0) {
            return New-CaFinding -Service Azure -CheckId 'AZURE-002' -Title 'Service principals do not hold high-risk Azure roles' -Status Info `
                -Detail 'No high-risk Azure roles are configured in the baseline.'
        }

        $r = Invoke-CaAzJson -Arguments @('role', 'assignment', 'list', '--all', '--include-inherited') -AllowFailure
        if (-not $r.Success) {
            return New-CaFinding -Service Azure -CheckId 'AZURE-002' -Title 'Service principals do not hold high-risk Azure roles' -Status Skipped `
                -SkippedReason 'Azure RBAC assignments are not readable with current az context.' -Detail $r.Text
        }

        $offenders = [System.Collections.Generic.List[object]]::new()
        foreach ($a in @($r.Json)) {
            $principalType = [string]$a.principalType
            $roleName = [string]$a.roleDefinitionName
            $principalId = [string]$a.principalId
            if ($principalType -notin @('ServicePrincipal', 'ManagedIdentity')) { continue }
            if ($roles -notcontains $roleName) { continue }
            if ($allowed -contains $principalId) { continue }
            $offenders.Add([pscustomobject]@{
                PrincipalName = $a.principalName
                PrincipalId   = $principalId
                PrincipalType = $principalType
                Role          = $roleName
                Scope         = $a.scope
            })
        }

        if ($offenders.Count -eq 0) {
            New-CaFinding -Service Azure -CheckId 'AZURE-002' -Title 'Service principals do not hold high-risk Azure roles' -Status Pass `
                -Detail "No service principal or managed identity has baseline high-risk roles: $($roles -join ', ')." -Evidence $offenders
        }
        else {
            New-CaFinding -Service Azure -CheckId 'AZURE-002' -Title 'Service principals do not hold high-risk Azure roles' -Status Fail -Severity High `
                -Detail "$($offenders.Count) service principal or managed identity high-risk Azure role assignment(s)." -Evidence $offenders `
                -Recommendation 'Replace standing Owner/Contributor/User Access Administrator grants with narrow custom roles, PIM/JIT activation and documented break-glass exceptions.' `
                -Reference 'https://learn.microsoft.com/azure/role-based-access-control/best-practices'
        }
    }
}

function Test-CaAzureGraphApplicationPermissions {
    Invoke-CaCheck -Service Azure -CheckId 'AZURE-003' -Title 'Application permissions avoid high-risk Microsoft Graph roles' -Body {
        $bl = Get-CaBaseline
        $highRiskRoles = ConvertTo-CaStringList $bl.Azure.HighRiskGraphAppRoles
        if ($highRiskRoles.Count -eq 0) {
            return New-CaFinding -Service Azure -CheckId 'AZURE-003' -Title 'Application permissions avoid high-risk Microsoft Graph roles' -Status Info `
                -Detail 'No high-risk Graph application roles are configured in the baseline.'
        }

        $graphSpResult = Invoke-CaAzJson -Arguments @('ad', 'sp', 'list', '--filter', "appId eq '00000003-0000-0000-c000-000000000000'") -AllowFailure
        if (-not $graphSpResult.Success -or @($graphSpResult.Json).Count -eq 0) {
            return New-CaFinding -Service Azure -CheckId 'AZURE-003' -Title 'Application permissions avoid high-risk Microsoft Graph roles' -Status Skipped `
                -SkippedReason 'Microsoft Graph service principal is not readable through az CLI.' -Detail $graphSpResult.Text
        }

        $graphSp = @($graphSpResult.Json) | Select-Object -First 1
        $roleById = @{}
        foreach ($role in @($graphSp.appRoles)) {
            if ($role.id -and $role.value) { $roleById[[string]$role.id] = [string]$role.value }
        }
        if ($roleById.Count -eq 0) {
            return New-CaFinding -Service Azure -CheckId 'AZURE-003' -Title 'Application permissions avoid high-risk Microsoft Graph roles' -Status Skipped `
                -SkippedReason 'Microsoft Graph app role catalog is empty in az output.'
        }

        $spResult = Invoke-CaAzJson -Arguments @('ad', 'sp', 'list', '--all') -AllowFailure
        if (-not $spResult.Success) {
            return New-CaFinding -Service Azure -CheckId 'AZURE-003' -Title 'Application permissions avoid high-risk Microsoft Graph roles' -Status Skipped `
                -SkippedReason 'Service principals are not readable through az CLI.' -Detail $spResult.Text
        }

        $offenders = [System.Collections.Generic.List[object]]::new()
        $errors = [System.Collections.Generic.List[string]]::new()
        foreach ($sp in @($spResult.Json)) {
            if ([string]::IsNullOrWhiteSpace([string]$sp.id)) { continue }
            $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments"
            $assignments = Invoke-CaAzRestJson -Uri $uri -AllowFailure
            if (-not $assignments.Success) {
                if ($errors.Count -lt 10) { $errors.Add("$($sp.displayName): $($assignments.Text)") }
                continue
            }

            foreach ($assignment in @($assignments.Json.value)) {
                if ([string]$assignment.resourceDisplayName -ne 'Microsoft Graph') { continue }
                $roleValue = $roleById[[string]$assignment.appRoleId]
                if ([string]::IsNullOrWhiteSpace($roleValue)) { continue }
                if ($highRiskRoles -notcontains $roleValue) { continue }
                $offenders.Add([pscustomobject]@{
                    ServicePrincipal = $sp.displayName
                    AppId            = $sp.appId
                    ObjectId         = $sp.id
                    GraphRole        = $roleValue
                })
            }
        }

        if ($offenders.Count -eq 0 -and $errors.Count -eq 0) {
            New-CaFinding -Service Azure -CheckId 'AZURE-003' -Title 'Application permissions avoid high-risk Microsoft Graph roles' -Status Pass `
                -Detail 'No high-risk Microsoft Graph application permissions found on service principals.' -Evidence $offenders
        }
        elseif ($offenders.Count -eq 0) {
            New-CaFinding -Service Azure -CheckId 'AZURE-003' -Title 'Application permissions avoid high-risk Microsoft Graph roles' -Status Warning -Severity Low `
                -Detail "No high-risk Graph roles found, but $($errors.Count) service principal assignment read(s) failed." -Evidence $errors `
                -Recommendation 'Grant directory read visibility or review failed service principals manually.'
        }
        else {
            New-CaFinding -Service Azure -CheckId 'AZURE-003' -Title 'Application permissions avoid high-risk Microsoft Graph roles' -Status Fail -Severity High `
                -Detail "$($offenders.Count) high-risk Microsoft Graph application permission assignment(s)." -Evidence $offenders `
                -Recommendation 'Review admin-consented application permissions, remove unused grants, and require approval workflow for privileged app roles.' `
                -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/manage-application-permissions'
        }
    }
}

function Test-CaAzureStorageExposure {
    Invoke-CaCheck -Service Azure -CheckId 'AZURE-004' -Title 'Storage accounts avoid public data exposure' -Body {
        $bl = Get-CaBaseline
        $requireDefaultDeny = $false
        if ($bl.Azure.PSObject.Properties.Name -contains 'RequireStorageDefaultDeny') {
            $requireDefaultDeny = [bool]$bl.Azure.RequireStorageDefaultDeny
        }

        $r = Invoke-CaAzJson -Arguments @('storage', 'account', 'list') -AllowFailure
        if (-not $r.Success) {
            return New-CaFinding -Service Azure -CheckId 'AZURE-004' -Title 'Storage accounts avoid public data exposure' -Status Skipped `
                -SkippedReason 'Storage accounts are not readable with current az context.' -Detail $r.Text
        }

        $issues = [System.Collections.Generic.List[object]]::new()
        foreach ($sa in @($r.Json)) {
            $allowBlobPublicAccess = [bool](Get-CaAzureProperty -Object $sa -Name 'allowBlobPublicAccess')
            $publicNetworkAccess = [string](Get-CaAzureProperty -Object $sa -Name 'publicNetworkAccess')
            $defaultAction = [string]$sa.networkRuleSet.defaultAction
            if ($allowBlobPublicAccess -or ($requireDefaultDeny -and $defaultAction -ne 'Deny')) {
                $issues.Add([pscustomobject]@{
                    Name                  = $sa.name
                    ResourceGroup         = $sa.resourceGroup
                    AllowBlobPublicAccess = $allowBlobPublicAccess
                    PublicNetworkAccess   = $publicNetworkAccess
                    DefaultNetworkAction  = $defaultAction
                })
            }
        }

        if ($issues.Count -eq 0) {
            New-CaFinding -Service Azure -CheckId 'AZURE-004' -Title 'Storage accounts avoid public data exposure' -Status Pass `
                -Detail 'No storage account allows blob public access; network baseline satisfied.' -Evidence $r.Json
        }
        else {
            New-CaFinding -Service Azure -CheckId 'AZURE-004' -Title 'Storage accounts avoid public data exposure' -Status Fail -Severity High `
                -Detail "$($issues.Count) storage account exposure issue(s)." -Evidence $issues `
                -Recommendation 'Disable blob public access and restrict storage account network access unless explicitly approved for public content.' `
                -Reference 'https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent'
        }
    }
}

function Test-CaAzureKeyVaultProtection {
    Invoke-CaCheck -Service Azure -CheckId 'AZURE-005' -Title 'Key Vaults have purge protection and controlled network exposure' -Body {
        $bl = Get-CaBaseline
        $requirePurge = if ($bl.Azure.PSObject.Properties.Name -contains 'RequireKeyVaultPurgeProtection') { [bool]$bl.Azure.RequireKeyVaultPurgeProtection } else { $true }
        $r = Invoke-CaAzJson -Arguments @('keyvault', 'list') -AllowFailure
        if (-not $r.Success) {
            return New-CaFinding -Service Azure -CheckId 'AZURE-005' -Title 'Key Vaults have purge protection and controlled network exposure' -Status Skipped `
                -SkippedReason 'Key Vaults are not readable with current az context.' -Detail $r.Text
        }

        $issues = [System.Collections.Generic.List[object]]::new()
        foreach ($kv in @($r.Json)) {
            $purge = Get-CaAzureProperty -Object $kv -Name 'enablePurgeProtection'
            if ($null -eq $purge) { $purge = $kv.properties.enablePurgeProtection }
            $publicNetworkAccess = [string](Get-CaAzureProperty -Object $kv -Name 'publicNetworkAccess')
            if ([string]::IsNullOrWhiteSpace($publicNetworkAccess)) { $publicNetworkAccess = [string]$kv.properties.publicNetworkAccess }
            $defaultAction = [string]$kv.properties.networkAcls.defaultAction
            if (($requirePurge -and -not [bool]$purge) -or ($defaultAction -eq 'Allow' -and $publicNetworkAccess -eq 'Enabled')) {
                $issues.Add([pscustomobject]@{
                    Name                = $kv.name
                    ResourceGroup       = $kv.resourceGroup
                    PurgeProtection     = [bool]$purge
                    PublicNetworkAccess = $publicNetworkAccess
                    DefaultAction       = $defaultAction
                })
            }
        }

        if ($issues.Count -eq 0) {
            New-CaFinding -Service Azure -CheckId 'AZURE-005' -Title 'Key Vaults have purge protection and controlled network exposure' -Status Pass `
                -Detail 'All discovered Key Vaults satisfy purge protection and network exposure baseline.' -Evidence $r.Json
        }
        else {
            New-CaFinding -Service Azure -CheckId 'AZURE-005' -Title 'Key Vaults have purge protection and controlled network exposure' -Status Fail -Severity High `
                -Detail "$($issues.Count) Key Vault protection issue(s)." -Evidence $issues `
                -Recommendation 'Enable purge protection and restrict public network access/default allow rules for production vaults.' `
                -Reference 'https://learn.microsoft.com/azure/key-vault/general/security-features'
        }
    }
}

function Test-CaAzurePublicIpInventory {
    Invoke-CaCheck -Service Azure -CheckId 'AZURE-006' -Title 'Azure public IP exposure inventory captured' -Body {
        $r = Invoke-CaAzJson -Arguments @('network', 'public-ip', 'list') -AllowFailure
        if (-not $r.Success) {
            return New-CaFinding -Service Azure -CheckId 'AZURE-006' -Title 'Azure public IP exposure inventory captured' -Status Skipped `
                -SkippedReason 'Public IP resources are not readable with current az context.' -Detail $r.Text
        }

        $ips = @($r.Json | Where-Object { $_ })
        $assigned = @($ips | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.ipAddress) })
        New-CaFinding -Service Azure -CheckId 'AZURE-006' -Title 'Azure public IP exposure inventory captured' -Status Info `
            -Detail "$($ips.Count) public IP resource(s) found; $($assigned.Count) currently assigned." -Evidence $ips
    }
}
