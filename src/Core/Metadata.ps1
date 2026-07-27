<#
    Metadata.ps1 - validated operational metadata for every production check.

    Prowler keeps check behavior and check metadata separate. Claudit uses a
    smaller profile/assignment model: common risk language stays reusable while
    exceptional controls can override severity, threats and relationships.
#>

$script:CaCheckMetadataCatalogPath = Join-Path $PSScriptRoot '..\..\config\check-metadata.json'
$script:CaCheckMetadataCatalog = $null
$script:CaCheckMetadataMap = @{}

function Get-CaMetadataProperty {
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string]$Name,
        $Default = $null
    )

    if ($InputObject.PSObject.Properties.Name -contains $Name) { return $InputObject.$Name }
    return $Default
}

function Test-CaMetadataStringList {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Issues,
        [Parameter(Mandatory)][string]$Owner,
        [Parameter(Mandatory)][string]$Field,
        [object[]]$Values,
        [switch]$AllowEmpty
    )

    $items = @($Values)
    if (-not $AllowEmpty -and $items.Count -eq 0) { $Issues.Add("missing $Field for '$Owner'"); return }
    foreach ($item in $items) {
        if ([string]$item -notmatch '^[a-z0-9][a-z0-9-]{1,63}$') {
            $Issues.Add("invalid $Field value '$item' for '$Owner'")
        }
    }
}

function Import-CaCheckMetadataCatalog {
    [CmdletBinding()]
    param([string]$Path = $script:CaCheckMetadataCatalogPath)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Claudit check metadata catalog not found: $Path"
    }
    try {
        $catalog = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Invalid Claudit check metadata JSON: $($_.Exception.Message)"
    }

    $issues = [System.Collections.Generic.List[string]]::new()
    $version = [string](Get-CaMetadataProperty -InputObject $catalog -Name 'CatalogVersion')
    if ($version -notmatch '^\d{4}\.\d{2}\.\d+$') { $issues.Add('invalid CatalogVersion') }

    $profiles = @{}
    foreach ($profile in @(Get-CaMetadataProperty -InputObject $catalog -Name 'Profiles' -Default @())) {
        $name = [string](Get-CaMetadataProperty -InputObject $profile -Name 'Name')
        if ($name -notmatch '^[a-z][a-z0-9-]{2,63}$') { $issues.Add("invalid profile '$name'"); continue }
        if ($profiles.ContainsKey($name)) { $issues.Add("duplicate profile '$name'"); continue }
        $profiles[$name] = $profile
        if ([string](Get-CaMetadataProperty -InputObject $profile -Name 'DefaultSeverity') -notin @('Critical', 'High', 'Medium', 'Low', 'Info')) {
            $issues.Add("invalid DefaultSeverity for profile '$name'")
        }
        foreach ($field in @('Description', 'Risk', 'Remediation')) {
            if ([string]::IsNullOrWhiteSpace([string](Get-CaMetadataProperty -InputObject $profile -Name $field))) {
                $issues.Add("missing $field for profile '$name'")
            }
        }
        Test-CaMetadataStringList -Issues $issues -Owner $name -Field Categories -Values @(Get-CaMetadataProperty -InputObject $profile -Name 'Categories' -Default @())
        Test-CaMetadataStringList -Issues $issues -Owner $name -Field Threats -Values @(Get-CaMetadataProperty -InputObject $profile -Name 'Threats' -Default @())
    }
    if ($profiles.Count -eq 0) { $issues.Add('no metadata profiles') }

    $controlIds = @((Get-CaControlCatalog).Controls.CheckId | ForEach-Object { [string]$_ })
    $knownIds = @{}; foreach ($id in $controlIds) { $knownIds[$id] = $true }
    $assignments = @{}
    foreach ($assignment in @(Get-CaMetadataProperty -InputObject $catalog -Name 'Assignments' -Default @())) {
        $profileName = [string](Get-CaMetadataProperty -InputObject $assignment -Name 'Profile')
        if (-not $profiles.ContainsKey($profileName)) { $issues.Add("assignment references unknown profile '$profileName'") }
        foreach ($idValue in @(Get-CaMetadataProperty -InputObject $assignment -Name 'CheckIds' -Default @())) {
            $id = [string]$idValue
            if ($id -notmatch '^[A-Z]+-\d{3}$') { $issues.Add("invalid assigned CheckId '$id'"); continue }
            if ($assignments.ContainsKey($id)) { $issues.Add("duplicate metadata assignment '$id'") }
            else { $assignments[$id] = $profileName }
            if (-not $knownIds.ContainsKey($id)) { $issues.Add("metadata assignment has unknown CheckId '$id'") }
        }
    }
    foreach ($id in $controlIds) {
        if (-not $assignments.ContainsKey($id)) { $issues.Add("missing metadata assignment '$id'") }
    }

    $overrides = @{}
    foreach ($override in @(Get-CaMetadataProperty -InputObject $catalog -Name 'Overrides' -Default @())) {
        $id = [string](Get-CaMetadataProperty -InputObject $override -Name 'CheckId')
        if (-not $knownIds.ContainsKey($id)) { $issues.Add("metadata override has unknown CheckId '$id'"); continue }
        if ($overrides.ContainsKey($id)) { $issues.Add("duplicate metadata override '$id'"); continue }
        $overrides[$id] = $override
        $severity = [string](Get-CaMetadataProperty -InputObject $override -Name 'DefaultSeverity')
        if ($severity -and $severity -notin @('Critical', 'High', 'Medium', 'Low', 'Info')) {
            $issues.Add("invalid override DefaultSeverity for '$id'")
        }
        foreach ($field in @('Categories', 'Threats')) {
            if ($override.PSObject.Properties.Name -contains $field) {
                Test-CaMetadataStringList -Issues $issues -Owner $id -Field $field -Values @($override.$field)
            }
        }
        foreach ($field in @('DependsOn', 'RelatedTo')) {
            foreach ($relatedValue in @(Get-CaMetadataProperty -InputObject $override -Name $field -Default @())) {
                $related = [string]$relatedValue
                if (-not $knownIds.ContainsKey($related)) { $issues.Add("$field for '$id' references unknown CheckId '$related'") }
                if ($related -eq $id) { $issues.Add("$field for '$id' references itself") }
            }
        }
    }

    if ($issues.Count -gt 0) { throw "Invalid Claudit check metadata catalog: $($issues -join '; ')." }

    $resolved = @{}
    foreach ($id in $controlIds) {
        $profileName = $assignments[$id]
        $profile = $profiles[$profileName]
        $override = if ($overrides.ContainsKey($id)) { $overrides[$id] } else { $null }
        $read = {
            param($Name, $Default)
            if ($override -and $override.PSObject.Properties.Name -contains $Name) { return $override.$Name }
            return $Default
        }
        $resolved[$id] = [pscustomobject]@{
            CatalogVersion  = $version
            CheckId         = $id
            Profile         = $profileName
            DefaultSeverity = [string](& $read 'DefaultSeverity' $profile.DefaultSeverity)
            Categories      = @(& $read 'Categories' @($profile.Categories) | ForEach-Object { [string]$_ })
            Threats         = @(& $read 'Threats' @($profile.Threats) | ForEach-Object { [string]$_ })
            Description     = [string](& $read 'Description' $profile.Description)
            Risk            = [string](& $read 'Risk' $profile.Risk)
            Remediation     = [string](& $read 'Remediation' $profile.Remediation)
            DependsOn       = @(& $read 'DependsOn' @() | ForEach-Object { [string]$_ })
            RelatedTo       = @(& $read 'RelatedTo' @() | ForEach-Object { [string]$_ })
            Source          = if ($override) { "profile:$profileName+override:$id" } else { "profile:$profileName" }
        }
    }

    [pscustomobject]@{ Catalog=$catalog; Resolved=$resolved }
}

$importedMetadata = Import-CaCheckMetadataCatalog
$script:CaCheckMetadataCatalog = $importedMetadata.Catalog
$script:CaCheckMetadataMap = $importedMetadata.Resolved

function Get-CaCheckMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[A-Z]+-\d{3}$')][string]$CheckId,
        [switch]$AllowUncataloged
    )

    if (-not $script:CaCheckMetadataMap.ContainsKey($CheckId)) {
        if (-not $AllowUncataloged) { throw "No check metadata for '$CheckId'." }
        return [pscustomobject]@{
            CatalogVersion  = [string]$script:CaCheckMetadataCatalog.CatalogVersion
            CheckId         = $CheckId
            Profile         = 'runtime-unclassified'
            DefaultSeverity = 'Medium'
            Categories      = @('diagnostics')
            Threats         = @('visibility-gap')
            Description     = 'Runtime or compatibility finding outside the production control catalog.'
            Risk            = 'An uncataloged runtime result lacks the richer risk context assigned to production controls.'
            Remediation     = 'Inspect the diagnostic context and add a production catalog entry if this identifier becomes a supported control.'
            DependsOn       = @()
            RelatedTo       = @()
            Source          = 'runtime-fallback'
        }
    }
    $script:CaCheckMetadataMap[$CheckId] | ConvertTo-Json -Depth 8 | ConvertFrom-Json
}

function Get-CaCheckMetadataCatalog {
    [CmdletBinding()]
    param()

    $script:CaCheckMetadataCatalog | ConvertTo-Json -Depth 12 | ConvertFrom-Json
}
