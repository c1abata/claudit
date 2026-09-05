<#
    Controls.ps1 - validated loader for the versioned control catalog.

    Mapping data lives in config/control-catalog.json so reviewers and GRC
    tooling can inspect it without executing PowerShell. Missing, duplicate or
    malformed control records fail module import instead of silently dropping
    governance context.
#>

$script:CaControlCatalogPath = Join-Path $PSScriptRoot '..\..\config\control-catalog.json'
$script:CaControlCatalog = $null
$script:CaControlMap = @{}
$script:CaControlLevelMap = @{}

function Import-CaControlCatalog {
    if (-not (Test-Path -LiteralPath $script:CaControlCatalogPath -PathType Leaf)) {
        throw "Claudit control catalog not found: $script:CaControlCatalogPath"
    }
    try {
        $catalog = Get-Content -LiteralPath $script:CaControlCatalogPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Invalid Claudit control catalog JSON: $($_.Exception.Message)"
    }
    $issues = [System.Collections.Generic.List[string]]::new()
    if ([string]::IsNullOrWhiteSpace([string]$catalog.CatalogVersion)) { $issues.Add('missing CatalogVersion') }
    if ($null -eq $catalog.Controls -or @($catalog.Controls).Count -eq 0) { $issues.Add('no controls') }
    $seen = @{}
    foreach ($control in @($catalog.Controls)) {
        $id = [string]$control.CheckId
        if ($id -notmatch '^[A-Z]+-\d{3}$') { $issues.Add("invalid CheckId '$id'"); continue }
        if ($seen.ContainsKey($id)) { $issues.Add("duplicate CheckId '$id'") } else { $seen[$id] = $true }
        if ([string]$control.ImplementationStatus -notin @('Automated', 'Manual', 'Unimplemented')) {
            $issues.Add("invalid implementation status for '$id'")
        }
        if (@($control.Mappings).Count -eq 0) { $issues.Add("no mapping for '$id'") }
    }
    $defaultLevel = [string]$catalog.DefaultControlLevel
    if ($defaultLevel -notin @('Formal', 'Passive', 'Active')) {
        $issues.Add('DefaultControlLevel must be Formal, Passive or Active')
    }
    if ($null -eq $catalog.ControlLevelOverrides) {
        $issues.Add('missing ControlLevelOverrides')
    }
    else {
        foreach ($property in @($catalog.ControlLevelOverrides.PSObject.Properties)) {
            if (-not $seen.ContainsKey([string]$property.Name)) {
                $issues.Add("control-level override references unknown CheckId '$($property.Name)'")
            }
            if ([string]$property.Value -notin @('Formal', 'Passive', 'Active')) {
                $issues.Add("invalid control level for '$($property.Name)'")
            }
        }
    }
    if ($issues.Count -gt 0) { throw "Invalid Claudit control catalog: $($issues -join '; ')." }
    return $catalog
}

$script:CaControlCatalog = Import-CaControlCatalog
foreach ($control in @($script:CaControlCatalog.Controls)) {
    $checkId = [string]$control.CheckId
    $script:CaControlMap[$checkId] = @($control.Mappings | ForEach-Object { [string]$_ })
    $override = $script:CaControlCatalog.ControlLevelOverrides.PSObject.Properties[$checkId]
    $script:CaControlLevelMap[$checkId] = if ($override) {
        [string]$override.Value
    }
    else {
        [string]$script:CaControlCatalog.DefaultControlLevel
    }
}

function Get-CaControlIds {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$CheckId)
    if ($script:CaControlMap.ContainsKey($CheckId)) { return @($script:CaControlMap[$CheckId]) }
    return @()
}

function Get-CaControlCatalog {
    [CmdletBinding()]
    param()

    # Return a copy so a caller cannot mutate module-wide control mappings.
    $script:CaControlCatalog | ConvertTo-Json -Depth 10 | ConvertFrom-Json
}

function Get-CaExpectedCheckIds {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Service,
        [Parameter(Mandatory)][ValidateSet('Formal', 'Passive', 'Active')][string]$ControlLevel
    )

    $canonicalService = (Get-CaServiceSpec -Name $Service).Name
    $prefix = @{
        Entra='ENTRA'; Exchange='EXO'; SharePoint='SPO'; OneDrive='OD'
        Azure='AZURE'; AWS='AWS'; GCP='GCP'; Tailscale='TAILSCALE'
        Domain='DOMAIN'; VPS='VPS'; Inventory='INV'
    }[$canonicalService]
    if ([string]::IsNullOrWhiteSpace([string]$prefix)) {
        throw "No control-catalog prefix is defined for service '$canonicalService'."
    }

    $rank = @{ Formal=1; Passive=2; Active=3 }
    @($script:CaControlCatalog.Controls |
        Where-Object {
            $_.CheckId -like "$prefix-*" -and
            $rank[$script:CaControlLevelMap[[string]$_.CheckId]] -le $rank[$ControlLevel]
        } |
        ForEach-Object { [string]$_.CheckId } |
        Sort-Object -Unique)
}
