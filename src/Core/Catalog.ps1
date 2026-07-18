<#
    Catalog.ps1 - service registry and provider runtime options.

    Services are data, not hardcoded ValidateSet lists. This keeps the public
    runner/wizard extensible while preserving the small auto-discovery model:
    Test-Ca<Service>* functions are still the only thing needed to add checks.
#>

$script:CaServiceCatalog = [ordered]@{
    Entra      = [pscustomobject]@{ Name = 'Entra';      Prefix = 'Entra';      Provider = 'Microsoft365'; RequiresGraph = $true;  RequiresExchange = $false; Default = $true;  Description = 'Microsoft Entra ID tenant controls' }
    Exchange   = [pscustomobject]@{ Name = 'Exchange';   Prefix = 'Exchange';   Provider = 'Microsoft365'; RequiresGraph = $false; RequiresExchange = $true;  Default = $true;  Description = 'Exchange Online tenant controls' }
    SharePoint = [pscustomobject]@{ Name = 'SharePoint'; Prefix = 'SharePoint'; Provider = 'Microsoft365'; RequiresGraph = $true;  RequiresExchange = $false; Default = $true;  Description = 'SharePoint Online tenant controls' }
    OneDrive   = [pscustomobject]@{ Name = 'OneDrive';   Prefix = 'OneDrive';   Provider = 'Microsoft365'; RequiresGraph = $true;  RequiresExchange = $false; Default = $true;  Description = 'OneDrive tenant controls' }
    Azure      = [pscustomobject]@{ Name = 'Azure';      Prefix = 'Azure';      Provider = 'Azure';        RequiresGraph = $false; RequiresExchange = $false; Default = $false; Description = 'Azure subscription posture via az CLI' }
    AWS        = [pscustomobject]@{ Name = 'AWS';        Prefix = 'Aws';        Provider = 'AWS';          RequiresGraph = $false; RequiresExchange = $false; Default = $false; Description = 'AWS account and regional posture via aws CLI' }
    GCP        = [pscustomobject]@{ Name = 'GCP';        Prefix = 'Gcp';        Provider = 'GCP';          RequiresGraph = $false; RequiresExchange = $false; Default = $false; Description = 'Google Cloud project posture via gcloud CLI' }
    Tailscale  = [pscustomobject]@{ Name = 'Tailscale';  Prefix = 'Tailscale';  Provider = 'SaaS';         RequiresGraph = $false; RequiresExchange = $false; Default = $false; Description = 'Tailscale tailnet posture via API token' }
    Domain     = [pscustomobject]@{ Name = 'Domain';     Prefix = 'Domain';     Provider = 'Internet';     RequiresGraph = $false; RequiresExchange = $false; Default = $false; Description = 'Authorized public-domain DNS and email exposure checks' }
    VPS        = [pscustomobject]@{ Name = 'VPS';        Prefix = 'Vps';        Provider = 'VPS';          RequiresGraph = $false; RequiresExchange = $false; Default = $false; Description = 'Linux VPS host posture via local shell or read-only SSH commands' }
    Inventory  = [pscustomobject]@{ Name = 'Inventory';  Prefix = 'Inventory';  Provider = 'MultiCloud';   RequiresGraph = $false; RequiresExchange = $false; Default = $false; Description = 'Normalized multi-cloud asset inventory' }
}

$script:CaProviderOptions = @{
    AZURE = [ordered]@{
        Subscription = ''
        Tenant = ''
    }
    AWS = [ordered]@{
        Profile = ''
        Regions = @()
    }
    GCP = [ordered]@{
        Project = ''
        Account = ''
        Organization = ''
    }
    TAILSCALE = [ordered]@{
        Tailnet = ''
        ApiTokenEnv = 'TAILSCALE_API_TOKEN'
        AuthScheme = 'Auto'
    }
    DOMAIN = [ordered]@{
        Domains = @()
        Subdomains = @('www', 'autodiscover', 'mail', 'vpn', 'portal', 'admin', 'dev', 'staging')
    }
    VPS = [ordered]@{
        Target = ''
        SshUser = ''
        SshPort = 22
        AllowedPublicPorts = @()
    }
    INVENTORY = [ordered]@{
        MaxItems = 500
    }
}

function Get-CaServiceCatalog {
    [CmdletBinding()]
    param()
    foreach ($name in $script:CaServiceCatalog.Keys) { $script:CaServiceCatalog[$name] }
}

function Get-CaServiceNames {
    [CmdletBinding()]
    param([switch]$IncludeAll)
    $names = @($script:CaServiceCatalog.Keys)
    if ($IncludeAll) { return @('All', 'M365') + $names }
    return $names
}

function Get-CaDefaultServices {
    [CmdletBinding()]
    param()
    @($script:CaServiceCatalog.Keys | Where-Object { $script:CaServiceCatalog[$_].Default })
}

function Get-CaMicrosoft365Services {
    [CmdletBinding()]
    param()
    @($script:CaServiceCatalog.Keys | Where-Object { $script:CaServiceCatalog[$_].Provider -eq 'Microsoft365' })
}

function Get-CaAuthCatalog {
    [CmdletBinding()]
    param()

    @(
        [pscustomobject]@{
            Provider       = 'Internet'
            Method         = 'Public'
            Level          = 'Unauthenticated'
            Description    = 'Authorized public-domain DNS, mail and takeover exposure checks. No credential is accepted or needed.'
            RequiredInputs = @('Domain')
            SecretInputs   = @()
        }
        [pscustomobject]@{
            Provider       = 'Microsoft365'
            Method         = 'DelegatedDeviceCode'
            Level          = 'DelegatedReadOnly'
            Description    = 'Operator signs in with device code and read-only Graph/Exchange scopes.'
            RequiredInputs = @('Tenant operator account')
            SecretInputs   = @()
        }
        [pscustomobject]@{
            Provider       = 'Microsoft365'
            Method         = 'DelegatedBrowser'
            Level          = 'DelegatedReadOnly'
            Description    = 'Operator signs in through a temporary local browser profile with PKCE.'
            RequiredInputs = @('Tenant operator account')
            SecretInputs   = @()
        }
        [pscustomobject]@{
            Provider       = 'Microsoft365'
            Method         = 'AppCertificate'
            Level          = 'ApplicationReadOnly'
            Description    = 'App-only certificate authentication for unattended tenant checks. Client secrets are intentionally unsupported.'
            RequiredInputs = @('TenantId', 'ClientId', 'CertificateThumbprint')
            SecretInputs   = @()
        }
        [pscustomobject]@{
            Provider       = 'Azure'
            Method         = 'AzCli'
            Level          = 'CliReadOnly'
            Description    = 'Uses the current Azure CLI identity; service principals and managed identities should authenticate with az before Claudit runs.'
            RequiredInputs = @('az login context')
            SecretInputs   = @()
        }
        [pscustomobject]@{
            Provider       = 'AWS'
            Method         = 'AwsCliProfile'
            Level          = 'CliReadOnly'
            Description    = 'Uses AWS CLI profile, SSO or environment credentials already configured with read-only permissions.'
            RequiredInputs = @('aws CLI context')
            SecretInputs   = @()
        }
        [pscustomobject]@{
            Provider       = 'GCP'
            Method         = 'Gcloud'
            Level          = 'CliReadOnly'
            Description    = 'Uses gcloud account/project context. Service-account JSON should be activated in gcloud before the run.'
            RequiredInputs = @('gcloud context')
            SecretInputs   = @()
        }
        [pscustomobject]@{
            Provider       = 'SaaS'
            Method         = 'ApiTokenEnv'
            Level          = 'TokenReadOnly'
            Description    = 'Reads API token from an environment variable; the token value is never persisted in profiles or reports.'
            RequiredInputs = @('Tailnet', 'Token environment variable')
            SecretInputs   = @('API token value')
        }
        [pscustomobject]@{
            Provider       = 'VPS'
            Method         = 'LocalOrSsh'
            Level          = 'HostReadOnly'
            Description    = 'Runs POSIX read-only commands locally or through OpenSSH BatchMode against an operator-supplied Linux VPS target.'
            RequiredInputs = @('Local shell or SSH target')
            SecretInputs   = @()
        }
    )
}

function Get-CaAuthPlan {
    [CmdletBinding()]
    param(
        [string[]]$Service,
        [ValidateSet('Interactive', 'AppOnly')]
        [string]$AuthMode = 'Interactive',
        [ValidateSet('DeviceCode', 'Browser')]
        [string]$GraphAuthMode = 'DeviceCode'
    )

    $resolved = Resolve-CaServices -Service $Service
    $specs = @($resolved | ForEach-Object { Get-CaServiceSpec -Name $_ })
    $plan = [System.Collections.Generic.List[object]]::new()

    if ($resolved -contains 'Domain') {
        $plan.Add([pscustomobject]@{
            Stage       = 10
            Name        = 'Public domain recon'
            AuthLevel   = 'Unauthenticated'
            Provider    = 'Internet'
            Services    = @('Domain')
            Method      = 'Public'
            Gate        = 'Authorized domain scope'
            Description = 'Runs DNS, mail posture and dangling-reference checks against only the configured domains.'
        })
    }

    $m365 = @($specs | Where-Object Provider -eq 'Microsoft365' | ForEach-Object Name)
    if ($m365.Count -gt 0) {
        $method = if ($AuthMode -eq 'AppOnly') { 'AppCertificate' } elseif ($GraphAuthMode -eq 'Browser') { 'DelegatedBrowser' } else { 'DelegatedDeviceCode' }
        $plan.Add([pscustomobject]@{
            Stage       = 20
            Name        = 'Microsoft 365 credential gate'
            AuthLevel   = if ($AuthMode -eq 'AppOnly') { 'ApplicationReadOnly' } else { 'DelegatedReadOnly' }
            Provider    = 'Microsoft365'
            Services    = @($m365)
            Method      = $method
            Gate        = 'Graph/Exchange read-only connection'
            Description = 'Validates tenant identity and requested read-only access before any authenticated checks run.'
        })
        $plan.Add([pscustomobject]@{
            Stage       = 30
            Name        = 'Microsoft 365 authenticated controls'
            AuthLevel   = 'Authenticated'
            Provider    = 'Microsoft365'
            Services    = @($m365)
            Method      = $method
            Gate        = 'Connected session'
            Description = 'Runs Entra, Exchange, SharePoint and OneDrive controls allowed by the selected identity.'
        })
    }

    foreach ($provider in @('Azure', 'AWS', 'GCP', 'SaaS', 'VPS', 'MultiCloud')) {
        $items = @($specs | Where-Object Provider -eq $provider | ForEach-Object Name)
        if ($items.Count -eq 0) { continue }
        $method = switch ($provider) {
            'Azure' { 'AzCli' }
            'AWS' { 'AwsCliProfile' }
            'GCP' { 'Gcloud' }
            'SaaS' { 'ApiTokenEnv' }
            'VPS' { 'LocalOrSsh' }
            default { 'ExistingProviderContexts' }
        }
        $plan.Add([pscustomobject]@{
            Stage       = 20
            Name        = "$provider credential gate"
            AuthLevel   = 'ReadOnlyContext'
            Provider    = $provider
            Services    = @($items)
            Method      = $method
            Gate        = 'CLI/API identity validation'
            Description = 'Checks local identity selectors first; live API permissions are verified by the provider check cycle.'
        })
        $plan.Add([pscustomobject]@{
            Stage       = 30
            Name        = "$provider authenticated controls"
            AuthLevel   = 'Authenticated'
            Provider    = $provider
            Services    = @($items)
            Method      = $method
            Gate        = 'Provider read-only context'
            Description = 'Runs posture and inventory checks reachable with the selected read-only identity.'
        })
    }

    @($plan | Sort-Object Stage, Provider, Name)
}

function Resolve-CaServiceName {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    if ($Name -ieq 'All') { return 'All' }
    if ($Name -match '^(M365|Microsoft365|Microsoft 365|O365|Office365|Office 365)$') { return 'M365' }
    foreach ($key in $script:CaServiceCatalog.Keys) {
        if ($key -ieq $Name) { return $key }
    }
    throw "Unknown Claudit service '$Name'. Valid values: $((Get-CaServiceNames -IncludeAll) -join ', ')."
}

function Resolve-CaServices {
    [CmdletBinding()]
    param([string[]]$Service)

    if (-not $Service -or $Service.Count -eq 0) {
        $Service = Get-CaDefaultServices
    }

    $requested = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($raw in $Service) {
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        foreach ($token in ($raw -split ',')) {
            $name = Resolve-CaServiceName -Name $token.Trim()
            if ($name -eq 'All') {
                foreach ($svc in $script:CaServiceCatalog.Keys) { [void]$requested.Add($svc) }
            }
            elseif ($name -eq 'M365') {
                foreach ($svc in (Get-CaMicrosoft365Services)) { [void]$requested.Add($svc) }
            }
            else {
                [void]$requested.Add($name)
            }
        }
    }

    $ordered = [System.Collections.Generic.List[string]]::new()
    foreach ($svc in $script:CaServiceCatalog.Keys) {
        if ($requested.Contains($svc)) { $ordered.Add($svc) }
    }
    if ($ordered.Count -eq 0) { throw 'No valid Claudit services selected.' }
    return @($ordered)
}

function Get-CaServiceSpec {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    $resolved = Resolve-CaServiceName -Name $Name
    if ($resolved -eq 'All') { throw 'All is a selector, not a concrete service.' }
    if ($resolved -eq 'M365') { throw 'M365 is a selector, not a concrete service.' }
    return $script:CaServiceCatalog[$resolved]
}

function Assert-CaServices {
    [CmdletBinding()]
    param([string[]]$Service)
    [void](Resolve-CaServices -Service $Service)
}

function Set-CaProviderOption {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Provider,
        [Parameter(Mandatory)][hashtable]$Options
    )

    $providerKey = $Provider.ToUpperInvariant()
    if (-not $script:CaProviderOptions.ContainsKey($providerKey)) {
        throw "Unknown provider '$Provider'. Valid providers: $($script:CaProviderOptions.Keys -join ', ')."
    }

    foreach ($key in $Options.Keys) {
        $script:CaProviderOptions[$providerKey][$key] = $Options[$key]
    }
}

function Get-CaProviderOption {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Provider)

    $providerKey = $Provider.ToUpperInvariant()
    if (-not $script:CaProviderOptions.ContainsKey($providerKey)) {
        throw "Unknown provider '$Provider'. Valid providers: $($script:CaProviderOptions.Keys -join ', ')."
    }

    $copy = [ordered]@{}
    foreach ($key in $script:CaProviderOptions[$providerKey].Keys) {
        $copy[$key] = $script:CaProviderOptions[$providerKey][$key]
    }
    [pscustomobject]$copy
}
