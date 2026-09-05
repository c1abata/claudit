#Requires -Version 7.2
<#
.SYNOPSIS
    Guided sysadmin wizard for safe Claudit execution.

.DESCRIPTION
    Builds an idempotent run profile, runs offline preflight, and starts a live
    read-only tenant audit only after explicit confirmation. The wizard stores
    non-secret preferences only; webhook URLs and certificate material are never
    persisted.
#>
[CmdletBinding()]
param(
    [string]$ProfilePath,
    [switch]$UseDefaults,
    [switch]$NoLive,

    [Alias('h', '?')]
    [switch]$Help,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArguments
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
$moduleManifest = Join-Path $root 'Claudit.psd1'
Import-Module $moduleManifest -Force -ErrorAction Stop
if (Test-CaHelpRequested -Help:$Help -RemainingArguments $RemainingArguments -InvocationLine $MyInvocation.Line) {
    Show-CaCommandHelp -Command $PSCommandPath
    exit 0
}
Assert-CaNoRemainingArgument -RemainingArguments $RemainingArguments

$script:LegacyWizardProfilePath = $null
if (-not $ProfilePath) {
    $configRoot = if ($IsWindows -and -not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        Join-Path $env:LOCALAPPDATA 'Claudit'
    }
    elseif (-not [string]::IsNullOrWhiteSpace($env:XDG_CONFIG_HOME)) {
        Join-Path $env:XDG_CONFIG_HOME 'claudit'
    }
    elseif (-not [string]::IsNullOrWhiteSpace($HOME)) {
        Join-Path (Join-Path $HOME '.config') 'claudit'
    }
    else {
        throw 'Cannot resolve a private user configuration directory. Pass -ProfilePath explicitly.'
    }
    $ProfilePath = Join-Path $configRoot 'wizard.profile.json'
    $script:LegacyWizardProfilePath = Join-Path $root 'config\wizard.profile.json'
}
$ProfilePath = [System.IO.Path]::GetFullPath($ProfilePath)

$script:Accent = 'Cyan'
$script:Muted = 'DarkGray'
$script:Good = 'Green'
$script:Warn = 'Yellow'
$script:Bad = 'Red'

function Write-WizardLine {
    param(
        [string]$Text = '',
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )
    Write-Host $Text -ForegroundColor $Color
}

function Write-WizardRule {
    param([string]$Title)
    Write-Host ''
    Write-WizardLine ('=' * 76) $script:Accent
    Write-WizardLine ("  $Title") $script:Accent
    Write-WizardLine ('=' * 76) $script:Accent
}

function Write-WizardPanel {
    param(
        [string]$Title,
        [string[]]$Lines,
        [ConsoleColor]$Color = [ConsoleColor]::Cyan
    )
    $width = 76
    Write-Host ''
    Write-WizardLine ('+' + ('-' * ($width - 2)) + '+') $Color
    Write-WizardLine ('| ' + $Title.PadRight($width - 4) + ' |') $Color
    Write-WizardLine ('+' + ('-' * ($width - 2)) + '+') $Color
    foreach ($line in $Lines) {
        $text = if ($line.Length -gt ($width - 4)) { $line.Substring(0, $width - 7) + '...' } else { $line }
        Write-WizardLine ('| ' + $text.PadRight($width - 4) + ' |') $Color
    }
    Write-WizardLine ('+' + ('-' * ($width - 2)) + '+') $Color
}

function Read-WizardText {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [string]$Default = ''
    )
    if ($UseDefaults) { return $Default }
    $suffix = if ([string]::IsNullOrWhiteSpace($Default)) { '' } else { " [$Default]" }
    $value = Read-Host "$Prompt$suffix"
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value.Trim()
}

function Read-WizardYesNo {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [bool]$Default = $false
    )
    if ($UseDefaults) { return $Default }
    $hint = if ($Default) { 'Y/n' } else { 'y/N' }
    while ($true) {
        $value = (Read-Host "$Prompt [$hint]").Trim()
        if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
        if ($value -match '^(y|yes|s|si)$') { return $true }
        if ($value -match '^(n|no)$') { return $false }
        Write-WizardLine 'Risposta non valida. Usa y oppure n.' $script:Warn
    }
}

function Read-WizardChoice {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][string[]]$Options,
        [string]$Default
    )
    if ([string]::IsNullOrWhiteSpace($Default)) { $Default = $Options[0] }
    if ($UseDefaults) { return $Default }

    Write-WizardLine $Prompt $script:Accent
    for ($i = 0; $i -lt $Options.Count; $i++) {
        $mark = if ($Options[$i] -eq $Default) { '*' } else { ' ' }
        Write-WizardLine ("  [{0}] {1} {2}" -f ($i + 1), $mark, $Options[$i])
    }
    while ($true) {
        $value = (Read-Host "Selezione [default: $Default]").Trim()
        if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
        $idx = 0
        if ([int]::TryParse($value, [ref]$idx) -and $idx -ge 1 -and $idx -le $Options.Count) {
            return $Options[$idx - 1]
        }
        $match = $Options | Where-Object { $_ -ieq $value } | Select-Object -First 1
        if ($match) { return $match }
        Write-WizardLine 'Selezione non valida.' $script:Warn
    }
}

function Read-WizardServices {
    param([string[]]$Default = @('Entra', 'Exchange', 'SharePoint', 'OneDrive'))
    $catalog = @(Get-CaServiceCatalog)
    $all = @($catalog | ForEach-Object { $_.Name })
    $m365 = @(Get-CaMicrosoft365Services)
    if ($UseDefaults) { return $Default }

    Write-WizardLine 'Workload da auditare:' $script:Accent
    for ($i = 0; $i -lt $catalog.Count; $i++) {
        Write-WizardLine ("  {0}) {1} - {2}" -f ($i + 1), $catalog[$i].Name, $catalog[$i].Description)
    }
    Write-WizardLine 'Shortcut: M365 = tutte le aree Microsoft 365; All = tutti i provider.'
    Write-WizardLine 'Inserisci numeri separati da virgola, nomi servizi, M365 oppure All.'
    $defaultText = if (@(Resolve-CaServices -Service $Default).Count -eq $all.Count) {
        'All'
    }
    elseif (@(Compare-Object -ReferenceObject $m365 -DifferenceObject @(Resolve-CaServices -Service $Default)).Count -eq 0) {
        'M365'
    }
    else {
        $Default -join ','
    }
    while ($true) {
        $value = (Read-Host "Servizi [default: $defaultText]").Trim()
        if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
        try {
            $tokens = [System.Collections.Generic.List[string]]::new()
            foreach ($part in ($value -split ',')) {
                $token = $part.Trim()
                $idx = 0
                if ([int]::TryParse($token, [ref]$idx) -and $idx -ge 1 -and $idx -le $all.Count) {
                    $tokens.Add($all[$idx - 1])
                }
                else {
                    $tokens.Add($token)
                }
            }
            return @(Resolve-CaServices -Service @($tokens))
        }
        catch {
            Write-WizardLine "Selezione servizi non valida: $($_.Exception.Message)" $script:Warn
        }
    }
}

function Get-DefaultProfile {
    [pscustomobject]@{
        TenantName      = 'Cloud tenant'
        Service         = @(Get-CaDefaultServices)
        Format          = 'All'
        Environment     = 'Global'
        GraphAuthMode   = 'DeviceCode'
        OutputRoot      = (Join-Path $root 'reports\wizard')
        BaselinePath    = ''
        RunPester       = $false
        AuthMode        = 'Interactive'
        TenantId        = ''
        ClientId        = ''
        Organization    = ''
        AzureSubscription = ''
        AzureTenant     = ''
        AwsProfile      = ''
        AwsRegions      = @()
        GcpProject      = ''
        GcpAccount      = ''
        GcpOrganization = ''
        TailscaleTailnet = ''
        TailscaleApiTokenEnv = 'TAILSCALE_API_TOKEN'
        TailscaleAuthScheme = 'Auto'
        Domains = @()
        DomainSubdomains = @('www', 'autodiscover', 'mail', 'vpn', 'portal', 'admin', 'dev', 'staging')
        VpsTarget       = ''
        VpsSshUser      = ''
        VpsSshPort      = 22
        VpsAllowedPublicPorts = @()
    }
}

function Read-WizardProfile {
    $sourcePath = $ProfilePath
    if (-not (Test-Path -LiteralPath $sourcePath)) {
        if ($script:LegacyWizardProfilePath -and (Test-Path -LiteralPath $script:LegacyWizardProfilePath)) {
            $sourcePath = $script:LegacyWizardProfilePath
            Write-WizardLine "Profilo legacy caricato da $sourcePath; il prossimo salvataggio usera $ProfilePath" $script:Warn
        }
        else {
            return (Get-DefaultProfile)
        }
    }
    try {
        $loaded = Get-Content -LiteralPath $sourcePath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        $default = Get-DefaultProfile
        foreach ($name in $default.PSObject.Properties.Name) {
            if ($loaded.PSObject.Properties.Name -notcontains $name) {
                $loaded | Add-Member -NotePropertyName $name -NotePropertyValue $default.$name
            }
        }
        return $loaded
    }
    catch {
        Write-WizardLine "Profilo wizard non leggibile, uso default: $($_.Exception.Message)" $script:Warn
        return (Get-DefaultProfile)
    }
}

function Save-WizardProfile {
    param([Parameter(Mandatory)][object]$Profile)
    $parent = Split-Path -Parent $ProfilePath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $safeProfile = [ordered]@{
        TenantName   = $Profile.TenantName
        Service      = @($Profile.Service)
        Format       = $Profile.Format
        Environment  = $Profile.Environment
        GraphAuthMode = $Profile.GraphAuthMode
        OutputRoot   = $Profile.OutputRoot
        BaselinePath = $Profile.BaselinePath
        RunPester    = [bool]$Profile.RunPester
        AuthMode     = $Profile.AuthMode
        TenantId     = $Profile.TenantId
        ClientId     = $Profile.ClientId
        Organization = $Profile.Organization
        AzureSubscription = $Profile.AzureSubscription
        AzureTenant  = $Profile.AzureTenant
        AwsProfile   = $Profile.AwsProfile
        AwsRegions   = @($Profile.AwsRegions)
        GcpProject   = $Profile.GcpProject
        GcpAccount   = $Profile.GcpAccount
        GcpOrganization = $Profile.GcpOrganization
        TailscaleTailnet = $Profile.TailscaleTailnet
        TailscaleApiTokenEnv = $Profile.TailscaleApiTokenEnv
        TailscaleAuthScheme = $Profile.TailscaleAuthScheme
        Domains = @($Profile.Domains)
        DomainSubdomains = @($Profile.DomainSubdomains)
        VpsTarget    = $Profile.VpsTarget
        VpsSshUser   = $Profile.VpsSshUser
        VpsSshPort   = $Profile.VpsSshPort
        VpsAllowedPublicPorts = @($Profile.VpsAllowedPublicPorts)
    }
    $json = [pscustomobject]$safeProfile | ConvertTo-Json -Depth 5
    $temporaryPath = Join-Path $parent ('.wizard-profile-' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [System.IO.File]::WriteAllText($temporaryPath, $json, [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::Move($temporaryPath, $ProfilePath, $true)
        if (-not $IsWindows) {
            try {
                $mode = [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite
                [System.IO.File]::SetUnixFileMode($ProfilePath, $mode)
            }
            catch { Write-WizardLine "Permessi profilo non aggiornati: $($_.Exception.Message)" $script:Warn }
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function New-WizardRunContext {
    param([Parameter(Mandatory)][object]$Profile)
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $runId = "wizard-$stamp-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
    $outputDirectory = Join-Path $Profile.OutputRoot $runId
    [pscustomobject]@{
        RunId              = $runId
        OutputDirectory    = $outputDirectory
        PreflightJsonPath  = Join-Path $outputDirectory 'preflight.json'
    }
}

function Invoke-WizardPreflight {
    param(
        [Parameter(Mandatory)][object]$Profile,
        [Parameter(Mandatory)][object]$Run,
        [string]$CertificateThumbprint = ''
    )
    $args = @{
        Service        = @($Profile.Service)
        OutputDirectory = $Run.OutputDirectory
        JsonOutputPath = $Run.PreflightJsonPath
    }
    if (-not [string]::IsNullOrWhiteSpace($Profile.BaselinePath)) { $args['BaselinePath'] = $Profile.BaselinePath }
    if ($Profile.RunPester) { $args['RequirePester'] = $true }
    if (-not [string]::IsNullOrWhiteSpace($Profile.AuthMode)) { $args['AuthMode'] = $Profile.AuthMode }
    if (-not [string]::IsNullOrWhiteSpace($Profile.GraphAuthMode)) { $args['GraphAuthMode'] = $Profile.GraphAuthMode }
    if (-not [string]::IsNullOrWhiteSpace($Profile.AzureSubscription)) { $args['AzureSubscription'] = $Profile.AzureSubscription }
    if (-not [string]::IsNullOrWhiteSpace($Profile.AzureTenant)) { $args['AzureTenant'] = $Profile.AzureTenant }
    if (-not [string]::IsNullOrWhiteSpace($Profile.AwsProfile)) { $args['AwsProfile'] = $Profile.AwsProfile }
    if (@($Profile.AwsRegions).Count -gt 0) { $args['AwsRegion'] = @($Profile.AwsRegions) }
    if (-not [string]::IsNullOrWhiteSpace($Profile.GcpProject)) { $args['GcpProject'] = $Profile.GcpProject }
    if (-not [string]::IsNullOrWhiteSpace($Profile.GcpAccount)) { $args['GcpAccount'] = $Profile.GcpAccount }
    if (-not [string]::IsNullOrWhiteSpace($Profile.GcpOrganization)) { $args['GcpOrganization'] = $Profile.GcpOrganization }
    if (-not [string]::IsNullOrWhiteSpace($Profile.TailscaleTailnet)) { $args['TailscaleTailnet'] = $Profile.TailscaleTailnet }
    if (-not [string]::IsNullOrWhiteSpace($Profile.TailscaleApiTokenEnv)) { $args['TailscaleApiTokenEnv'] = $Profile.TailscaleApiTokenEnv }
    if (-not [string]::IsNullOrWhiteSpace($Profile.TailscaleAuthScheme)) { $args['TailscaleAuthScheme'] = $Profile.TailscaleAuthScheme }
    if (@($Profile.Domains).Count -gt 0) { $args['Domain'] = @($Profile.Domains) }
    if (@($Profile.DomainSubdomains).Count -gt 0) { $args['DomainSubdomain'] = @($Profile.DomainSubdomains) }
    if (-not [string]::IsNullOrWhiteSpace($Profile.VpsTarget)) { $args['VpsTarget'] = $Profile.VpsTarget }
    if (-not [string]::IsNullOrWhiteSpace($Profile.VpsSshUser)) { $args['VpsSshUser'] = $Profile.VpsSshUser }
    if ($Profile.VpsSshPort -and [int]$Profile.VpsSshPort -ne 22) { $args['VpsSshPort'] = [int]$Profile.VpsSshPort }
    if (@($Profile.VpsAllowedPublicPorts).Count -gt 0) { $args['VpsAllowedPublicPort'] = @($Profile.VpsAllowedPublicPorts) }
    if ($Profile.AuthMode -eq 'AppOnly') {
        if (-not [string]::IsNullOrWhiteSpace($Profile.TenantId)) { $args['TenantId'] = $Profile.TenantId }
        if (-not [string]::IsNullOrWhiteSpace($Profile.ClientId)) { $args['ClientId'] = $Profile.ClientId }
        if (-not [string]::IsNullOrWhiteSpace($CertificateThumbprint)) { $args['CertificateThumbprint'] = $CertificateThumbprint }
        if (-not [string]::IsNullOrWhiteSpace($Profile.Organization)) { $args['Organization'] = $Profile.Organization }
    }

    & (Join-Path $root 'Test-ClauditPreflight.ps1') @args | Out-Host
    $code = $LASTEXITCODE
    return $code
}

function Invoke-WizardAudit {
    param(
        [Parameter(Mandatory)][object]$Profile,
        [Parameter(Mandatory)][object]$Run,
        [string]$CertificateThumbprint = '',
        [string]$NotifyWebhook = ''
    )
    $args = @{
        Service                 = @($Profile.Service)
        Format                  = $Profile.Format
        TenantName              = $Profile.TenantName
        OutputDirectory          = $Run.OutputDirectory
        Environment             = $Profile.Environment
        ConfirmTenantConnection = $true
    }
    if (-not [string]::IsNullOrWhiteSpace($Profile.BaselinePath)) { $args['BaselinePath'] = $Profile.BaselinePath }
    if ($Profile.RunPester) { $args['RunPester'] = $true }
    if (-not [string]::IsNullOrWhiteSpace($NotifyWebhook)) { $args['NotifyWebhook'] = $NotifyWebhook }
    if (-not [string]::IsNullOrWhiteSpace($Profile.GraphAuthMode)) { $args['GraphAuthMode'] = $Profile.GraphAuthMode }
    if (-not [string]::IsNullOrWhiteSpace($Profile.AzureSubscription)) { $args['AzureSubscription'] = $Profile.AzureSubscription }
    if (-not [string]::IsNullOrWhiteSpace($Profile.AzureTenant)) { $args['AzureTenant'] = $Profile.AzureTenant }
    if (-not [string]::IsNullOrWhiteSpace($Profile.AwsProfile)) { $args['AwsProfile'] = $Profile.AwsProfile }
    if (@($Profile.AwsRegions).Count -gt 0) { $args['AwsRegion'] = @($Profile.AwsRegions) }
    if (-not [string]::IsNullOrWhiteSpace($Profile.GcpProject)) { $args['GcpProject'] = $Profile.GcpProject }
    if (-not [string]::IsNullOrWhiteSpace($Profile.GcpAccount)) { $args['GcpAccount'] = $Profile.GcpAccount }
    if (-not [string]::IsNullOrWhiteSpace($Profile.GcpOrganization)) { $args['GcpOrganization'] = $Profile.GcpOrganization }
    if (-not [string]::IsNullOrWhiteSpace($Profile.TailscaleTailnet)) { $args['TailscaleTailnet'] = $Profile.TailscaleTailnet }
    if (-not [string]::IsNullOrWhiteSpace($Profile.TailscaleApiTokenEnv)) { $args['TailscaleApiTokenEnv'] = $Profile.TailscaleApiTokenEnv }
    if (-not [string]::IsNullOrWhiteSpace($Profile.TailscaleAuthScheme)) { $args['TailscaleAuthScheme'] = $Profile.TailscaleAuthScheme }
    if (@($Profile.Domains).Count -gt 0) { $args['Domain'] = @($Profile.Domains) }
    if (@($Profile.DomainSubdomains).Count -gt 0) { $args['DomainSubdomain'] = @($Profile.DomainSubdomains) }
    if (-not [string]::IsNullOrWhiteSpace($Profile.VpsTarget)) { $args['VpsTarget'] = $Profile.VpsTarget }
    if (-not [string]::IsNullOrWhiteSpace($Profile.VpsSshUser)) { $args['VpsSshUser'] = $Profile.VpsSshUser }
    if ($Profile.VpsSshPort -and [int]$Profile.VpsSshPort -ne 22) { $args['VpsSshPort'] = [int]$Profile.VpsSshPort }
    if (@($Profile.VpsAllowedPublicPorts).Count -gt 0) { $args['VpsAllowedPublicPort'] = @($Profile.VpsAllowedPublicPorts) }
    if ($Profile.AuthMode -eq 'AppOnly') {
        $args['AppOnly'] = $true
        $args['TenantId'] = $Profile.TenantId
        $args['ClientId'] = $Profile.ClientId
        $args['CertificateThumbprint'] = $CertificateThumbprint
        if (-not [string]::IsNullOrWhiteSpace($Profile.Organization)) { $args['Organization'] = $Profile.Organization }
    }

    & (Join-Path $root 'Start-ClauditSafeAudit.ps1') @args | Out-Host
    $code = $LASTEXITCODE
    return $code
}

try { Clear-Host } catch { Write-Host '' }
Write-WizardPanel -Title 'Claudit safe execution wizard' -Lines @(
    'Read-only multi-cloud audit orchestration.',
    'Preflight is always offline. Live tenant connection requires confirmation.',
    'Profile is idempotent: re-running updates preferences and creates a new run folder.'
) -Color $script:Accent

$profile = Read-WizardProfile
$profile.TenantName = Read-WizardText -Prompt 'Tenant/display name' -Default $profile.TenantName
$profile.Service = @(Read-WizardServices -Default @($profile.Service))
$profile.Format = Read-WizardChoice -Prompt 'Formato report' -Options @('All', 'Html', 'Json', 'Markdown', 'Csv', 'Ocsf', 'Oscal', 'Catalog') -Default $profile.Format
$profile.Environment = Read-WizardChoice -Prompt 'Cloud Microsoft' -Options @('Global', 'USGov', 'USGovDOD', 'China') -Default $profile.Environment
$profile.OutputRoot = Read-WizardText -Prompt 'Directory radice report' -Default $profile.OutputRoot
$profile.BaselinePath = Read-WizardText -Prompt 'Baseline custom opzionale' -Default $profile.BaselinePath
$profile.RunPester = Read-WizardYesNo -Prompt 'Eseguire Pester compliance dopo audit?' -Default ([bool]$profile.RunPester)
$profile.AuthMode = Read-WizardChoice -Prompt 'Metodo autenticazione' -Options @('Interactive', 'AppOnly') -Default $profile.AuthMode
$needsGraphAuth = @($profile.Service | Where-Object { $_ -in @('Entra', 'SharePoint', 'OneDrive') }).Count -gt 0
if ($needsGraphAuth -and $profile.AuthMode -eq 'Interactive') {
    $profile.GraphAuthMode = Read-WizardChoice -Prompt 'Metodo autenticazione Graph' -Options @('DeviceCode', 'Browser') -Default $profile.GraphAuthMode
}

$certificateThumbprint = ''
if ($profile.AuthMode -eq 'AppOnly') {
    $profile.TenantId = Read-WizardText -Prompt 'TenantId' -Default $profile.TenantId
    $profile.ClientId = Read-WizardText -Prompt 'ClientId app registration' -Default $profile.ClientId
    if (@($profile.Service) -contains 'Exchange') {
        $profile.Organization = Read-WizardText -Prompt 'Exchange organization domain' -Default $profile.Organization
    }
    $certificateThumbprint = Read-WizardText -Prompt 'Certificate thumbprint (non salvato)' -Default ''
}

if (@($profile.Service) -contains 'Azure') {
    $profile.AzureSubscription = Read-WizardText -Prompt 'Azure subscription opzionale' -Default $profile.AzureSubscription
    $profile.AzureTenant = Read-WizardText -Prompt 'Azure tenant opzionale' -Default $profile.AzureTenant
}

if (@($profile.Service) -contains 'AWS') {
    $profile.AwsProfile = Read-WizardText -Prompt 'AWS CLI profile opzionale' -Default $profile.AwsProfile
    $regionDefault = (@($profile.AwsRegions) | Where-Object { $_ }) -join ','
    $regionText = Read-WizardText -Prompt 'AWS regioni audit (csv, vuoto=baseline)' -Default $regionDefault
    $profile.AwsRegions = @(ConvertTo-CaStringList $regionText)
}

if (@($profile.Service) -contains 'GCP') {
    $profile.GcpProject = Read-WizardText -Prompt 'GCP project id' -Default $profile.GcpProject
    $profile.GcpAccount = Read-WizardText -Prompt 'GCP account opzionale' -Default $profile.GcpAccount
    $profile.GcpOrganization = Read-WizardText -Prompt 'GCP organization id opzionale' -Default $profile.GcpOrganization
}

if (@($profile.Service) -contains 'Tailscale') {
    $profile.TailscaleTailnet = Read-WizardText -Prompt 'Tailscale tailnet' -Default $profile.TailscaleTailnet
    $profile.TailscaleApiTokenEnv = Read-WizardText -Prompt 'Tailscale API token env var' -Default $profile.TailscaleApiTokenEnv
    $profile.TailscaleAuthScheme = Read-WizardChoice -Prompt 'Tailscale API auth scheme' -Options @('Auto', 'Basic', 'Bearer') -Default $profile.TailscaleAuthScheme
}

if (@($profile.Service) -contains 'Domain') {
    $domainDefault = (@($profile.Domains) | Where-Object { $_ }) -join ','
    $domainText = Read-WizardText -Prompt 'Domini autorizzati audit (csv, obbligatorio)' -Default $domainDefault
    $profile.Domains = @(ConvertTo-CaStringList $domainText)
    $subDefault = (@($profile.DomainSubdomains) | Where-Object { $_ }) -join ','
    $subText = Read-WizardText -Prompt 'Subdomain comuni da verificare (csv)' -Default $subDefault
    $profile.DomainSubdomains = @(ConvertTo-CaStringList $subText)
}

if (@($profile.Service) -contains 'VPS') {
    $profile.VpsTarget = Read-WizardText -Prompt 'VPS SSH target (vuoto = host locale)' -Default $profile.VpsTarget
    if (-not [string]::IsNullOrWhiteSpace($profile.VpsTarget)) {
        $profile.VpsSshUser = Read-WizardText -Prompt 'VPS SSH user opzionale' -Default $profile.VpsSshUser
        $portText = Read-WizardText -Prompt 'VPS SSH port' -Default ([string]$profile.VpsSshPort)
        if (-not [string]::IsNullOrWhiteSpace($portText)) { $profile.VpsSshPort = [int]$portText }
    }
    $portDefault = (@($profile.VpsAllowedPublicPorts) | Where-Object { $_ }) -join ','
    $allowedText = Read-WizardText -Prompt 'VPS porte pubbliche ammesse (csv)' -Default $portDefault
    $profile.VpsAllowedPublicPorts = @(ConvertTo-CaStringList $allowedText | ForEach-Object { [int]$_ })
}

Save-WizardProfile -Profile $profile
$run = New-WizardRunContext -Profile $profile

Write-WizardRule 'Run plan'
Write-WizardLine ("Run ID:      {0}" -f $run.RunId)
Write-WizardLine ("Tenant:      {0}" -f $profile.TenantName)
Write-WizardLine ("Services:    {0}" -f (@($profile.Service) -join ', '))
Write-WizardLine ("Format:      {0}" -f $profile.Format)
Write-WizardLine ("Cloud:       {0}" -f $profile.Environment)
if ($needsGraphAuth -and $profile.AuthMode -eq 'Interactive') {
    Write-WizardLine ("Graph auth:  {0}" -f $profile.GraphAuthMode)
}
if (@($profile.Service) -contains 'AWS') {
    $awsRegions = if (@($profile.AwsRegions).Count -gt 0) { @($profile.AwsRegions) -join ', ' } else { 'baseline' }
    $awsProfile = if ([string]::IsNullOrWhiteSpace($profile.AwsProfile)) { 'default' } else { $profile.AwsProfile }
    Write-WizardLine ("AWS:         profile={0}; regions={1}" -f $awsProfile, $awsRegions)
}
if (@($profile.Service) -contains 'Azure') {
    $azSub = if ([string]::IsNullOrWhiteSpace($profile.AzureSubscription)) { 'az account default' } else { $profile.AzureSubscription }
    Write-WizardLine ("Azure:      subscription={0}" -f $azSub)
}
if (@($profile.Service) -contains 'GCP') {
    $gcpProject = if ([string]::IsNullOrWhiteSpace($profile.GcpProject)) { 'gcloud config' } else { $profile.GcpProject }
    Write-WizardLine ("GCP:         project={0}" -f $gcpProject)
}
if (@($profile.Service) -contains 'Tailscale') {
    $tailnet = if ([string]::IsNullOrWhiteSpace($profile.TailscaleTailnet)) { 'TAILSCALE_TAILNET/baseline' } else { $profile.TailscaleTailnet }
    Write-WizardLine ("Tailscale:  tailnet={0}; tokenEnv={1}" -f $tailnet, $profile.TailscaleApiTokenEnv)
}
if (@($profile.Service) -contains 'Domain') {
    $domains = if (@($profile.Domains).Count -gt 0) { @($profile.Domains) -join ', ' } else { 'not configured' }
    Write-WizardLine ("Domain:     authorized={0}" -f $domains)
}
if (@($profile.Service) -contains 'VPS') {
    $vpsTarget = if ([string]::IsNullOrWhiteSpace($profile.VpsTarget)) { 'local host' } else { $profile.VpsTarget }
    $vpsPorts = if (@($profile.VpsAllowedPublicPorts).Count -gt 0) { @($profile.VpsAllowedPublicPorts) -join ', ' } else { 'baseline' }
    Write-WizardLine ("VPS:        target={0}; allowedPorts={1}" -f $vpsTarget, $vpsPorts)
}
Write-WizardLine ("Output:      {0}" -f $run.OutputDirectory)
Write-WizardLine ("Profile:     {0}" -f $ProfilePath) $script:Muted

Write-WizardRule 'Offline preflight'
$preflightExit = Invoke-WizardPreflight -Profile $profile -Run $run -CertificateThumbprint $certificateThumbprint
if ($preflightExit -ne 0) {
    Write-WizardPanel -Title 'Preflight blocked live execution' -Lines @(
        "Exit code: $preflightExit",
        "Report: $($run.PreflightJsonPath)",
        'Fix missing prerequisites, then rerun this wizard. No tenant connection was attempted.'
    ) -Color $script:Bad
    exit $preflightExit
}

Write-WizardPanel -Title 'Preflight passed' -Lines @(
    'Local prerequisites look usable.',
    "Preflight JSON: $($run.PreflightJsonPath)"
) -Color $script:Good

if ($NoLive) {
    Write-WizardLine 'NoLive set: wizard stopped after successful preflight.' $script:Warn
    exit 0
}

$goLive = Read-WizardYesNo -Prompt 'Avviare ora connessione tenant read-only?' -Default $false
if (-not $goLive) {
    Write-WizardLine 'Live audit non avviato. Riesegui il wizard quando vuoi procedere.' $script:Warn
    exit 0
}

$notifyWebhook = ''
if (Read-WizardYesNo -Prompt 'Inviare notifica webhook a fine audit?' -Default $false) {
    $notifyWebhook = Read-WizardText -Prompt 'Webhook URL (non salvato)' -Default ''
}

if ($profile.AuthMode -eq 'AppOnly' -and [string]::IsNullOrWhiteSpace($certificateThumbprint)) {
    Write-WizardLine 'AppOnly richiede certificate thumbprint per la live run.' $script:Bad
    exit 2
}

Write-WizardRule 'Live audit'
$auditExit = Invoke-WizardAudit -Profile $profile -Run $run -CertificateThumbprint $certificateThumbprint -NotifyWebhook $notifyWebhook
if ($auditExit -eq 0) {
    Write-WizardPanel -Title 'Audit completed' -Lines @(
        'No Critical/High failures caused a non-zero exit.',
        "Output directory: $($run.OutputDirectory)"
    ) -Color $script:Good
}
elseif ($auditExit -eq 2) {
    Write-WizardPanel -Title 'Audit completed with high-impact findings' -Lines @(
        'Review Critical/High findings before escalation.',
        "Output directory: $($run.OutputDirectory)"
    ) -Color $script:Warn
}
else {
    Write-WizardPanel -Title 'Audit ended with runtime error' -Lines @(
        "Exit code: $auditExit",
        "Output directory: $($run.OutputDirectory)"
    ) -Color $script:Bad
}
exit $auditExit
