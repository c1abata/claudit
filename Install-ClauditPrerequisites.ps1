#Requires -Version 7.2
<#
.SYNOPSIS
    Installs Claudit PowerShell prerequisites for the current user.

.DESCRIPTION
    This script reaches PowerShell Gallery, so it requires network access. It
    does nothing unless -ConfirmInstall is supplied.
#>
[CmdletBinding()]
param(
    [string[]]$Service = @('Entra', 'Exchange', 'SharePoint', 'OneDrive'),

    [switch]$IncludePester,
    [switch]$ConfirmInstall,
    [switch]$TrustPSGallery,

    [Alias('h', '?')]
    [switch]$Help,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArguments
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$moduleManifest = Join-Path $PSScriptRoot 'Claudit.psd1'
if (Test-Path -LiteralPath $moduleManifest) {
    Import-Module $moduleManifest -Force -ErrorAction Stop
    if (Test-CaHelpRequested -Help:$Help -RemainingArguments $RemainingArguments -InvocationLine $MyInvocation.Line) {
        Show-CaCommandHelp -Command $PSCommandPath
        exit 0
    }
    Assert-CaNoRemainingArgument -RemainingArguments $RemainingArguments
    $Service = Resolve-CaServices -Service $Service
}
elseif ($Help -or ($RemainingArguments -contains '--help')) {
    Write-Host 'Claudit module manifest not found; cannot show full command help.' -ForegroundColor Red
    exit 2
}

if (-not $ConfirmInstall) {
    Write-Host 'No modules installed. Rerun with -ConfirmInstall to use PowerShell Gallery.' -ForegroundColor Yellow
    exit 0
}

if ($TrustPSGallery) {
    $repo = Get-PSRepository -Name PSGallery -ErrorAction Stop
    if ($repo.InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    }
}

$modules = [System.Collections.Generic.List[string]]::new()
if ($Service | Where-Object { $_ -in @('Entra', 'SharePoint', 'OneDrive') }) {
    $modules.Add('Microsoft.Graph.Authentication')
}
if ($Service -contains 'Entra') {
    foreach ($name in @(
        'Microsoft.Graph.Identity.DirectoryManagement',
        'Microsoft.Graph.Identity.SignIns',
        'Microsoft.Graph.Applications',
        'Microsoft.Graph.Users'
    )) { $modules.Add($name) }
}
if ($Service -contains 'Exchange') {
    $modules.Add('ExchangeOnlineManagement')
}
if ($IncludePester) {
    $modules.Add('Pester')
}

if ($Service -contains 'AWS') {
    Write-Host 'AWS selected: install AWS CLI v2 and configure a read-only profile. See https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html' -ForegroundColor Yellow
}
if ($Service -contains 'Azure') {
    Write-Host 'Azure selected: install Azure CLI and authenticate read-only with az login. See https://learn.microsoft.com/cli/azure/install-azure-cli' -ForegroundColor Yellow
}
if ($Service -contains 'GCP') {
    Write-Host 'GCP selected: install Google Cloud SDK and authenticate with gcloud. See https://cloud.google.com/sdk/docs/install' -ForegroundColor Yellow
}
if ($Service -contains 'Tailscale') {
    Write-Host 'Tailscale selected: set TAILSCALE_TAILNET and a short-lived TAILSCALE_API_TOKEN in the current process. No token is stored by Claudit.' -ForegroundColor Yellow
}
if ($Service -contains 'Inventory') {
    Write-Host 'Inventory selected: no extra PowerShell module is required; it reuses configured aws/az/gcloud/Tailscale contexts.' -ForegroundColor Yellow
}

$modules = $modules | Sort-Object -Unique
foreach ($name in $modules) {
    $installed = Get-Module -ListAvailable -Name $name | Sort-Object Version -Descending | Select-Object -First 1
    if ($installed -and (-not ($name -eq 'Pester' -and $installed.Version -lt [version]'5.0'))) {
        Write-Host "Already installed: $name $($installed.Version)" -ForegroundColor Green
        continue
    }

    $minimum = if ($name -eq 'Pester') { @{ MinimumVersion = '5.0.0' } } else { @{} }
    Write-Host "Installing: $name" -ForegroundColor Cyan
    try {
        Install-Module -Name $name -Scope CurrentUser -Force -AllowClobber @minimum -ErrorAction Stop
    }
    catch {
        throw "Failed to install module '$name': $($_.Exception.Message)"
    }
}

Write-Host 'Prerequisite installation complete. Run .\Test-ClauditPreflight.ps1 next.' -ForegroundColor Green
