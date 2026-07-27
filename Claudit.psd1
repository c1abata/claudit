@{
    RootModule        = 'Claudit.psm1'
    ModuleVersion     = '0.3.1'
    GUID              = 'b3f1c0d2-7a4e-4d9c-9b2a-2f6e1c8d3a01'
    Author            = 'Claudit Project'
    CompanyName       = 'Claudit (FOSS)'
    Copyright         = '(c) Claudit Project. MIT License.'
    Description       = 'Read-only multi-cloud and VPS diagnostic auditing suite for Microsoft 365, Azure, AWS, Google Cloud, Tailscale, Linux VPS hosts and public DNS/email exposure with guarded orchestration, inventory, control mapping, drift detection and multi-format reporting.'
    PowerShellVersion = '7.2'

    # Modules are imported on demand inside Connect-Claudit so the suite can be
    # loaded and inspected even when the dependencies are not yet installed.
    RequiredModules   = @()

    FunctionsToExport = @(
        'Connect-Claudit',
        'Disconnect-Claudit',
        'Get-CaServiceCatalog',
        'Get-CaServiceNames',
        'Get-CaDefaultServices',
        'Get-CaMicrosoft365Services',
        'Get-CaAuthCatalog',
        'Get-CaAuthPlan',
        'Get-CaServiceSpec',
        'Resolve-CaServices',
        'Set-CaProviderOption',
        'Get-CaProviderOption',
        'ConvertTo-CaStringList',
        'Resolve-CaDnsQuery',
        'Resolve-CaDnsRecord',
        'Resolve-CaDnsTxt',
        'Resolve-CaDnssecStatus',
        'Invoke-CaDnsxQuery',
        'Test-CaHelpRequested',
        'Assert-CaNoRemainingArgument',
        'Show-CaCommandHelp',
        'Get-CaBaseline',
        'New-CaCheckAssessment',
        'ConvertTo-CaFinding',
        'New-CaFinding',
        'Invoke-CaCheck',
        'Invoke-CaGraphRequest',
        'Get-CaControlIds',
        'Get-CaControlCatalog',
        'Get-CaCheckMetadata',
        'Get-CaCheckMetadataCatalog',
        'Get-CaEntraFindings',
        'Get-CaExchangeFindings',
        'Get-CaSharePointFindings',
        'Get-CaOneDriveFindings',
        'Get-CaAzureFindings',
        'Get-CaAwsFindings',
        'Get-CaGcpFindings',
        'Get-CaTailscaleFindings',
        'Get-CaAuthorizedDomains',
        'Get-CaDomainSubdomains',
        'Get-CaDomainFindings',
        'Get-CaVpsFindings',
        'Get-CaActiveFindings',
        'Get-CaInventoryFindings',
        'Get-CaAllFindings',
        'New-CaReport',
        'Compare-ClauditResult',
        'Send-CaNotification',
        'Start-CaDashboard'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('Microsoft365', 'Azure', 'AWS', 'GCP', 'Tailscale', 'VPS', 'Linux', 'SSH', 'DNS', 'Domain', 'Security', 'Audit', 'Entra', 'Exchange', 'SharePoint', 'OneDrive', 'Misconfiguration', 'Inventory', 'CISA', 'CIS', 'EIDSCA')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ProjectUri   = 'https://github.com/c1abata/claudit'
            ReleaseNotes = 'v0.3.1 stability release. Closes missing-control false greens, records cumulative control-level applicability and emits OCSF 1.8 Compliance Findings with normalized status.'
        }
    }
}
