<#
    Controls.ps1 - control-framework mapping (Maester-inspired).

    Each Claudit check is mapped to the relevant control(s) in:
      * CISA SCuBA - Microsoft 365 Secure Configuration Baselines
        (MS.AAD = Entra, MS.EXO = Exchange, MS.SHAREPOINT = SharePoint/OneDrive)
      * CIS Microsoft 365 Foundations Benchmark

    These identifiers are an INDICATIVE cross-reference to help auditors line up
    Claudit findings with their control catalogue. Control numbering evolves
    between baseline versions - always verify against the version you are
    certifying against. The mapping lives in one place so checks stay clean.
#>

$script:CaControlMap = @{
    # Entra ID
    'ENTRA-001' = @('CISA:MS.AAD.3.1', 'CIS:5.2.2.1')   # Strong auth / MFA
    'ENTRA-002' = @('CISA:MS.AAD.7.1', 'CIS:5.1.1.1')   # Limit privileged roles
    'ENTRA-003' = @('CISA:MS.AAD.1.1', 'CIS:5.2.2.3')   # Block legacy authentication
    'ENTRA-004' = @('CIS:5.1.2.2')                       # Users cannot register apps
    'ENTRA-005' = @('CISA:MS.AAD.8.1', 'CIS:5.1.6.1')   # Guest invite restrictions
    'ENTRA-006' = @('CISA:MS.AAD.5.1', 'CIS:5.1.5.2')   # User app consent
    'ENTRA-007' = @('CISA:MS.AAD.6.1')                   # Credential hygiene
    'ENTRA-008' = @('CISA:MS.AAD.8.3')                   # Guest access review
    'ENTRA-010' = @('CISA:MS.AAD.3.2')                   # Authenticator number matching
    'ENTRA-011' = @('CISA:MS.AAD.3.2')                   # Authenticator app/geo context
    'ENTRA-012' = @('CISA:MS.AAD.3.3')                   # Auth methods policy migration
    'ENTRA-013' = @('CISA:MS.AAD.5.4', 'CIS:5.1.5.1')   # Admin consent workflow
    'ENTRA-014' = @('CIS:5.1.2.3')                       # Block legacy AAD PowerShell

    # Exchange Online
    'EXO-000'   = @('Exchange:Preflight')                   # Connected cmdlet surface
    'EXO-001'   = @('CIS:6.5.1')                          # Modern authentication
    'EXO-002'   = @('CISA:MS.EXO.5.1', 'CIS:3.1.1')      # Mailbox auditing
    'EXO-003'   = @('CISA:MS.EXO.1.1', 'CIS:6.2.1')      # Block external auto-forward
    'EXO-004'   = @('CISA:MS.EXO.1.1')                    # Transport rule redirection
    'EXO-005'   = @('CISA:MS.EXO.4.2', 'CIS:2.1.9')      # DKIM
    'EXO-006'   = @('CIS:6.5.2')                          # SMTP AUTH
    'EXO-007'   = @('CIS:6.5.1')                          # POP/IMAP
    'EXO-008'   = @('CISA:MS.EXO.1.1')                    # Remote domain auto-forward
    'EXO-009'   = @('CISA:MS.EXO.7.1', 'CIS:2.1.7')      # Anti-phishing
    'EXO-010'   = @('CISA:MS.EXO.4.1', 'CIS:2.1.8')      # SPF on all domains
    'EXO-011'   = @('CISA:MS.EXO.4.3')                    # DMARC reject/quarantine

    # SharePoint Online
    'SPO-001'   = @('CISA:MS.SHAREPOINT.1.1', 'CIS:7.2.3') # External sharing ceiling
    'SPO-002'   = @('CISA:MS.SHAREPOINT.3.1')              # Legacy auth protocols
    'SPO-003'   = @('CISA:MS.SHAREPOINT.1.3')              # Reauth match invited
    'SPO-004'   = @('CISA:MS.SHAREPOINT.1.2', 'CIS:7.2.6') # Sharing domain restriction

    # OneDrive
    'OD-001'    = @('CIS:7.2.2')                           # Restrict unmanaged sync
    'OD-002'    = @('CIS:7.2.1')                           # Block risky sync extensions
    'OD-003'    = @('CIS:1.3.3')                           # Deleted-user retention

    # Azure
    'AZURE-001' = @('Azure:Inventory')
    'AZURE-002' = @('CIS-Azure:5.1', 'MITRE:PrivilegeEscalation') # High-risk Azure RBAC grants
    'AZURE-003' = @('CISA:MS.AAD.5.1', 'CISA:MS.AAD.6.1')         # High-risk Graph app roles
    'AZURE-004' = @('CIS-Azure:3.1')                              # Storage public exposure
    'AZURE-005' = @('CIS-Azure:8.5')                              # Key Vault protection
    'AZURE-006' = @('Azure:PublicExposure')                       # Public IP inventory

    # AWS
    'AWS-001'   = @('AWS:Inventory')
    'AWS-002'   = @('CIS-AWS:1.5')                          # Root MFA
    'AWS-003'   = @('CIS-AWS:1.8')                          # Password policy
    'AWS-004'   = @('CIS-AWS:3.1', 'AWS-FSBP:CloudTrail.1') # Multi-region CloudTrail
    'AWS-005'   = @('AWS-FSBP:GuardDuty.1')                 # GuardDuty
    'AWS-006'   = @('AWS-FSBP:SecurityHub.1')               # Security Hub
    'AWS-007'   = @('CIS-AWS:2.1.5', 'AWS-FSBP:S3.1')       # S3 public access block
    'AWS-008'   = @('CIS-AWS:1.14')                         # Stale access keys
    'AWS-009'   = @('AWS-FSBP:EC2.7')                       # EBS default encryption
    'AWS-010'   = @('CIS-AWS:3.5')                          # AWS Config
    'AWS-011'   = @('CIS-AWS:3.9')                          # VPC flow logs

    # Google Cloud
    'GCP-001'   = @('GCP:Inventory')
    'GCP-002'   = @('CIS-GCP:1.3')                          # Primitive roles
    'GCP-003'   = @('CIS-GCP:1.6')                          # Service account keys
    'GCP-004'   = @('CIS-GCP:2.1')                          # Data Access audit logs
    'GCP-005'   = @('CIS-GCP:5.1')                          # Public buckets
    'GCP-006'   = @('GCP:StorageUniformAccess')
    'GCP-007'   = @('CIS-GCP:3.1')                          # Default network
    'GCP-008'   = @('CIS-GCP:3.6', 'CIS-GCP:3.7')           # Open SSH/RDP
    'GCP-009'   = @('CIS-GCP:4.4')                          # OS Login
    'GCP-010'   = @('GCP:LoggingSink')                      # Centralized logs

    # Tailscale
    'TAILSCALE-001' = @('Tailscale:Inventory')
    'TAILSCALE-002' = @('SOC2:CC6.2', 'Tailscale:DeviceLifecycle')
    'TAILSCALE-003' = @('SOC2:CC6.1', 'Tailscale:AuthKeys')
    'TAILSCALE-004' = @('SOC2:CC6.6', 'Tailscale:AccessPolicy')

    # Authorized public domains
    'DOMAIN-001' = @('NIST-CSF:GV.OC', 'Engagement:Scope')
    'DOMAIN-002' = @('NIST-CSF:PR.DS', 'DNS:Delegation')
    'DOMAIN-003' = @('CISA:MS.EXO.4', 'DNS:MX')
    'DOMAIN-004' = @('CISA:MS.EXO.4.1', 'DNS:SPF')
    'DOMAIN-005' = @('CISA:MS.EXO.4.3', 'DNS:DMARC')
    'DOMAIN-006' = @('DNS:CAA', 'Certificate:Issuance')
    'DOMAIN-007' = @('MITRE:T1580', 'Cloud:SubdomainTakeover')
    'DOMAIN-008' = @('NIST-CSF:PR.DS', 'TLS:CertificateValidation')
    'DOMAIN-009' = @('DNS:RCODE', 'NIST-CSF:DE.CM')
    'DOMAIN-010' = @('RFC:1035', 'RFC:1912', 'DNS:SOA')
    'DOMAIN-011' = @('RFC:4033', 'RFC:4034', 'RFC:4035', 'DNS:DNSSEC')
    'DOMAIN-012' = @('RFC:7208', 'CISA:MS.EXO.4.1', 'DNS:SPF')
    'DOMAIN-013' = @('CISA:MS.EXO.4.3', 'DNS:DMARC')
    'DOMAIN-014' = @('RFC:6376', 'CISA:MS.EXO.4.2', 'DNS:DKIM')
    'DOMAIN-015' = @('RFC:8460', 'RFC:8461', 'Mail:TransportSecurity')
    'DOMAIN-016' = @('MITRE:T1580', 'Cloud:SubdomainTakeover', 'DNS:Availability')

    # Linux VPS host posture
    'VPS-001' = @('NIST-CSF:ID.AM', 'Host:Inventory')
    'VPS-002' = @('CIS-Linux:SSH', 'MITRE:InitialAccess')
    'VPS-003' = @('CIS-Linux:NetworkServices', 'MITRE:T1046')
    'VPS-004' = @('CIS-Linux:Firewall', 'NIST-CSF:PR.PT')
    'VPS-005' = @('CIS-Linux:PatchManagement', 'NIST-CSF:PR.IP')
    'VPS-006' = @('CIS-Linux:Logging', 'NIST-CSF:DE.CM')
    'VPS-007' = @('NIST-CSF:ID.AM', 'Network:ReachabilityValidation')

    # Multi-cloud inventory
    'INV-001' = @('NIST-CSF:ID.AM', 'NIST-CSF:GV.OC')
}

function Get-CaControlIds {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$CheckId)
    if ($script:CaControlMap.ContainsKey($CheckId)) {
        return $script:CaControlMap[$CheckId]
    }
    return @()
}
