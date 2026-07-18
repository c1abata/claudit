# Claudit cloud provider diagnostic runbook

## Scopo

Questo runbook descrive come eseguire e interpretare i controlli Claudit per
Microsoft 365, Azure, AWS, Google Cloud, Tailscale e Inventory. Tutte le
operazioni sono read-only: il tool produce finding locali e report
HTML/JSON/Markdown/CSV.

## Modello operativo

1. Eseguire sempre il wizard o il launcher sicuro.
2. Fare preflight offline.
3. Correggere CLI/moduli mancanti.
4. Avviare live audit solo con `-ConfirmTenantConnection`.
5. Revisionare manualmente Critical/High prima di aprire ticket o escalation.

```powershell
.\Start-ClauditWizard.ps1
```

Esecuzione non interattiva completa:

```powershell
.\Start-ClauditSafeAudit.ps1 -ConfirmTenantConnection `
  -Service All `
  -AzureSubscription "<subscription-id>" `
  -TenantName "Enterprise cloud estate" `
  -AwsProfile audit `
  -AwsRegion eu-west-1,eu-central-1 `
  -GcpProject prod-project `
  -GcpAccount auditor@example.com `
  -Format All
```

Selector operativi:

- `-Service M365`: tutte le aree Microsoft 365 (`Entra`, `Exchange`, `SharePoint`, `OneDrive`).
- `-Service All`: Microsoft 365 + Azure + AWS + GCP + Tailscale + Inventory.

## Permessi minimi

Microsoft 365:

- Entra roles: Global Reader + Security Reader.
- Exchange: View-Only Organization Management.
- Delegated Graph scopes: quelli elencati nel README.

AWS:

- Usare AWS CLI v2 con SSO o profilo locale.
- Permessi read-only equivalenti a SecurityAudit piu lettura per servizi regionali:
  IAM, STS, CloudTrail, GuardDuty, SecurityHub, S3Control, EC2, Config.
- Nessun secret viene passato a Claudit.

Google Cloud:

- Usare Google Cloud SDK (`gcloud`) con account auditor.
- Ruoli tipici: Viewer, Security Reviewer, IAM Security Reviewer, Logs Viewer,
  Storage Viewer, Compute Viewer.
- Passare `-GcpProject` esplicito per evitare ambiguita.

Azure:

- Usare Azure CLI (`az`) con account Reader/Security Reader dove possibile.
- Per controlli Graph application permissions servono permessi directory read
  sufficienti a leggere service principal e app-role assignments.
- Passare `-AzureSubscription` per evitare ambiguita fra sottoscrizioni.

Tailscale:

- Usare un API token a vita breve in `TAILSCALE_API_TOKEN` o nella variabile
  indicata da `-TailscaleApiTokenEnv`.
- Passare `-TailscaleTailnet` o impostare `TAILSCALE_TAILNET`.
- Il token non viene mai scritto nel profilo wizard.

## Baseline

`config\baseline.json` contiene soglie e toggle:

- `AWS.Regions`: regioni da auditare per controlli regionali.
- `AWS.MaxAccessKeyAgeDays`: eta massima chiavi IAM attive.
- `AWS.RequireVpcFlowLogs`: abilita/frena controllo flow log.
- `Azure.HighRiskAzureRoles`: ruoli RBAC da considerare privilegiati per SP/MI.
- `Azure.AllowedPrivilegedPrincipalIds`: allow-list object ID per eccezioni.
- `Azure.HighRiskGraphAppRoles`: permessi application Microsoft Graph ad alto rischio.
- `GCP.AllowedPrimitiveRoleMembers`: allow-list per Owner/Editor.
- `GCP.MaxServiceAccountKeyAgeDays`: eta massima chiavi user-managed.
- `GCP.RequiredAuditLogTypes`: Data Access log richiesti.
- `GCP.RequireOsLogin`: richiede OS Login su Compute.
- `GCP.RequireCentralLogSink`: richiede almeno un logging sink progetto.
- `Tailscale.MaxStaleDeviceDays`: eta massima device senza attivita.
- `Tailscale.MaxAuthKeyExpiryDays`: durata massima auth key.
- `Inventory.MaxAssetsPerProvider`: cap evidenze per provider.

## Azure checks

| ID | Comandi read-only | Diagnostica |
|----|-------------------|-------------|
| AZURE-001 | `az account show` | Identifica subscription/tenant/user usati dal report. |
| AZURE-002 | `az role assignment list --all --include-inherited` | Fail se SP/Managed Identity hanno ruoli RBAC baseline high-risk. |
| AZURE-003 | `az ad sp list`, `az rest GET /servicePrincipals/{id}/appRoleAssignments` | Fail se app hanno permessi Microsoft Graph application ad alto rischio. |
| AZURE-004 | `az storage account list` | Fail se blob public access e abilitato o baseline richiede default deny. |
| AZURE-005 | `az keyvault list` | Fail se purge protection/network posture non soddisfa baseline. |
| AZURE-006 | `az network public-ip list` | Finding Info con inventario public IP assegnati. |

Esecuzione mirata:

```powershell
.\Invoke-ClauditAudit.ps1 -Service Azure -AzureSubscription "<subscription-id>" -Format All
```

Troubleshooting Azure:

- `Required CLI 'az' was not found`: installare Azure CLI e riaprire PowerShell.
- `Please run az login`: autenticarsi con `az login`.
- `Insufficient privileges`: aggiungere Reader/Security Reader o permessi directory read.
- Tenant con molte app: `AZURE-003` puo essere il controllo piu lento perche legge app-role assignments.

## AWS checks

| ID | Comandi read-only | Diagnostica |
|----|-------------------|-------------|
| AWS-001 | `aws sts get-caller-identity` | Identifica account/ARN usato dal report. |
| AWS-002 | `aws iam get-account-summary` | Fail Critical se root MFA non e abilitata. |
| AWS-003 | `aws iam get-account-password-policy` | Fail se policy assente o sotto baseline. |
| AWS-004 | `aws cloudtrail describe-trails`, `get-trail-status` | Fail se manca trail multi-region in logging. |
| AWS-005 | `aws guardduty list-detectors` per regione | Fail se GuardDuty manca in regioni audit. |
| AWS-006 | `aws securityhub describe-hub` per regione | Fail se Security Hub non e abilitato. |
| AWS-007 | `aws s3control get-public-access-block` | Fail se uno dei 4 flag account-level e disattivato. |
| AWS-008 | `aws iam list-users`, `list-access-keys` | Fail se chiavi attive superano `MaxAccessKeyAgeDays`. |
| AWS-009 | `aws ec2 get-ebs-encryption-by-default` | Fail se EBS default encryption manca in regioni audit. |
| AWS-010 | `aws configservice describe-configuration-recorder-status` | Fail se AWS Config non registra. |
| AWS-011 | `aws ec2 describe-vpcs`, `describe-flow-logs` | Fail se VPC senza flow logs. |

Esecuzione mirata:

```powershell
.\Invoke-ClauditAudit.ps1 -Service AWS -AwsProfile audit -AwsRegion eu-west-1 -Format All
```

Troubleshooting AWS:

- `Required CLI 'aws' was not found`: installare AWS CLI v2 e riaprire PowerShell.
- `Unable to locate credentials`: configurare SSO/profilo e riprovare.
- `AccessDenied`: aggiungere permessi read-only per il servizio indicato dal finding Error.
- Troppo rumore regionale: ridurre temporaneamente `-AwsRegion`, poi ampliare.

## Google Cloud checks

| ID | Comandi read-only | Diagnostica |
|----|-------------------|-------------|
| GCP-001 | `gcloud config list` | Identifica project/account usati dal report. |
| GCP-002 | `gcloud projects get-iam-policy` | Fail se Owner/Editor non in allow-list. |
| GCP-003 | `gcloud iam service-accounts list`, `keys list` | Fail se chiavi user-managed sono stale. |
| GCP-004 | `gcloud projects get-iam-policy` auditConfigs | Fail se Data Access log richiesti mancano. |
| GCP-005 | `gcloud storage buckets list`, `get-iam-policy` | Fail se bucket concede `allUsers` o `allAuthenticatedUsers`. |
| GCP-006 | `gcloud storage buckets describe` | Fail se uniform bucket-level access non e attivo. |
| GCP-007 | `gcloud compute networks list` | Fail se esiste la default VPC. |
| GCP-008 | `gcloud compute firewall-rules list` | Fail se SSH/RDP/all e aperto a internet. |
| GCP-009 | `gcloud compute project-info describe` | Fail se OS Login non e abilitato. |
| GCP-010 | `gcloud logging sinks list` | Fail se baseline richiede sink e non ne esiste uno. |

Esecuzione mirata:

```powershell
.\Invoke-ClauditAudit.ps1 -Service GCP -GcpProject prod-project -GcpAccount auditor@example.com -Format All
```

Troubleshooting GCP:

- `Required CLI 'gcloud' was not found`: installare Google Cloud SDK.
- `No GCP project selected`: passare `-GcpProject` o configurare `gcloud config set project`.
- Check Compute `Skipped`: API Compute disabilitata o permessi insufficienti.
- Errori Storage: verificare che `gcloud storage` sia disponibile nella SDK installata.

## Tailscale checks

| ID | API read-only | Diagnostica |
|----|---------------|-------------|
| TAILSCALE-001 | `GET /api/v2/tailnet/{tailnet}/devices` | Identifica tailnet e numero device. |
| TAILSCALE-002 | `GET /devices` | Fail se device stale superano `MaxStaleDeviceDays`. |
| TAILSCALE-003 | `GET /keys` | Fail se auth key reusable/preauthorized/long-lived. |
| TAILSCALE-004 | `GET /acl` | Fail Critical se ACL/grant consente broad source verso `*:*`. |

Esecuzione mirata:

```powershell
$env:TAILSCALE_TAILNET = "example.com"
$env:TAILSCALE_API_TOKEN = "<short-lived-token>"
.\Invoke-ClauditAudit.ps1 -Service Tailscale -Format All
```

## Inventory

`Inventory` raccoglie asset da qualsiasi contesto disponibile: AWS, Azure, GCP e
Tailscale. Non fallisce se un provider manca; lo registra come errore provider
nel finding `INV-001`.

```powershell
.\Invoke-ClauditAudit.ps1 -Service Inventory -Format All
```

## Interpretazione finding

- `Pass`: controllo conforme alla baseline.
- `Fail`: misconfigurazione confermata rispetto alla baseline.
- `Warning`: evidenza incompleta o postura da revisionare.
- `Skipped`: servizio/API non applicabile o non accessibile.
- `Error`: eccezione runtime o permesso mancante; non trattarlo come pass.
- `Investigate`: evidenza raccolta ma serve giudizio umano.

Exit code:

- `0`: nessun Critical/High e nessun finding `Error`.
- `2`: almeno un Critical/High, un finding `Error`, oppure preflight fallito.
- altro non-zero: errore runtime.
