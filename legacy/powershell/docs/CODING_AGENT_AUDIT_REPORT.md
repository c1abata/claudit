# Claudit - report operativo per coding agent

## Missione

Potenziare Claudit come suite read-only enterprise-grade per audit di ambienti Microsoft 365, AWS e Google Cloud, mantenendo il carattere di tool personale: PowerShell chiaro, dipendenze minime, baseline JSON modificabile, report leggibili, nessun agente residente, nessuna mutazione del tenant/account/project.

## Stato verificato

Claudit oggi copre bene il perimetro Microsoft 365 tenant-level:

- Entra ID: security defaults/Conditional Access, Global Admin, legacy auth, app registration, guest invite, user consent, credenziali service principal, guest inventory, Authenticator/EIDSCA-style checks.
- Exchange Online: modern auth, audit, forwarding, transport rules, DKIM, SMTP AUTH, POP/IMAP, remote domain, anti-phish, SPF e DMARC.
- SharePoint/OneDrive: tenant external sharing, legacy auth, invited identity match, domain restriction, sync unmanaged, risky extensions, deleted-user retention.
- Core: finding model flat, severita normalizzata, mapping CISA/CIS, report HTML/JSON/Markdown/CSV, drift diff, webhook Teams/Slack, Pester compliance.

Aggiornamento v0.3:

- Introdotto registry servizi (`Entra`, `Exchange`, `SharePoint`, `OneDrive`, `AWS`, `GCP`) con selezione `All`.
- Esteso il modello finding e la reportistica a servizi non Microsoft senza cambiare il formato flat.
- Aggiunti provider options non segreti per profilo AWS, regioni AWS, project/account/org GCP.
- Aggiunti controlli AWS via `aws` CLI: identity, root MFA, password policy, CloudTrail, GuardDuty, Security Hub, S3 public access block, stale access keys, EBS encryption, AWS Config, VPC Flow Logs.
- Aggiunti controlli Google Cloud via `gcloud`: context, primitive IAM roles, service account keys, Data Access audit logs, public buckets, uniform bucket access, default network, open admin firewall rules, OS Login, logging sinks.
- Wizard, preflight, safe launcher e runner principale ora propagano provider selectors e restano read-only.
- Documentazione operativa aggiornata in `README.md`, `docs/OPERATIONS.md` e `docs/CLOUD_PROVIDER_RUNBOOK.md`.

Fix applicati in questa verifica:

- Raw Microsoft Graph calls ora rispettano il cloud selezionato (`Global`, `USGov`, `USGovDOD`, `China`) invece di puntare sempre a `graph.microsoft.com`.
- Pulito il filtro domini Exchange per SPF/DMARC: rimossa una condizione sempre vera.
- Aggiunto test Pester sul Graph root per national cloud.

## Principi non negoziabili

1. Read-only assoluto: usare solo `Get-*`, `Invoke-MgGraphRequest -Method GET`, API cloud in modalità list/describe/get.
2. Niente segreti statici: preferire certificate auth, workload identity, profili locali o token ottenuti dal provider.
3. Un check non deve interrompere la suite: ogni controllo passa da `Invoke-CaCheck` o equivalente.
4. Output flat: ogni osservazione produce un finding autonomo, filtrabile e diffabile.
5. Baseline prima del codice: soglie, toggle e allow-list stanno in JSON, non hardcoded nei check.
6. Dipendenze leggere: aggiungere moduli solo quando il beneficio supera il costo operativo.
7. Evidenza utile: ogni finding deve includere valore osservato, dettaglio breve, raccomandazione e riferimento.

## Gap enterprise prioritari

Priorita P0 chiuse in v0.3:

- Registry servizi introdotto e usato da runner/report/wizard.
- `New-CaFinding` accetta servizi registrati AWS/GCP mantenendo compatibilita report.
- Connessione Microsoft 365 separata dai provider CLI: AWS/GCP non richiedono Graph o Exchange.

Priorita P1 residua:

- Google Workspace read-only: Admin SDK Directory, Reports API, Alert Center. Primi controlli: super admin count, 2SV admin, domain-wide delegation, external sharing Drive, Gmail forwarding/POP/IMAP, SPF/DKIM/DMARC.
- Azure subscription posture: tenant/subscription inventory, Defender for Cloud, diagnostic settings, public storage, key vault purge protection, privileged role assignments.
- AWS Organizations deep audit: org trail delegation, delegated admin, SCP guardrails, account inventory.
- GCP organization/folder posture: org policies, SCC premium state, folder-level IAM inheritance.

Priorita P2:

- Report per executive e SOC: separare `risk register`, `evidence appendix`, `operator delta`.
- SARIF o OSCAL-lite opzionale per integrazione GRC.
- Cache read-only per grandi tenant, con TTL locale e disattivabile.

## Architettura target

Mantieni questa forma:

```text
src/Core/*                  finding, baseline, report, drift, notify
src/Providers/Microsoft365  connection helpers Graph/EXO
src/Providers/Google        connection helpers Admin SDK
src/Providers/AWS           connection helpers AWS CLI/SDK
src/Providers/Azure         connection helpers Az/Graph
src/Providers/GCP           connection helpers gcloud/API
src/Checks/<Service>.ps1    checks auto-discovered by prefix
config/baseline.json        single source of policy intent
tests/*.Tests.ps1           unit tests provider-agnostic first
```

Non introdurre database, web server, queue, agent o daemon. Claudit deve restare copiabile su una workstation admin e revisionabile in un pomeriggio.

## Pattern per nuovi check

Ogni nuovo check deve:

- chiamarsi `Test-Ca<Service><Name>`;
- usare un ID stabile (`GWS-001`, `AWS-001`, `AZURE-001`, `GCP-001`);
- leggere baseline con `Get-CaBaseline`;
- fallire in modo contenuto via wrapper;
- restituire `New-CaFinding`;
- avere mapping in `src/Core/Controls.ps1`;
- avere almeno un test locale senza tenant reale, usando mock/funzioni pure.

Esempio logico:

```powershell
function Test-CaGoogleWorkspaceSuperAdminCount {
    Invoke-CaCheck -Service GoogleWorkspace -CheckId 'GWS-001' -Title 'Super Admin count within limit' -Body {
        $bl = Get-CaBaseline
        $admins = Get-CaGoogleWorkspaceAdmins
        if ($admins.Count -le [int]$bl.GoogleWorkspace.MaxSuperAdmins) {
            New-CaFinding -Service GoogleWorkspace -CheckId 'GWS-001' -Title 'Super Admin count within limit' -Status Pass -Evidence $admins.Count
        } else {
            New-CaFinding -Service GoogleWorkspace -CheckId 'GWS-001' -Title 'Super Admin count within limit' -Status Fail -Severity High -Detail "$($admins.Count) Super Admins exceed baseline." -Recommendation 'Reduce standing Super Admins; use delegated admin roles.' -Evidence $admins.Count
        }
    }
}
```

## Roadmap operativo per coding agent

1. Eseguire `Invoke-Pester` e correggere regressioni del core prima di nuove feature.
2. Creare service registry e aggiornare test del finding model/report.
3. Aggiungere sezioni baseline vuote ma documentate per `GoogleWorkspace`, `Azure`, `AWS`, `GCP`.
4. Implementare Google Workspace come provider SaaS separato, mantenendo il pattern CLI/API read-only.
5. Aggiungere controlli DNS condivisi tra Exchange e Google Workspace per domini mail.
6. Estendere AWS/GCP a livello organization/folder con controlli opzionali e baseline esplicita.
7. Aggiornare README solo dopo che i test confermano la superficie pubblica.

## Criterio di qualita

Un coding agent deve considerare una modifica completa solo quando:

- importa il modulo senza dipendenze cloud installate;
- i test Pester locali passano;
- il nuovo servizio puo essere escluso o incluso esplicitamente;
- i report vecchi restano leggibili da `Compare-ClauditResult`;
- nessun controllo richiede permessi write;
- la documentazione dice esattamente quali ruoli/scopes read-only servono.
