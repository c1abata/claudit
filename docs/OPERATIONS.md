# Claudit operations guide

## Regola operativa

Claudit deve essere eseguito da una workstation admin controllata. La suite e read-only verso il tenant: legge Graph, Exchange Online e DNS pubblici; scrive solo report locali e, se richiesto, invia una notifica webhook.
Per AWS e Google Cloud legge solo tramite CLI locali (`aws`, `gcloud`) gia autenticati con profili/ruoli read-only. Nessun token o segreto viene scritto nel profilo wizard.

## Orchestrator Ubuntu stabile

Prerequisiti: Ubuntu con systemd e PowerShell 7.2+ installato in
`/usr/bin/pwsh`. Installazione:

```bash
sudo bash ./install-ubuntu.sh
sudo systemctl status claudit --no-pager
sudo journalctl -u claudit -f
```

Il servizio ascolta esclusivamente su `127.0.0.1:8765`. Accedere dalla
workstation tramite tunnel SSH:

```bash
ssh -L 8765:127.0.0.1:8765 operator@ubuntu-host
```

Aprire poi `http://127.0.0.1:8765/`. Non pubblicare la porta con reverse proxy
o bind `0.0.0.0`: il cockpit e una console single-operator e non implementa
autenticazione multiutente.

Percorsi operativi:

- `/opt/claudit`: codice read-only;
- `/etc/claudit/service.json`: porta, data root e retention di default;
- `/etc/claudit/claudit.env`: variabili segrete opzionali, permessi `0640`;
- `/var/lib/claudit`: report, log, operazioni, stato UI e profili CLI del service account.

La UI espone **Results to keep**. Il valore indica quante run completate
conservare, viene scritto atomicamente in
`/var/lib/claudit/dashboard-state.json` e sopravvive ai restart. Le run attive e
le directory non riconosciute non vengono eliminate.

Per cambiare il default amministrativo:

```bash
sudoedit /etc/claudit/service.json
sudo systemctl restart claudit
```

Se esiste gia `dashboard-state.json`, il valore scelto dalla UI prevale. Per le
credenziali usare identita read-only e configurare i tool come account
`claudit`, per esempio `sudo -u claudit -H pwsh` oppure
`sudo -u claudit -H aws configure sso`. Claudit non crea ne conserva segreti;
gli eventuali credential store appartengono ai CLI dei provider.

Comandi di gestione:

```bash
sudo systemctl restart claudit
sudo systemctl stop claudit
sudo systemctl enable claudit
sudo journalctl -u claudit --since today
```

## Sequenza standard

1. Aprire PowerShell 7.2+ nella directory del progetto.
2. Eseguire il preflight offline.
3. Installare eventuali prerequisiti mancanti.
4. Rieseguire il preflight.
5. Lanciare audit live solo con consenso esplicito.

```powershell
cd C:\sharero\claudit
.\Test-ClauditPreflight.ps1
.\Install-ClauditPrerequisites.ps1 -IncludePester -ConfirmInstall
.\Test-ClauditPreflight.ps1
.\Start-ClauditSafeAudit.ps1 -ConfirmTenantConnection -TenantName "Contoso"
```

Esecuzione multi-cloud completa da wizard:

```powershell
.\Start-ClauditWizard.ps1
# Workload: All
```

Esecuzione omnicomprensiva solo Microsoft 365:

```powershell
.\Start-ClauditWizard.ps1
# Workload: M365
```

Per terminali embedded su Windows, usare autenticazione Graph a device code.
E il default del wizard per evitare problemi WAM/browser:

```powershell
.\Start-ClauditSafeAudit.ps1 -ConfirmTenantConnection `
  -Service M365 `
  -GraphAuthMode DeviceCode
```

## Wizard guidato

Il wizard e il punto di ingresso consigliato per il sysadmin. Salva solo
preferenze non segrete nella configurazione privata dell'utente
(`%LOCALAPPDATA%\Claudit\wizard.profile.json` su Windows,
`$XDG_CONFIG_HOME/claudit/wizard.profile.json` o `~/.config/claudit/` su Unix),
crea una directory run nuova a ogni esecuzione, esegue sempre preflight offline
e chiede conferma prima di qualsiasi connessione live. Un vecchio
`config\wizard.profile.json` viene letto per compatibilita e migrato al prossimo
salvataggio, senza essere modificato.

```powershell
.\Start-ClauditWizard.ps1
```

Modalita test/non interattiva con default e stop dopo preflight:

```powershell
.\Start-ClauditWizard.ps1 -UseDefaults -NoLive
```

Il wizard non salva webhook URL, certificate thumbprint o materiale segreto.
In aggiunta, Claudit redige in modo centralizzato token, Authorization header,
client secret, password, webhook URL e chiavi note prima di serializzare
finding, evidence, errori CLI e report. La redaction e una cintura di sicurezza:
non incollare comunque segreti reali in `TenantName`, baseline, note operative o
parametri CLI.

Se la PowerShell Gallery chiede trust del repository:

```powershell
.\Install-ClauditPrerequisites.ps1 -IncludePester -TrustPSGallery -ConfirmInstall
```

## Variabili d'ambiente

Il preflight controlla le variabili che possono cambiare il comportamento della suite:

- `CLAUDIT_FINDINGS`: usata solo da Pester per replay offline di un report JSON. Il runner live la ripristina dopo il test.
- `CLAUDIT_NOTIFY_WEBHOOK`: usata dal launcher sicuro per passare il webhook al processo isolato senza esporlo nella command line del child. Viene ripristinata dopo la run.
- `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`: possono influenzare Graph, Exchange, DNS-over-HTTPS e webhook.
- `POWERSHELL_TELEMETRY_OPTOUT`: non e richiesta, ma viene riportata per trasparenza operativa.

Per pulire un replay Pester rimasto in sessione:

```powershell
.\Reset-ClauditEnvironment.ps1
```

Per pulire anche proxy impostati solo nella sessione corrente:

```powershell
.\Reset-ClauditEnvironment.ps1 -ClearProxy
```

## Esecuzione interattiva sicura

Solo preflight, senza tenant:

```powershell
.\Start-ClauditSafeAudit.ps1
```

Audit completo, report in directory timestampata:

```powershell
.\Start-ClauditSafeAudit.ps1 -ConfirmTenantConnection -Format All -TenantName "Contoso"
```

Il launcher sicuro esegue la live audit in un processo `pwsh -NoProfile`
isolato. Questo evita conflitti di assembly tra moduli cloud gia caricati nella
sessione admin, in particolare `Microsoft.Identity.Client` / Graph / Exchange.

Audit parziale Entra + Exchange:

```powershell
.\Start-ClauditSafeAudit.ps1 -ConfirmTenantConnection -Service Entra,Exchange -Format All
```

Solo AWS, usando un profilo CLI read-only:

```powershell
.\Start-ClauditSafeAudit.ps1 -ConfirmTenantConnection `
  -Service AWS `
  -AwsProfile audit `
  -AwsRegion eu-west-1,eu-central-1 `
  -TenantName "AWS production"
```

Solo Google Cloud:

```powershell
.\Start-ClauditSafeAudit.ps1 -ConfirmTenantConnection `
  -Service GCP `
  -GcpProject prod-project `
  -GcpAccount auditor@example.com `
  -TenantName "GCP production"
```

Microsoft 365 + AWS + GCP nello stesso report:

```powershell
.\Start-ClauditSafeAudit.ps1 -ConfirmTenantConnection `
  -Service All `
  -AwsProfile audit `
  -AwsRegion eu-west-1,eu-central-1 `
  -GcpProject prod-project `
  -TenantName "Enterprise cloud estate"
```

Domini pubblici preautorizzati, senza credenziali tenant:

```powershell
.\Start-ClauditSafeAudit.ps1 -ConfirmTenantConnection `
  -Service Domain `
  -Domain example.com,example.org `
  -DomainSubdomain www,autodiscover,mail,vpn,portal,admin,dev,staging `
  -TenantName "Authorized domains"
```

Il servizio `Domain` esegue solo lookup DNS pubblici su domini dichiarati
dall'operatore. Non fa brute force, crawling, login, exploit o discovery fuori
scope. Se `-Domain` non viene passato e il baseline privato non contiene
`Domain.AuthorizedDomains`, il preflight blocca l'esecuzione.

Tutte le aree Microsoft 365, senza provider cloud esterni:

```powershell
.\Start-ClauditSafeAudit.ps1 -ConfirmTenantConnection `
  -Service M365 `
  -TenantName "Microsoft 365 estate"
```

National cloud:

```powershell
.\Start-ClauditSafeAudit.ps1 -ConfirmTenantConnection -Environment USGov
```

## Esecuzione app-only

Prerequisiti:

- certificato installato nello store accessibile all'utente/task;
- app registration con permessi read-only Graph necessari;
- per Exchange, app abilitata a Exchange Online app-only e `-Organization`.

Esempio:

```powershell
.\Start-ClauditSafeAudit.ps1 -ConfirmTenantConnection -AppOnly `
  -TenantId "<tenant-guid>" `
  -ClientId "<app-id>" `
  -CertificateThumbprint "<thumbprint>" `
  -Organization "contoso.onmicrosoft.com" `
  -TenantName "Contoso"
```

Il launcher blocca l'esecuzione se mancano `TenantId`, `ClientId`, `CertificateThumbprint` o, per Exchange, `Organization`.

## Scheduled task

Usare `pwsh.exe`, non Windows PowerShell 5.1.

Program:

```text
pwsh.exe
```

Arguments:

```text
-NoProfile -ExecutionPolicy Bypass -File C:\sharero\claudit\Start-ClauditSafeAudit.ps1 -ConfirmTenantConnection -AppOnly -TenantId <tenant-guid> -ClientId <app-id> -CertificateThumbprint <thumbprint> -Organization contoso.onmicrosoft.com -OutputDirectory C:\sharero\claudit\reports\scheduled
```

Exit code:

- `0`: run completato senza Critical/High e senza finding `Error`.
- `2`: run completato con almeno un finding Critical/High, con finding `Error`, oppure preflight fallito.
- altro non-zero: errore runtime da correggere.

## Drift

Confrontare un run precedente con quello nuovo:

```powershell
.\Start-ClauditSafeAudit.ps1 -ConfirmTenantConnection `
  -CompareWith C:\sharero\claudit\reports\baseline\claudit-20260630-080000.json
```

Il confronto richiede output JSON: usare `-Format Json` o `-Format All`.

## Notifiche

Le notifiche sono disattivate di default. Passare il webhook solo a runtime:

```powershell
.\Start-ClauditSafeAudit.ps1 -ConfirmTenantConnection `
  -NotifyWebhook "https://contoso.webhook.office.com/..." `
  -NotifyType Teams
```

Non salvare webhook in baseline, script o repository.

## Troubleshooting rapido

Modulo mancante:

```powershell
.\Install-ClauditPrerequisites.ps1 -ConfirmInstall
```

Pester vecchio:

```powershell
.\Install-ClauditPrerequisites.ps1 -IncludePester -ConfirmInstall
```

Proxy aziendale:

```powershell
$env:HTTPS_PROXY = "http://proxy.contoso.local:8080"
.\Test-ClauditPreflight.ps1
```

Errore Graph/Exchange in live run:

1. rieseguire `.\Test-ClauditPreflight.ps1 -Service <servizio>`;
2. verificare ruoli read-only e consent dell'app;
3. verificare national cloud `-Environment`;
4. rilanciare con un solo servizio per isolare.

Errore Graph WAM/MSAL come `InteractiveBrowserCredential authentication failed`
o `BaseAbstractApplicationBuilder.WithLogging(...) Method not found`:

1. usare sempre il launcher sicuro, non il runner diretto, cosi la live run parte
   in `pwsh -NoProfile`;
2. rilanciare con device code:

   ```powershell
   .\Start-ClauditSafeAudit.ps1 -ConfirmTenantConnection -Service M365 -GraphAuthMode DeviceCode
   ```

3. nel wizard scegliere `Metodo autenticazione Graph: DeviceCode`;
4. se fallisce anche nel processo isolato, reinstallare/aggiornare `Microsoft.Graph.Authentication`;
5. se serve il browser/WAM esplicitamente, usare `-GraphAuthMode Browser`, ma in terminali embedded puo fallire o aprirsi dietro altre finestre.

Exchange report con `Get-OrganizationConfig`, `Get-TransportRule` o `Get-AcceptedDomain` non riconosciuti:

1. il modulo e installato, ma la sessione live non ha importato i cmdlet richiesti;
2. verificare dopo login:

   ```powershell
   Connect-ExchangeOnline
   Get-Command Get-OrganizationConfig,Get-TransportRule,Get-AcceptedDomain
   ```

3. se mancano, assegnare all'account auditor un ruolo Exchange read-only adeguato, tipicamente `View-Only Organization Management`;
4. disconnettere e rilanciare il wizard. Il report non contiene finding tenant validi finche questa superficie cmdlet non e disponibile.

Errore AWS CLI:

1. verificare `aws --version`;
2. verificare `aws sts get-caller-identity --profile <profile>`;
3. limitare temporaneamente `-AwsRegion` a una regione nota;
4. controllare permessi read-only per IAM, CloudTrail, GuardDuty, SecurityHub, S3Control, EC2, Config.

Errore gcloud:

1. verificare `gcloud --version`;
2. verificare `gcloud auth list` e `gcloud config get-value project`;
3. passare `-GcpProject` esplicito;
4. se i check Compute risultano `Skipped`, verificare API Compute e permessi read-only sul progetto.

## Checklist prima di consegnare un report

- Preflight senza errori.
- Output JSON e HTML generati.
- TenantName corretto.
- Nessun webhook o segreto salvato su disco.
- Se `CLAUDIT_FINDINGS` e impostata, e intenzionale.
- Finding Critical/High revisionati manualmente prima di escalation.

## Protocollo test live Microsoft 365

Quando sara disponibile un account reale, usare un tenant di test o un account
read-only dedicato. Non incollare password, token, webhook o export del browser
nel terminale o nei report.

Permessi minimi consigliati:

- Entra: `Global Reader` + `Security Reader`.
- Exchange: `View-Only Organization Management`.
- Graph delegated consent per gli scope read-only indicati nel README.

Sequenza di validazione:

```powershell
.\Reset-ClauditEnvironment.ps1
.\Test-ClauditPreflight.ps1 -Service M365 -OutputDirectory .\reports\m365-live-preflight
.\Start-ClauditSafeAudit.ps1 -ConfirmTenantConnection `
  -Service M365 `
  -GraphAuthMode DeviceCode `
  -Format All `
  -TenantName "M365 test tenant" `
  -OutputDirectory .\reports\m365-live-test
```

Se fallisce, raccogliere solo:

- comando eseguito, senza segreti;
- exit code;
- ultimo blocco errore redatto;
- `reports\m365-live-preflight\preflight.json`;
- nome dei file report generati, non il contenuto se contiene dati tenant.

Per isolare un bug da un problema di permessi, rieseguire un solo servizio:

```powershell
.\Start-ClauditSafeAudit.ps1 -ConfirmTenantConnection -Service Entra -GraphAuthMode DeviceCode -OutputDirectory .\reports\m365-entra-only
.\Start-ClauditSafeAudit.ps1 -ConfirmTenantConnection -Service Exchange -OutputDirectory .\reports\m365-exchange-only
```

Runbook diagnostico dettagliato per ogni check AWS/GCP: `docs\CLOUD_PROVIDER_RUNBOOK.md`.
