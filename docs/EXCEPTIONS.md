# Governed finding exceptions

Claudit can suppress an accepted `Fail`, `Warning` or `Investigate` finding at
report time without changing its original status. The exception remains visible
in JSON, CSV, Markdown, HTML, OCSF and the complete finding list.

Start from `config/exceptions.example.json`, copy it outside the repository and
pass the private file to the audit:

```powershell
./Invoke-ClauditAudit.ps1 -Service AWS -ConfirmTenantConnection `
  -ExceptionPath C:\secure\claudit-exceptions.json
```

Every enabled rule requires an exact `CheckId`, an owner, a reason, a ticket and
an expiry. Resource-specific rules use the privacy-preserving `FindingId` from a
previous report. A check-wide rule is allowed only when `AllowBroad` is set to
`true`. Rules are ANDed, duplicate matches fail the report, and expired rules do
not suppress findings.

Execution errors and skipped checks cannot be suppressed. Suppression never
changes `Status`; it sets `IsSuppressed`, attaches governance metadata and maps
the OCSF status to `Suppressed`. Review the `ExceptionPolicy` summary on every
run and keep the private policy file under the same change control as risk
acceptance records.
