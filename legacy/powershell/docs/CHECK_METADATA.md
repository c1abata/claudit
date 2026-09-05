# Check metadata catalog

Claudit separates executable checks from reusable operational metadata in
`config/check-metadata.json`. The compact model borrows Prowler's separation of
check behavior and metadata without importing one large JSON document per check.

Every production `CheckId` must belong to exactly one profile. Profiles define
the shared category, threat, risk and remediation language; narrow overrides
carry exceptional severity, relationships or control-specific guidance. Module
import fails when an ID is missing, duplicated, unknown or self-referential.
Synthetic diagnostic and legacy comparison IDs may use a clearly marked
`runtime-unclassified` fallback. This does not weaken the import-time guarantee
that every production control has an explicit catalog assignment.

Each finding receives:

- `MetadataCatalogVersion` and `MetadataProfile`
- `DefaultSeverity`
- `Categories` and `Threats`
- `Risk`
- `DependsOn` and `RelatedTo`

The behavioral `Status`, observed `Severity`, `Detail` and `Evidence` still come
from the check. If a check emits no recommendation, the profile remediation is
used as a safe fallback. `Format All` and `Format Catalog` emit the compact
metadata catalog as a separate `.checks.json` artifact.

This is intentionally not a remediation engine: metadata explains operator
intent, while Claudit remains read-only and never executes fix commands.
