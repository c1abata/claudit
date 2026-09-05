# PowerShell reference implementation

This directory preserves Claudit's pre-Bash implementation, its module
manifest, service scripts and Pester tests. It is retained for behavioural
comparison during the migration and is deliberately outside the Bash runtime.

Do not add new runtime features here. Port a check into `../../checks/` with a
Bash regression test and document any API-equivalence gap explicitly.
