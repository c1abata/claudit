<#
    Claudit.psm1 - module loader.

    Dot-sources Core first (helpers, model, connection, reporting) then Checks.
    Files are discovered by glob and loaded alphabetically within each folder, so
    adding a new check or core helper needs no change here. Core dependencies are
    named so they sort correctly (Controls before Findings, etc.).
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot

$folders = @(
    (Join-Path $root 'src/Core'),
    (Join-Path $root 'src/Checks')
)

foreach ($folder in $folders) {
    if (-not (Test-Path -LiteralPath $folder)) {
        throw "Claudit: required source folder not found: $folder"
    }
    # NOTE: use the foreach statement (not ForEach-Object) so that dot-sourcing
    # imports into the module scope, not a child pipeline scope.
    $sources = Get-ChildItem -LiteralPath $folder -Filter '*.ps1' -File | Sort-Object Name
    foreach ($src in $sources) {
        . $src.FullName
    }
}
