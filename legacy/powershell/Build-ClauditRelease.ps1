<#
.SYNOPSIS
    Builds the Claudit source release from the current clean Git commit.

.DESCRIPTION
    Uses git archive so the ZIP contains only versioned files and honors
    export-ignore rules. Refuses a dirty tree to keep the artifact traceable to
    one commit. Writes a sha256sum-compatible checksum beside the archive.
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'dist')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$manifestPath = Join-Path $PSScriptRoot 'Claudit.psd1'
$manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
$version = $manifest.Version.ToString()

$git = Get-Command git -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $git) {
    throw 'git is required to build a traceable Claudit release archive.'
}

$insideWorkTree = & $git.Source -C $PSScriptRoot rev-parse --is-inside-work-tree 2>$null
if ($LASTEXITCODE -ne 0 -or $insideWorkTree -ne 'true') {
    throw "Claudit release root is not a Git worktree: $PSScriptRoot"
}

$workTreeStatus = @(& $git.Source -C $PSScriptRoot status --porcelain=v1 --untracked-files=all)
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to inspect the Claudit worktree before packaging.'
}
if ($workTreeStatus.Count -gt 0) {
    throw 'Refusing to package an uncommitted working tree. Commit or remove all changes first.'
}

$resolvedOutput = [System.IO.Path]::GetFullPath($OutputDirectory)
[System.IO.Directory]::CreateDirectory($resolvedOutput) | Out-Null

$baseName = "claudit-$version"
$archivePath = Join-Path $resolvedOutput "$baseName.zip"
$temporaryArchive = Join-Path $resolvedOutput ".$baseName.$([guid]::NewGuid().ToString('N')).tmp"
$checksumPath = "$archivePath.sha256"
$temporaryChecksum = "$checksumPath.tmp"

try {
    & $git.Source -C $PSScriptRoot archive --format=zip "--prefix=$baseName/" "--output=$temporaryArchive" HEAD
    if ($LASTEXITCODE -ne 0 -or -not [System.IO.File]::Exists($temporaryArchive)) {
        throw 'git archive failed to produce the Claudit release ZIP.'
    }

    [System.IO.File]::Move($temporaryArchive, $archivePath, $true)
    $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText(
        $temporaryChecksum,
        "$hash  $([System.IO.Path]::GetFileName($archivePath))`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    [System.IO.File]::Move($temporaryChecksum, $checksumPath, $true)

    [pscustomobject]@{
        Version      = $version
        Archive      = $archivePath
        Sha256       = $hash
        ChecksumFile = $checksumPath
    }
}
finally {
    foreach ($temporaryPath in @($temporaryArchive, $temporaryChecksum)) {
        if ([System.IO.File]::Exists($temporaryPath)) {
            [System.IO.File]::Delete($temporaryPath)
        }
    }
}
