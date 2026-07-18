#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v pwsh >/dev/null 2>&1; then
  echo "claudit: pwsh is required. Install PowerShell 7.2+ first." >&2
  exit 127
fi

exec pwsh -NoProfile -ExecutionPolicy Bypass -File "$root/claudit.ps1" "$@"
