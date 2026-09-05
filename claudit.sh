#!/usr/bin/env bash
# Claudit Bash front controller. All live operations are read-only.
set -euo pipefail

CLAUDIT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/core.sh
source "$CLAUDIT_ROOT/lib/core.sh"

main "$@"
