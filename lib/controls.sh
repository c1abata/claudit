#!/usr/bin/env bash
# Control contract: collectors may only emit catalogued controls.  The catalog is
# intentionally plain JSON so it can be reviewed without learning a DSL.

CLAUDIT_CONTROL_CATALOG="${CLAUDIT_CONTROL_CATALOG:-$CLAUDIT_ROOT/config/runtime-control-catalog.json}"

ca_control_metadata() {
    local id="$1"
    jq -cer --arg id "$id" '.Controls[] | select(.Id == $id)' "$CLAUDIT_CONTROL_CATALOG" 2>/dev/null
}

ca_control_exists() {
    ca_control_metadata "$1" >/dev/null
}

ca_control_remediation() {
    ca_control_metadata "$1" | jq -r '.Remediation'
}

ca_control_category() {
    ca_control_metadata "$1" | jq -r '.Category'
}

ca_validate_control_catalog() {
    [[ -f "$CLAUDIT_CONTROL_CATALOG" && ! -L "$CLAUDIT_CONTROL_CATALOG" ]] || ca_die "control catalog '$CLAUDIT_CONTROL_CATALOG' must be a regular file"
    jq -e '.Version | type == "string"' "$CLAUDIT_CONTROL_CATALOG" >/dev/null || ca_die 'control catalog lacks a version'
    jq -e '([.Controls[] | .Id]) as $ids | ($ids | length) > 0 and ($ids | length) == ($ids | unique | length)' "$CLAUDIT_CONTROL_CATALOG" >/dev/null || ca_die 'control catalog contains duplicate or no IDs'
    jq -e '[.Controls[] | select((.Id|type) != "string" or (.Service|type) != "string" or (.Level|type) != "string" or (.Remediation|type) != "string")] | length == 0' "$CLAUDIT_CONTROL_CATALOG" >/dev/null || ca_die 'control catalog has an invalid control contract'
}

ca_validate_emitted_controls() {
    local unknown
    unknown="$(jq -r '.id' "$CLAUDIT_FINDINGS_FILE" | sort -u | while IFS= read -r id; do ca_control_exists "$id" || printf '%s\n' "$id"; done)"
    [[ -z "$unknown" ]] || ca_die "collector emitted uncatalogued control(s): $(tr '\n' ' ' <<<"$unknown")"
}
