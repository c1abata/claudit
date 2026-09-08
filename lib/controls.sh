#!/usr/bin/env bash
# Control contract: collectors may only emit catalogued controls.  The catalog is
# intentionally plain JSON so it can be reviewed without learning a DSL.

CLAUDIT_CONTROL_CATALOG="${CLAUDIT_CONTROL_CATALOG:-$CLAUDIT_ROOT/config/runtime-control-catalog.json}"
CLAUDIT_BASELINE_CAPABILITY_MAP="${CLAUDIT_BASELINE_CAPABILITY_MAP:-$CLAUDIT_ROOT/config/baseline-capabilities.json}"

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

ca_validate_baseline_capabilities() {
    [[ -f "$CLAUDIT_BASELINE_CAPABILITY_MAP" && ! -L "$CLAUDIT_BASELINE_CAPABILITY_MAP" ]] || ca_die "baseline capability map '$CLAUDIT_BASELINE_CAPABILITY_MAP' must be a regular file"
    jq -e '.Version | type == "string"' "$CLAUDIT_BASELINE_CAPABILITY_MAP" >/dev/null || ca_die 'baseline capability map lacks a version'
    jq -e '(.Capabilities | type == "array" and length > 0) and (([.Capabilities[] | .Path]) as $paths | ($paths | length) == ($paths | unique | length))' "$CLAUDIT_BASELINE_CAPABILITY_MAP" >/dev/null || ca_die 'baseline capability map has duplicate or no paths'
    jq -e '[.Capabilities[] | . as $entry | select(($entry.Path | type) != "string" or (["enforced", "scope_only", "unsupported"] | index($entry.State) | not) or ($entry.Controls | type) != "array" or ($entry.Explanation | type) != "string")] | length == 0' "$CLAUDIT_BASELINE_CAPABILITY_MAP" >/dev/null || ca_die 'baseline capability map has an invalid entry'
}

ca_validate_baseline_capability_coverage() {
    local baseline="$1"
    jq -en --slurpfile baseline "$baseline" --slurpfile capabilities "$CLAUDIT_BASELINE_CAPABILITY_MAP" '
      def canonical_paths:
        [paths(scalars) | select(.[-1] != "_comment") |
          . as $path |
          ([$path | to_entries[] | select(.value | type == "number") | .key][0]) as $array_index |
          (if $array_index == null then $path else $path[0:$array_index] end) |
          map(select(type != "number")) | join(".")] +
        [paths(type == "array") |
          . as $path |
          ([$path | to_entries[] | select(.value | type == "number") | .key][0]) as $array_index |
          (if $array_index == null then $path else $path[0:$array_index] end) |
          map(select(type != "number")) | join(".")] | unique;
      ($baseline[0] | canonical_paths) as $baseline_paths |
      ($capabilities[0].Capabilities | map(.Path) | unique) as $mapped_paths |
      ($baseline_paths - $mapped_paths | length == 0)
    ' >/dev/null || ca_die 'baseline capability map must classify every configurable baseline path'
}

ca_validate_emitted_controls() {
    local unknown
    unknown="$(jq -r '.id' "$CLAUDIT_FINDINGS_FILE" | sort -u | while IFS= read -r id; do ca_control_exists "$id" || printf '%s\n' "$id"; done)"
    [[ -z "$unknown" ]] || ca_die "collector emitted uncatalogued control(s): $(tr '\n' ' ' <<<"$unknown")"
}

# Missing collectors must reduce coverage, including prerequisites that stop a service.
ca_complete_controls() {
    local id service level category
    while IFS='|' read -r id service level category; do
        [[ "$service" != Runtime && "$category" != runtime ]] || continue
        ca_selected "$service" || { [[ "$service" =~ ^(Entra|SharePoint|OneDrive|Exchange)$ ]] && ca_selected M365; } || { [[ "$service" == M365 ]] && { ca_selected Entra || ca_selected SharePoint || ca_selected OneDrive; }; } || continue
        [[ "$level" != Active || "$CLAUDIT_LEVEL" == active ]] || continue
        [[ "$level" == Formal || "$CLAUDIT_LEVEL" != formal ]] || continue
        jq -e --arg id "$id" 'select(.id == $id)' "$CLAUDIT_FINDINGS_FILE" >/dev/null && continue
        ca_finding "$id" "$service" unknown medium 'Control not assessed' 'No evidence was emitted for this planned control; inspect prerequisites and collector coverage.'
    done < <(jq -r '.Controls[] | [.Id,.Service,.Level,.Category] | join("|")' "$CLAUDIT_CONTROL_CATALOG")
}
