#!/usr/bin/env bash
ca_drift_rank() { case "$1" in pass|info|not_applicable) echo 0;; unknown|warning) echo 1;; fail) echo 3;; *) echo 2;; esac; }
ca_compare_reports() {
    local reference="$1" difference="$2" output
    [[ -r "$reference" && -r "$difference" ]] || ca_die 'compare requires readable --reference and --difference JSON reports'
    jq -e '.findings | type == "array"' "$reference" "$difference" >/dev/null || ca_die 'compare inputs must be Claudit JSON reports'
    output="${CLAUDIT_OUTPUT_DIRECTORY:-$CLAUDIT_ROOT/reports/compare-$(date -u +%Y%m%dT%H%M%SZ)}"
    mkdir -p -- "$output"
    jq -n --slurpfile old "$reference" --slurpfile new "$difference" '
      ($old[0].findings | map({key:(.finding_id // (.service + "|" + .id)),value:.}) | from_entries) as $a |
      ($new[0].findings | map({key:(.finding_id // (.service + "|" + .id)),value:.}) | from_entries) as $b |
      [$a,$b | keys[]] | unique | map(. as $id | $a[$id] as $before | $b[$id] as $after |
        {finding_id:$id,id:($after.id // $before.id),service:($after.service // $before.service),title:($after.title // $before.title),old_status:($before.status // null),new_status:($after.status // null),change:(if $before == null then "New" elif $after == null then "Removed" elif $before.status == $after.status and $before.evidence_sha256 != $after.evidence_sha256 then "EvidenceChanged" elif $before.status == $after.status then "Unchanged" elif ($after.status == "fail" and $before.status != "fail") then "Regressed" elif ($before.status == "fail" and $after.status != "fail") then "Fixed" else "Changed" end)})' > "$output/claudit-drift.json"
    ca_log "drift report written to $output/claudit-drift.json"
}
