#!/usr/bin/env bash
ca_send_notification() {
    local report="$1" payload failed unknown coverage text
    [[ -n "$CLAUDIT_WEBHOOK_URL" ]] || return 0
    [[ "$CLAUDIT_WEBHOOK_URL" =~ ^https:// ]] || ca_die 'webhook URL must use HTTPS'
    [[ "$CLAUDIT_WEBHOOK_TYPE" == slack || "$CLAUDIT_WEBHOOK_TYPE" == teams ]] || ca_die 'webhook type must be slack or teams'
    failed="$(jq '.summary.failed // ([.findings[] | select(.status == "fail")] | length)' "$report")"
    unknown="$(jq '.summary.not_assessed // ([.findings[] | select(.status == "unknown" or .status == "error")] | length)' "$report")"
    coverage="$(jq '.summary.coverage // 0 | floor' "$report")"
    if (( unknown > 0 )); then text="Claudit incomplete: $failed failing finding(s), $unknown not assessed, coverage ${coverage}%."; else text="Claudit: $failed failing finding(s), coverage ${coverage}%."; fi
    if [[ "$CLAUDIT_WEBHOOK_TYPE" == slack ]]; then payload="$(jq -cn --arg text "$text" '{text:$text}')"; else payload="$(jq -cn --arg text "$text" '{"@type":"MessageCard","@context":"http://schema.org/extensions",summary:$text,title:$text}')"; fi
    curl --fail --silent --show-error --max-time 15 -H 'Content-Type: application/json' --data "$payload" "$CLAUDIT_WEBHOOK_URL" >/dev/null
}
