#!/usr/bin/env bash
# Public-business-domain checks. Passive collection is DNS only; active mode
# performs one bounded TLS/HEAD handshake to the exact declared root domain.

ca_dns_resolver() {
    jq -ce '.Domain.Resolver | {name:.Name,endpoint:.Endpoint,private:.Private,timeout_seconds:.TimeoutSeconds,transport:"dns-over-https",fallback:"disabled"}' "$(ca_baseline_path)" 2>/dev/null
}

ca_dns_resolver_label() { ca_dns_resolver | jq -r .name; }

ca_dns_lookup() {
    local resolver
    resolver="$(ca_dns_resolver)" || return 1
    ca_dns_lookup_with_resolver "$1" "$2" "$resolver"
}

ca_dns_lookup_with_resolver() {
    local name="$1" type="$2" resolver="$3" key response endpoint timeout
    key="${name}|${type}"
    if [[ -n "$CLAUDIT_DOH_FIXTURE" ]]; then
        [[ -r "$CLAUDIT_DOH_FIXTURE" && ! -L "$CLAUDIT_DOH_FIXTURE" ]] || return 1
        response="$(jq -cer --arg key "$key" '.[$key]' "$CLAUDIT_DOH_FIXTURE" 2>/dev/null)" || return 1
    else
        endpoint="$(jq -r .endpoint <<<"$resolver")"
        timeout="$(jq -r .timeout_seconds <<<"$resolver")"
        response="$(curl --fail --silent --show-error --proto '=https' --tlsv1.2 --max-time "$timeout" --get \
            --data-urlencode "name=$name" --data-urlencode "type=$type" \
            "$endpoint" -H 'accept: application/dns-json' 2>/dev/null)" || return 1
    fi
    # HTTP success is not DNS success. SERVFAIL, REFUSED and truncation are unavailable.
    jq -e 'type == "object" and (.Status == 0 or .Status == 3) and (.TC != true) and ((.Answer // []) | type == "array") and all(.Answer[]?; (.data | type) == "string")' >/dev/null 2>&1 <<<"$response" || return 1
    local code
    case "$type" in A) code=1;; NS) code=2;; CNAME) code=5;; MX) code=15;; TXT) code=16;; AAAA) code=28;; DNSKEY) code=48;; CAA) code=257;; esac
    response="$(jq -c --argjson code "$code" '.Answer = [ .Answer[]? | select(.type == $code) ]' <<<"$response")"
    jq -cn --arg name "$name" --arg type "$type" --argjson resolver "$resolver" --argjson response "$response" '{name:$name,type:$type,resolver:$resolver,response:$response}' >> "$CLAUDIT_OUTPUT_DIRECTORY/claudit-dns-evidence.jsonl"
    printf '%s\n' "$response"
}

ca_dns_answers() { jq -r '.Answer[]?.data // empty' <<<"$1"; }
ca_domain_authorized() {
    local domain="$1"
    jq -e --arg domain "$domain" '(.Domain.AuthorizedDomains // []) as $domains | ($domains | length == 0) or ($domains | index($domain) != null)' "$(ca_baseline_path)" >/dev/null
}

ca_check_configured_subdomains() {
    local prefix name type response values checked=0 found=0 unavailable=0 candidate_available candidate_found
    : >"$CLAUDIT_OUTPUT_DIRECTORY/claudit-dns-subdomains.jsonl"
    while IFS= read -r prefix; do
        checked=$((checked + 1)); name="${prefix,,}.$CLAUDIT_DOMAIN"; candidate_available=0; candidate_found=0
        for type in A AAAA CNAME; do
            response="$(ca_dns_lookup "$name" "$type" || true)"
            [[ -n "$response" ]] || continue
            candidate_available=1
            values="$(ca_dns_answers "$response")"
            if [[ -n "$values" ]]; then
                candidate_found=1
                jq -cn --arg name "$name" --arg type "$type" --argjson values "$(jq -Rn '[inputs | select(length > 0)]' <<<"$values")" '{name:$name,type:$type,values:$values}' >>"$CLAUDIT_OUTPUT_DIRECTORY/claudit-dns-subdomains.jsonl"
            fi
        done
        found=$((found + candidate_found))
        (( candidate_available )) || unavailable=$((unavailable + 1))
    done < <(jq -r '.Domain.Subdomains[]?' "$(ca_baseline_path)")
    if (( checked == 0 )); then ca_finding CA-DNS-SUBDOMAINS Domain not_applicable info 'No configured subdomain candidates' 'Add bounded single-label candidates to Domain.Subdomains when discovery is required.'
    elif (( unavailable > 0 )); then ca_finding CA-DNS-SUBDOMAINS Domain unknown medium 'Configured subdomain discovery incomplete' "$unavailable of $checked configured candidates had no valid DNS response; $found responsive candidate(s) were retained."
    else ca_finding CA-DNS-SUBDOMAINS Domain pass info 'Configured subdomain discovery complete' "Checked $checked bounded candidates and retained $found responsive name(s) in claudit-dns-subdomains.jsonl."; fi
}

ca_check_dnsx() {
    if ! ca_baseline_enabled '.Domain.EnableDnsx'; then ca_finding CA-DNS-DNSX Domain info info 'dnsx discovery disabled' 'The local baseline disables optional dnsx wordlist discovery.'; return; fi
    local binary rate timeout_seconds wordlist output resolver_args=() resolvers count
    binary="$(ca_baseline_get '.Domain.DnsxBinary' | tr -d '"')"; rate="$(ca_baseline_get '.Domain.DnsxRateLimit')"; timeout_seconds="$(ca_baseline_get '.Domain.DnsxTimeoutSeconds')"
    if ! ca_command_exists "$binary"; then ca_finding CA-DNS-DNSX Domain unknown medium 'dnsx unavailable' "The configured dnsx binary '$binary' is not installed."; return; fi
    wordlist="$CLAUDIT_OUTPUT_DIRECTORY/.dnsx-wordlist"; jq -r '.Domain.Subdomains[]?' "$(ca_baseline_path)" >"$wordlist"
    [[ -s "$wordlist" ]] || { ca_finding CA-DNS-DNSX Domain not_applicable info 'dnsx wordlist empty' 'Domain.Subdomains contains no bounded discovery candidates.'; return; }
    resolvers="$(jq -r '.Domain.DnsxResolvers | join(",")' "$(ca_baseline_path)")"; [[ -z "$resolvers" ]] || resolver_args=(-r "$resolvers")
    if ! output="$(ca_run_cli "$binary" -d "$CLAUDIT_DOMAIN" -w "$wordlist" -rl "$rate" -timeout "$timeout_seconds" -silent -json -omit-raw -disable-update-check "${resolver_args[@]}" 2>/dev/null)"; then ca_finding CA-DNS-DNSX Domain unknown medium 'dnsx discovery unavailable' 'The bounded dnsx process failed or exceeded the global command deadline.'; return; fi
    if ! jq -s -e --arg domain "$CLAUDIT_DOMAIN" 'length <= 100 and all(.[]; type == "object" and (.host | type == "string") and (.host == $domain or (.host | endswith("." + $domain))) and (.host | split(".") | all(.[]; length >= 1 and length <= 63 and test("^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$"))))' >/dev/null 2>&1 <<<"$output"; then ca_finding CA-DNS-DNSX Domain error high 'dnsx response malformed or out of scope' 'dnsx output exceeded the evidence bound or contained a malformed hostname outside the authorized root domain.'; return; fi
    jq -sc '[.[] | {host, a:(.a // []), aaaa:(.aaaa // []), cname:(.cname // [])}]' <<<"$output" >"$CLAUDIT_OUTPUT_DIRECTORY/claudit-dnsx-discovery.json"
    count="$(jq length "$CLAUDIT_OUTPUT_DIRECTORY/claudit-dnsx-discovery.json")"
    ca_finding CA-DNS-DNSX Domain pass info 'dnsx discovery complete' "dnsx retained $count in-scope result(s) from the bounded configured wordlist."
}

ca_check_domain() {
    local domain="${CLAUDIT_DOMAIN,,}" label response records spf dmarc policy selector resolver_label found=0 dkim_collected=0
    if [[ -z "$domain" ]]; then ca_finding CA-DNS-000 Domain unknown medium 'Business domain scope required' 'Provide one explicitly authorized business domain.'; return; fi
    [[ "$domain" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,251}[A-Za-z0-9]$ ]] || { ca_finding CA-DNS-000 Domain error high 'Invalid business domain scope' 'The supplied domain is not a valid hostname.'; return; }
    local -a labels
    IFS='.' read -r -a labels <<<"$domain"
    for label in "${labels[@]}"; do
        [[ "$label" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || { ca_finding CA-DNS-000 Domain error high 'Invalid domain label' 'Each DNS label must be 1–63 characters without leading or trailing hyphens.'; return; }
    done
    if ! ca_domain_authorized "$domain"; then ca_finding CA-DNS-000 Domain error high 'Business domain is outside policy scope' "The declared domain is not present in Domain.AuthorizedDomains."; return; fi
    ca_finding CA-DNS-000 Domain pass info 'Business domain scope accepted' "Declared domain '$domain' is valid and within the local authorized scope policy."
    # `set -e` is active in the runtime: make the successful formal-only exit
    # explicit instead of returning the failed comparison status.
    [[ "$CLAUDIT_LEVEL" != formal ]] || return 0
    resolver_label="$(ca_dns_resolver_label)"

    for selector in A AAAA MX NS TXT CAA; do
        response="$(ca_dns_lookup "$domain" "$selector" || true)"
        if [[ -z "$response" ]]; then ca_finding "CA-DNS-$selector" Domain unknown medium "DNS $selector lookup unavailable" "The DNS resolver did not return a valid $selector response for $domain."; continue; fi
        records="$(ca_dns_answers "$response")"
        if [[ -n "$records" ]]; then
            if [[ "$selector" == NS ]] && (( $(wc -l <<<"$records") < 2 )); then ca_finding CA-DNS-NS Domain warning medium 'Insufficient authoritative DNS redundancy' "Only one NS record was returned for $domain."; else ca_finding "CA-DNS-$selector" Domain pass info "DNS $selector record resolved" "Configured resolver '$resolver_label' returned $(wc -l <<<"$records") $selector record(s) for $domain."; fi
        elif [[ "$selector" == NS ]]; then ca_finding CA-DNS-NS Domain fail high 'Authoritative name servers absent' "No NS record was returned for $domain."; else ca_finding "CA-DNS-$selector" Domain unknown low "DNS $selector record absent" "Configured resolver '$resolver_label' returned no $selector answer for $domain; applicability requires operator review."; fi
    done

    response="$(ca_dns_lookup "$domain" TXT || true)"
    if [[ -z "$response" ]]; then ca_finding CA-DNS-SPF Domain unknown medium 'SPF lookup unavailable' "TXT records could not be collected for $domain."; else
        spf="$(ca_dns_answers "$response" | tr -d '"' | awk 'tolower($0) ~ /^v=spf1([[:space:]]|$)/ {print}')"
        if (( $(wc -l <<<"$spf") > 1 )); then ca_finding CA-DNS-SPF Domain fail high 'Multiple SPF records published' 'Multiple SPF records create an invalid and unpredictable sender policy.'
        elif [[ -z "$spf" ]]; then ca_finding CA-DNS-SPF Domain warning medium 'SPF record absent' 'No SPF policy was found; confirm that this business domain does not send mail.'
        elif (( $(grep -Eo '(^|[[:space:]])(include:|a[:[:space:]]|mx[:[:space:]]|exists:|ptr[:[:space:]])' <<<"$spf" | wc -l) > 10 )); then ca_finding CA-DNS-SPF Domain warning high 'SPF may exceed DNS lookup limit' 'The published SPF text contains more than ten DNS-lookup mechanisms; validate it with the active mail providers.'
        else ca_finding CA-DNS-SPF Domain pass info 'SPF policy present' 'One SPF policy was found with no obvious static lookup-limit violation.'; fi
    fi

    response="$(ca_dns_lookup "_dmarc.$domain" TXT || true)"
    dmarc="$(ca_dns_answers "$response" | tr -d '"' | awk 'tolower($0) ~ /^v=dmarc1;/ {print}')"
    if [[ -z "$response" ]]; then ca_finding CA-DNS-DMARC Domain unknown medium 'DMARC lookup unavailable' "The resolver could not collect _dmarc.$domain."
    elif (( $(wc -l <<<"$dmarc") > 1 )); then ca_finding CA-DNS-DMARC Domain fail high 'Multiple DMARC records published' 'Publish exactly one DMARC policy at the declared name.'
    elif [[ -z "$dmarc" ]]; then ca_finding CA-DNS-DMARC Domain fail high 'DMARC record absent' "No DMARC policy was found for _dmarc.$domain."
    else
        policy="$(tr '[:upper:]' '[:lower:]' <<<"$dmarc" | sed -nE 's/.*(^|;[[:space:]]*)p=([^;[:space:]]+).*/\2/p')"
        case "$policy" in reject|quarantine) ca_finding CA-DNS-DMARC Domain pass info 'DMARC enforcement enabled' "DMARC policy '$policy' is published for $domain.";; none) ca_finding CA-DNS-DMARC Domain warning medium 'DMARC monitoring-only policy' 'DMARC is present but p=none does not enforce spoofing protection.';; *) ca_finding CA-DNS-DMARC Domain unknown medium 'DMARC policy unreadable' 'A DMARC record was returned but its p= value could not be evaluated.';; esac
    fi

    response="$(ca_dns_lookup "$domain" DNSKEY || true)"
    if ca_baseline_enabled '.Domain.RequireDnssec'; then
        if [[ -n "$response" ]] && jq -e '(.AD == true) and (.CD != true) and ((.Answer // []) | length > 0)' >/dev/null <<<"$response"; then ca_finding CA-DNS-DNSSEC Domain pass info 'DNSSEC material observed' 'The resolver returned authenticated DNSSEC material for the declared domain.'; else ca_finding CA-DNS-DNSSEC Domain unknown medium 'DNSSEC not verified' 'DNSSEC could not be verified from the configured resolver; do not treat this as proof of absence.'; fi
    else ca_finding CA-DNS-DNSSEC Domain info info 'DNSSEC policy not required' 'The local baseline does not require DNSSEC for this domain.'; fi

    response="$(ca_dns_lookup "_mta-sts.$domain" TXT || true)"
    if [[ -z "$response" ]]; then ca_finding CA-DNS-MTA-STS Domain unknown low 'MTA-STS lookup unavailable' 'MTA-STS applicability could not be assessed because DNS collection failed.'
    elif ca_dns_answers "$response" | tr -d '"' | grep -qi '^v=STSv1;'; then ca_finding CA-DNS-MTA-STS Domain pass info 'MTA-STS policy advertised' 'An MTA-STS DNS policy is published.'
    else ca_finding CA-DNS-MTA-STS Domain warning low 'MTA-STS policy absent' 'No MTA-STS TXT policy was found; assess applicability for inbound business mail.'; fi
    response="$(ca_dns_lookup "_smtp._tls.$domain" TXT || true)"
    if [[ -z "$response" ]]; then ca_finding CA-DNS-TLS-RPT Domain unknown low 'TLS-RPT lookup unavailable' 'TLS-RPT applicability could not be assessed because DNS collection failed.'
    elif ca_dns_answers "$response" | tr -d '"' | grep -qi '^v=TLSRPTv1;'; then ca_finding CA-DNS-TLS-RPT Domain pass info 'TLS-RPT policy advertised' 'A TLS-RPT DNS policy is published.'
    else ca_finding CA-DNS-TLS-RPT Domain warning low 'TLS-RPT policy absent' 'No TLS-RPT policy was found; failed mail TLS delivery will have less visibility.'; fi

    for selector in $(jq -r '.Domain.DkimSelectors[]?' "$(ca_baseline_path)"); do
        response="$(ca_dns_lookup "${selector}._domainkey.$domain" TXT || true)"
        [[ -n "$response" ]] || continue
        dkim_collected=1
        if ca_dns_answers "$response" | tr -d '"' | grep -qi 'v=DKIM1'; then found=1; break; fi
    done
    if (( found )); then ca_finding CA-DNS-DKIM Domain pass info 'Configured DKIM selector found' 'At least one selector from the local business-domain baseline published a DKIM key.'
    elif (( dkim_collected )); then ca_finding CA-DNS-DKIM Domain warning medium 'No configured DKIM selector found' 'No configured selector returned a DKIM key; update the baseline or publish the current provider selector.'
    else ca_finding CA-DNS-DKIM Domain unknown medium 'DKIM selector lookup unavailable' 'Configured DKIM selectors could not be collected; this is not evidence that keys are absent.'; fi

    ca_check_configured_subdomains
    ca_check_dnsx
    ca_dns_baseline
    ca_dns_propagation

    if [[ "$CLAUDIT_LEVEL" == active ]]; then
        if curl --fail --silent --show-error --proto '=https' --tlsv1.2 --head --max-time 12 "https://$domain/" >/dev/null 2>&1; then ca_finding CA-DNS-TLS Domain pass info 'Declared HTTPS endpoint completed TLS' "One bounded HTTPS HEAD request completed for $domain."; else ca_finding CA-DNS-TLS Domain unknown medium 'Declared HTTPS endpoint not verified' "The bounded TLS/HTTPS HEAD request to $domain did not complete; inspect DNS, certificate and listener state."; fi
    fi
}

ca_dns_baseline() {
    local entry name type expected response actual status=pass count=0 ttl_status=pass ttl_evaluated=0 min_ttl max_ttl ttls=null
    min_ttl="$(ca_baseline_get '.Domain.MinTtlSeconds')"; max_ttl="$(ca_baseline_get '.Domain.MaxTtlSeconds')"
    while IFS= read -r entry; do
        count=$((count + 1))
        name="$(jq -r .name <<<"$entry")"; type="$(jq -r .type <<<"$entry")"
        expected="$(jq -c '.values | sort | unique' <<<"$entry")"
        response="$(ca_dns_lookup "$name" "$type" || true)"
        if [[ -z "$response" ]]; then
            actual=null; ttls=null; [[ "$status" == fail ]] || status=unknown; [[ "$ttl_status" == fail ]] || ttl_status=unknown
        else
            actual="$(jq -c '[.Answer[]?.data] | sort | unique' <<<"$response")"
            [[ "$actual" == "$expected" ]] || status=fail
            ttls="$(jq -c '[.Answer[]?.TTL]' <<<"$response")"
            if (( $(jq length <<<"$actual") > 0 )); then
                if ! jq -e 'all(.Answer[]?; (.TTL | type == "number") and (.TTL | floor == .) and .TTL >= 0)' >/dev/null 2>&1 <<<"$response"; then [[ "$ttl_status" == fail ]] || ttl_status=unknown
                elif jq -e --argjson minimum "$min_ttl" --argjson maximum "$max_ttl" 'all(.Answer[]?; .TTL >= $minimum and .TTL <= $maximum)' >/dev/null <<<"$response"; then ttl_evaluated=$((ttl_evaluated + $(jq '.Answer | length' <<<"$response")))
                else ttl_status=fail; fi
            fi
        fi
        jq -cn --arg name "$name" --arg type "$type" --argjson expected "$expected" --argjson actual "$actual" --argjson observed_ttls "$ttls" --argjson minimum_ttl "$min_ttl" --argjson maximum_ttl "$max_ttl" '{name:$name,type:$type,expected:$expected,observed:$actual,observed_ttls:$observed_ttls,ttl_policy:{minimum:$minimum_ttl,maximum:$maximum_ttl},change:(if $actual == null then "blocked" elif $actual == $expected then "none" elif ($actual|length) == 0 then "create" elif ($expected|length) == 0 then "delete" else "replace" end),preconditions:{authorized_scope:true,current_values_must_equal:$actual},rollback:{restore_values:$actual},verify:{query_name:$name,query_type:$type,expected_values:$expected},action:(if $actual == null then "Collect evidence before proposing changes" elif $actual == $expected then "No change" else "Review the exact RRset diff; apply outside Claudit only after current-value precondition and retain rollback values" end)}' >> "$CLAUDIT_OUTPUT_DIRECTORY/claudit-dns-plan.jsonl"
    done < <(jq -c '.Domain.ExpectedRecords[]?' "$(ca_baseline_path)")
    if (( count == 0 )); then ca_finding CA-DNS-BASELINE Domain not_applicable info 'No desired DNS records declared' 'Add expected RRsets to a work session to assess DNS configuration drift.'
    else ca_finding CA-DNS-BASELINE Domain "$status" medium 'Desired DNS configuration comparison' "Compared $count declared RRsets. See claudit-dns-plan.jsonl for observed values and reviewable changes; no remote writes occurred."; fi
    if (( count == 0 || ttl_evaluated == 0 )) && [[ "$ttl_status" == pass ]]; then ca_finding CA-DNS-TTL Domain not_applicable info 'No observed TTLs to assess' 'Declare desired RRsets with observed answers to evaluate TTL policy.'
    elif [[ "$ttl_status" == pass ]]; then ca_finding CA-DNS-TTL Domain pass info 'Observed DNS TTLs within baseline' "All $ttl_evaluated observed TTL value(s) are between $min_ttl and $max_ttl seconds."
    elif [[ "$ttl_status" == fail ]]; then ca_finding CA-DNS-TTL Domain fail medium 'Observed DNS TTL outside baseline' "At least one desired RRset TTL is outside $min_ttl–$max_ttl seconds."
    else ca_finding CA-DNS-TTL Domain unknown medium 'DNS TTL evidence incomplete' 'One or more desired RRsets lacked a valid DNS response or numeric TTL evidence.'; fi
}

ca_dns_propagation() {
    local resolver entry name type expected response actual resolver_name total=0 unavailable=0 mismatch=0
    : >"$CLAUDIT_OUTPUT_DIRECTORY/claudit-dns-propagation.jsonl"
    while IFS= read -r resolver; do
        resolver_name="$(jq -r .name <<<"$resolver")"
        while IFS= read -r entry; do
            total=$((total + 1)); name="$(jq -r .name <<<"$entry")"; type="$(jq -r .type <<<"$entry")"; expected="$(jq -c '.values | sort | unique' <<<"$entry")"
            response="$(ca_dns_lookup_with_resolver "$name" "$type" "$resolver" || true)"
            if [[ -z "$response" ]]; then actual=null; unavailable=$((unavailable + 1))
            else actual="$(jq -c '[.Answer[]?.data] | sort | unique' <<<"$response")"; [[ "$actual" == "$expected" ]] || mismatch=$((mismatch + 1)); fi
            jq -cn --arg resolver "$resolver_name" --arg name "$name" --arg type "$type" --argjson expected "$expected" --argjson observed "$actual" '{resolver:$resolver,name:$name,type:$type,expected:$expected,observed:$observed,matches:($observed != null and $observed == $expected)}' >>"$CLAUDIT_OUTPUT_DIRECTORY/claudit-dns-propagation.jsonl"
        done < <(jq -c '.Domain.ExpectedRecords[]?' "$(ca_baseline_path)")
    done < <(jq -c '.Domain.VerificationResolvers[] | {name:.Name,endpoint:.Endpoint,private:.Private,timeout_seconds:.TimeoutSeconds,transport:"dns-over-https",fallback:"disabled"}' "$(ca_baseline_path)")
    if [[ "$(jq '.Domain.VerificationResolvers | length' "$(ca_baseline_path)")" == 0 ]]; then ca_finding CA-DNS-PROPAGATION Domain not_applicable info 'No secondary DNS resolvers configured' 'Add up to two explicit verification resolvers when propagation or split-horizon comparison is required.'
    elif (( total == 0 )); then ca_finding CA-DNS-PROPAGATION Domain not_applicable info 'No desired RRsets for propagation review' 'Declare desired RRsets before comparing resolver propagation.'
    elif (( mismatch > 0 )); then ca_finding CA-DNS-PROPAGATION Domain fail high 'DNS resolver divergence found' "$mismatch of $total secondary-resolver observations differ from desired RRsets; review propagation or split-horizon intent."
    elif (( unavailable > 0 )); then ca_finding CA-DNS-PROPAGATION Domain unknown medium 'DNS propagation evidence incomplete' "$unavailable of $total secondary-resolver observations were unavailable."
    else ca_finding CA-DNS-PROPAGATION Domain pass info 'DNS propagation consistent' "All $total secondary-resolver observations match the desired RRsets."; fi
}
