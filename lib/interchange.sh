#!/usr/bin/env bash

ca_write_interchange() {
    local report="$1" base="$CLAUDIT_OUTPUT_DIRECTORY" run_id result_id plan_id finding_id observation_id oscal_finding_id uuid_map='{}'
    run_id="$(ca_uuid_from_text "$(jq -r .generated_at "$report")|claudit")"
    result_id="$(ca_uuid_from_text "$run_id|result")"
    plan_id="$(ca_uuid_from_text "$run_id|assessment-plan")"
    while IFS= read -r finding_id; do
        observation_id="$(ca_uuid_from_text "$finding_id|observation")"
        oscal_finding_id="$(ca_uuid_from_text "$finding_id|finding")"
        uuid_map="$(jq -cn --argjson current "$uuid_map" --arg id "$finding_id" --arg observation "$observation_id" --arg finding "$oscal_finding_id" '$current + {($id):{observation:$observation,finding:$finding}}')"
    done < <(jq -r '.findings[].finding_id' "$report")
    jq -c --arg version "$CLAUDIT_VERSION" '
      .findings[] | {
        activity_id:1,activity_name:"Create",category_uid:2,category_name:"Findings",
        class_uid:2003,class_name:"Compliance Finding",type_uid:200301,type_name:"Compliance Finding: Create",
        time:(.observed_at | fromdateiso8601 * 1000),
        severity_id:({info:1,low:2,medium:3,high:4,critical:5}[.severity] // 1),
        status:(if .status == "pass" then "Resolved" elif .status == "fail" then "New" else "Other" end),
        message:.detail,
        finding_info:{uid:.finding_id,title:.title,desc:.detail,product:{name:"Claudit",version:$version,vendor_name:"Claudit Project"}},
        compliance:{control:.id,status_code:.status,desc:.detail},metadata:{version:"1.8.0",product:{name:"Claudit",version:$version,vendor_name:"Claudit Project"}}
      }' "$report" > "$base/claudit-ocsf.jsonl"
    jq --arg generated "$(jq -r .generated_at "$report")" --arg version "$CLAUDIT_VERSION" --arg run_id "$run_id" --arg result_id "$result_id" --arg plan_id "$plan_id" --argjson uuids "$uuid_map" '
      {"assessment-results":{
        uuid:$run_id,
        metadata:{title:"Claudit assessment results", "last-modified":$generated,version:$version,"oscal-version":"1.2.3"},
        "import-ap":{href:("urn:uuid:" + $plan_id)},
        results:[{uuid:$result_id,title:"Claudit automated control evaluation",description:"Read-only Claudit control observations for the declared assessment scope.",start:$generated,end:$generated,
          "reviewed-controls":{"control-selections":[{"include-controls":([.findings[].id] | unique | map({"control-id":.}))}]},
          observations:[.findings[] | {uuid:$uuids[.finding_id].observation,title:.title,description:.detail,methods:["TEST"],types:["discovery"],collected:.observed_at,props:[{name:"claudit-status",value:.status},{name:"claudit-finding-id",value:.finding_id}]}],
          findings:[.findings[] | select(.status == "pass" or .status == "fail" or .status == "warning") | {uuid:$uuids[.finding_id].finding,title:.title,description:.detail,props:[{name:"claudit-finding-id",value:.finding_id}],target:{type:"objective-id","target-id":.id,status:{state:(if .status == "pass" then "satisfied" else "not-satisfied" end),reason:(if .status == "pass" then "pass" elif .status == "fail" then "fail" else "other" end)}}}]
        }]
      }}' "$report" > "$base/claudit-oscal-assessment-results.json"
}
