#!/usr/bin/env bash

ca_write_interchange() {
    local report="$1" base="$CLAUDIT_OUTPUT_DIRECTORY" run_id
    run_id="$(ca_uuid_from_text "$(jq -r .generated_at "$report")|claudit")"
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
    jq --arg generated "$(jq -r .generated_at "$report")" --arg version "$CLAUDIT_VERSION" --arg run_id "$run_id" '
      {"assessment-results":{
        uuid:$run_id,
        metadata:{title:"Claudit assessment results", "last-modified":$generated,version:$version,"oscal-version":"1.2.1"},
        results:[{title:"Claudit automated control evaluation",start:$generated,end:$generated,
          observations:[.findings[] | {uuid:(.finding_id[0:8] + "-" + .finding_id[8:12] + "-" + .finding_id[12:16] + "-" + .finding_id[16:20] + "-" + .finding_id[20:32]),title:.title,description:.detail,methods:["TEST"],types:["discovery"],collected:.observed_at}],
          findings:[.findings[] | {uuid:(.finding_id[32:40] + "-" + .finding_id[40:44] + "-" + .finding_id[44:48] + "-" + .finding_id[48:52] + "-" + .finding_id[52:64]),title:.title,description:.detail,props:[{name:"claudit-finding-id",value:.finding_id}],target:{type:"objective-id","target-id":.id,status:{state:(if .status == "pass" then "satisfied" else "not-satisfied" end),reason:.status}}}]
        }]
      }}' "$report" > "$base/claudit-oscal-assessment-results.json"
}
