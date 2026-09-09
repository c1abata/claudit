"use strict";

(() => {
    const app = window.claudit;
    const inspector = document.querySelector("#operatorReport");
    let current = null;
    let currentPath = "";
    let localFilter = {};

    const node = (tag, text = "", className = "") => { const element = document.createElement(tag); element.textContent = String(text ?? "—"); if (className) element.className = className; return element; };
    const badge = (value, kind = "status") => node("span", value, `operator-${kind} ${String(value || "unknown").toLowerCase()}`);
    const count = (findings, status) => findings.filter(item => item.status === status).length;

    function matches(finding) {
        const term = (localFilter.term ?? document.querySelector("#reportFilter").value).trim().toLowerCase();
        let status = document.querySelector("#reportStatusFilter").value;
        const severity = document.querySelector("#reportSeverityFilter").value;
        if (localFilter.preset === "confirmed") status = "fail";
        if (localFilter.preset === "warning") status = "warning";
        const gap = localFilter.preset === "gaps";
        return (!term || `${finding.id} ${finding.service} ${finding.category} ${finding.title} ${finding.detail} ${finding.remediation}`.toLowerCase().includes(term)) &&
            (!status || finding.status === status) && (!severity || finding.severity === severity) && (!gap || ["unknown", "error"].includes(finding.status)) &&
            (localFilter.preset !== "confirmed" || ["high", "critical"].includes(finding.severity)) &&
            (!localFilter.category || finding.category === localFilter.category);
    }

    function renderDetail(finding, container) {
        const header = document.createElement("div"); header.className = "finding-detail-head";
        header.append(badge(finding.status), badge(finding.severity, "severity"), node("h4", finding.title || "Untitled control result"));
        const tabs = document.createElement("div"); tabs.className = "detail-tabs";
        const content = document.createElement("div"); content.className = "finding-detail-content";
        const sections = {
            Summary: [node("p", finding.detail || "No observation detail was emitted."), node("p", `Scope: ${finding.service || "unknown"} · ${finding.category || "uncategorized"}`, "muted")],
            Evidence: [node("dl", "", "evidence-list")],
            Control: [node("p", `${finding.id} · catalog level ${finding.catalog_level || finding.control_level || "unknown"}`), node("p", `Finding identity: ${finding.finding_id || "not recorded"}`, "mono"), node("p", `Resource identity: ${finding.resource_uid || "scope-level result"}`, "mono")],
            "Remediation & retest": [node("p", finding.remediation || "No remediation was provided."), node("p", finding.status === "pass" ? "Keep the baseline and repeat the same scope to verify continued operation." : ["unknown", "error"].includes(finding.status) ? "Restore usable collection evidence, then repeat the same scope." : "Apply an approved change outside Claudit, then repeat the same control and scope.", "next-step")],
        };
        const evidence = sections.Evidence[0];
        [["Observed", finding.observed_at], ["Evidence hash", finding.evidence_sha256], ["Control level", finding.control_level], ["Source report", currentPath]].forEach(([key,value]) => { evidence.append(node("dt",key), node("dd",value || "Not recorded")); });
        const show = name => { content.replaceChildren(...sections[name]); tabs.querySelectorAll("button").forEach(button => button.setAttribute("aria-selected", String(button.textContent === name))); };
        Object.keys(sections).forEach((name,index) => { const button=node("button",name); button.type="button"; button.setAttribute("aria-selected",String(index===0)); button.addEventListener("click",()=>show(name)); tabs.append(button); });
        show("Summary"); container.replaceChildren(header,tabs,content);
    }

    function render() {
        if (!current) return;
        const findings = Array.isArray(current.findings) ? current.findings : [];
        const statusRank = {fail:0,error:1,warning:2,unknown:3,pass:4,info:5,not_applicable:6};
        const severityRank = {critical:0,high:1,medium:2,low:3,info:4};
        const visible = findings.filter(matches).sort((left,right)=>(statusRank[left.status]??9)-(statusRank[right.status]??9)||(severityRank[left.severity]??9)-(severityRank[right.severity]??9)||String(left.id).localeCompare(String(right.id)));
        const summary = document.createElement("div"); summary.className = "operator-summary";
        const assetValue=current.scope?.domain || current.scope?.vps || current.scope?.aws_profile || current.scope?.azure_subscription || current.scope?.gcp_project || "Provider scope"; const asset=app.state.assetHistory.find(item=>item.value===String(assetValue).toLowerCase().replace(/\.$/,""));
        const title = document.createElement("div"); title.append(node("p", "Selected assessment", "eyebrow"), node("h3", `${current.scope?.level || "Assessment"} · ${assetValue}`), node("p", `Observed ${window.claudit ? new Date(current.generated_at).toLocaleString() : current.generated_at} · ${visible.length} of ${findings.length} controls shown${asset ? ` · ${asset.assessmentCount} assessments in asset history` : ""}`, "muted"));
        const exports = document.createElement("div"); exports.className = "report-exports";
        const report = app.state.reports.find(item => item.RelativePath === currentPath);
        for (const [label,path] of Object.entries(report?.Artifacts || {JSON:currentPath})) { const link=node("a",label); link.href=`/api/report?path=${encodeURIComponent(path)}`; link.target="_blank"; link.rel="noopener"; exports.append(link); }
        const remove=node("button","Delete report","danger-link"); remove.type="button"; remove.addEventListener("click",async()=>{if(!confirm("Delete this complete report run from local storage?"))return;remove.disabled=true;try{await app.api(`/api/report?path=${encodeURIComponent(currentPath)}`,{method:"DELETE"});current=null;currentPath="";inspector.replaceChildren(node("div","Report deleted. Select another assessment.","empty-state compact"));await app.refresh();}catch(error){remove.disabled=false;app.showToast(error.message,"error");}});exports.append(remove);
        summary.append(title,exports);
        const metrics=document.createElement("div"); metrics.className="operator-metrics";
        const assessed=findings.filter(item=>["pass","fail","warning"].includes(item.status)).length; const applicable=assessed+count(findings,"unknown")+count(findings,"error");
        [["Coverage",applicable?`${(100*assessed/applicable).toFixed(1)}%`:"—"],["Failed",count(findings,"fail")],["Warnings",count(findings,"warning")],["Evidence gaps",count(findings,"unknown")+count(findings,"error")],["Not applicable",count(findings,"not_applicable")]].forEach(([label,value])=>{const metric=document.createElement("div");metric.append(node("strong",value),node("span",label));metrics.append(metric);});
        const split=document.createElement("div");split.className="findings-split";const list=document.createElement("div");list.className="findings-list";const detail=document.createElement("article");detail.className="finding-detail";
        if(!visible.length){list.append(node("div","No control results match the selected filters.","empty-state compact"));detail.append(node("p","Reset or change the filters to inspect evidence.","muted"));}
        else visible.forEach((finding,index)=>{const button=document.createElement("button");button.type="button";button.className="finding-row";button.append(badge(finding.status),badge(finding.severity,"severity"),node("span",finding.title),node("small",`${finding.service} · ${finding.id}${finding._change && finding._change!=="Unchanged" ? ` · ${finding._change}` : ""}`));button.addEventListener("click",()=>{list.querySelectorAll("button").forEach(item=>item.classList.remove("selected"));button.classList.add("selected");renderDetail(finding,detail);});list.append(button);if(index===0){button.classList.add("selected");renderDetail(finding,detail);}});
        split.append(list,detail);inspector.replaceChildren(summary,metrics,split);
    }

    async function load(path, filter = {}) {
        currentPath=path;localFilter=filter;
        if(filter.term)document.querySelector("#reportFilter").value=filter.term;
        if(filter.preset==="confirmed")document.querySelector("#reportStatusFilter").value="fail";
        else if(filter.preset==="warning")document.querySelector("#reportStatusFilter").value="warning";
        else if(filter.preset==="gaps")document.querySelector("#reportStatusFilter").value="";
        inspector.replaceChildren(node("div","Loading assessment evidence…","empty-state compact"));
        try{current=await app.api(`/api/report?path=${encodeURIComponent(path)}`);const comparison=await app.compareReport(path,current).catch(()=>({changes:new Map()}));for(const finding of current.findings||[]){finding._change=comparison.changes.get(finding.finding_id||`${finding.service}|${finding.id}`);}render();}
        catch(error){current=null;inspector.replaceChildren(node("div",`Assessment evidence is unavailable: ${error.message}`,"empty-state compact error"));}
    }

    document.addEventListener("claudit:open-report",event=>load(event.detail.path,event.detail.filter));
    document.addEventListener("claudit:result-filter",()=>{localFilter={};render();});
    const parameter=new URLSearchParams(location.search).get("report");if(parameter){app.selectTab("results");load(parameter);}
})();
