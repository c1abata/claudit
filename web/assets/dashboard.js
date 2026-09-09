"use strict";

const state = {
    services: [], authCatalog: [], controlCatalog: [], baselineCapabilities: [], dnsResolver: null,
    reports: [], operations: [], overview: {}, reportTotal: 0, selectedOperation: "", selectedReport: "",
    reportCache: new Map(), wizardStep: 1, serviceSignature: "", refreshPending: null, draftRequestId: "",
};

const requestToken = document.body.dataset.requestToken || "";
const qs = (selector, root = document) => root.querySelector(selector);
const qsa = (selector, root = document) => Array.from(root.querySelectorAll(selector));
const providerIcons = {
    Microsoft365: "/assets/icons/cloud/icons8-azure-1-50.png", Azure: "/assets/icons/cloud/icons8-azure-50.png",
    AWS: "/assets/icons/cloud/icons8-amazon-aws-50.png", GCP: "/assets/icons/cloud/icons8-google-cloud-50.png",
    Internet: "/assets/icons/cloud/icons8-cloudflare-50.png", MultiCloud: "/assets/icons/cloud/icons8-cloud-50.png",
    SaaS: "/assets/icons/cloud/icons8-cloud-50.png", VPS: "/assets/icons/cloud/icons8-cloud-50.png",
};

function element(tag, options = {}, children = []) {
    const node = document.createElement(tag);
    if (options.className) node.className = options.className;
    if (options.text !== undefined) node.textContent = String(options.text);
    for (const [name, value] of Object.entries(options.attrs || {})) if (value !== null && value !== undefined) node.setAttribute(name, String(value));
    for (const child of children) if (child !== null && child !== undefined) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    return node;
}
function replaceChildren(target, children) { target.replaceChildren(...children); }
function localTime(value) { const date = new Date(value); return value && !Number.isNaN(date.getTime()) ? date.toLocaleString() : "—"; }
function pill(value, extra = "") { const label = String(value || "Info"); return element("span", {className: `pill ${label.toLowerCase().replace(/[^a-z0-9_-]/g, "")} ${extra}`, text: label}); }
function showToast(message, tone = "info") { const toast = element("div", {className: `toast ${tone}`, text: message, attrs: {role: tone === "error" ? "alert" : "status"}}); qs("#toastRegion").append(toast); setTimeout(() => toast.remove(), 5000); }
function setConnection(connected, detail = "") { qs("#connectionState").dataset.state = connected ? "online" : "offline"; qs("#serverState").textContent = connected ? "Connected" : "Disconnected"; qs("#connectionState").title = detail; }
function targetOf(reportOrOperation) { const operation = reportOrOperation.Operation || reportOrOperation; return operation.Target || operation.Domain || operation.Scope?.domain || operation.Scope?.vpsTarget || operation.Scope?.awsProfile || operation.Scope?.azureSubscription || operation.Scope?.gcpProject || "Provider scope"; }
function selectedServices() { return qsa(".service-checkbox:checked").map(input => input.value); }
function selectedSpecs() { const selected = new Set(selectedServices()); return state.services.filter(service => selected.has(service.Name)); }
function hasProvider(provider) { return selectedSpecs().some(service => service.Provider === provider); }
function hasService(name) { return selectedServices().includes(name); }

async function api(path, options = {}) {
    const response = await fetch(path, {...options, headers: {...(options.headers || {}), "x-claudit-token": requestToken}, cache: options.cache || "no-store"});
    const body = await response.text();
    if (!response.ok) { let message = body || `Request failed (${response.status})`; try { message = JSON.parse(body).error || message; } catch {} throw new Error(message); }
    return body ? JSON.parse(body) : null;
}

function activeProfile() { return qs("input[name='profile']:checked")?.value || "domain"; }
function applyProfile(profile = activeProfile()) {
    const map = {domain: ["Domain"], vps: ["VPS"], cloud: ["AWS"], advanced: [], preflight: ["Runtime"]};
    const cloudServices = new Set(["Entra", "Exchange", "SharePoint", "OneDrive", "Azure", "AWS", "GCP", "Tailscale", "Inventory"]);
    const chosen = new Set(map[profile] || []);
    qsa(".service-checkbox").forEach(input => { input.checked = chosen.has(input.value); input.disabled = profile === "preflight" || (profile === "domain" && input.value !== "Domain") || (profile === "vps" && input.value !== "VPS") || (profile === "cloud" && !cloudServices.has(input.value)); });
    qs("#opMode").value = profile === "preflight" ? "preflight" : "audit";
    if (profile === "preflight") qs("#controlLevel").value = "Formal";
    if (profile === "domain" && qs("#controlLevel").value === "Formal") qs("#controlLevel").value = "Passive";
    refreshWizard();
}

function renderServices() {
    const previous = new Set(selectedServices());
    replaceChildren(qs("#serviceList"), state.services.filter(service => service.Name !== "Runtime").map((service, index) => {
        const input = element("input", {className: "service-checkbox", attrs: {id: `service-${index}`, type: "checkbox", value: service.Name}});
        input.checked = previous.size ? previous.has(service.Name) : service.Name === "Domain";
        input.addEventListener("change", refreshWizard);
        return element("label", {className: "service-option", attrs: {for: input.id}}, [input, element("img", {className: "service-icon", attrs: {src: providerIcons[service.Provider] || providerIcons.MultiCloud, alt: "", width: 22, height: 22}}), element("span", {className: "service-name", text: service.Name}), element("span", {className: "service-provider", text: service.Provider})]);
    }));
    applyProfile();
}

function setGroup(name, visible) { qsa(`.${name}`).forEach(node => { node.hidden = !visible; }); }
function authMethod(provider) {
    if (provider === "Microsoft365") return qs("#authMode").value === "AppOnly" ? "AppCertificate" : (qs("#graphAuthMode").value === "Browser" ? "DelegatedBrowser" : "DelegatedDeviceCode");
    return {Azure: "AzCli", AWS: "AwsCliProfile", GCP: "Gcloud", SaaS: "ApiTokenEnv", VPS: "LocalOrSsh", Internet: "Public"}[provider] || "ExistingProviderContexts";
}
function renderAuthPlan() {
    const plan = [];
    for (const provider of [...new Set(selectedSpecs().map(item => item.Provider))]) {
        const method = authMethod(provider); const catalog = state.authCatalog.find(item => item.Provider === provider && item.Method === method);
        plan.push(element("div", {className: "auth-gate"}, [element("strong", {text: `${provider} · ${method}`}), element("p", {text: catalog?.Description || "Use the existing read-only provider context."}), pill(provider === "Internet" ? "Public evidence" : "Access checked at run time") ]));
    }
    replaceChildren(qs("#authPlan"), plan.length ? plan : [element("div", {className: "callout", text: "This preflight uses local prerequisites only; it does not analyze an asset."})]);
}
function plannedControls() {
    const services = new Set(selectedServices()); const level = qs("#controlLevel").value;
    const rank = {Formal: 0, Passive: 1, Active: 2};
    return state.controlCatalog.filter(control => (services.has(control.Service) || (activeProfile() === "preflight" && control.Service === "Runtime")) && rank[control.Level] <= rank[level]);
}
function renderReview() {
    const request = operationRequest(); const controls = plannedControls();
    const preflight = request.mode === "preflight";
    const rows = [
        ["Objective", qsa("input[name='profile']:checked")[0]?.closest("label")?.querySelector("strong")?.textContent || "Assessment"],
        ["Target", preflight ? "Local engine" : request.domain || request.vpsTarget || request.awsProfile || request.azureSubscription || request.gcpProject || "Provider scope"],
        ["Collection", request.mode === "preflight" ? "Preflight — no asset analysis" : request.controlLevel],
        ["Surface", preflight ? "Runtime" : request.service.join(", ") || "Provider scope"], ["Planned controls", String(controls.length)],
        ["Evidence", request.format === "All" ? "All report formats" : request.format],
    ];
    replaceChildren(qs("#operationReview"), rows.map(([label, value]) => element("div", {}, [element("span", {text: label}), element("strong", {text: value})])));
}
function refreshWizard() {
    const profile = activeProfile(); const preflight = profile === "preflight"; const active = !preflight && qs("#controlLevel").value === "Active";
    qs("#advancedScope").hidden = preflight;
    qs("#serviceList").hidden = preflight;
    qs("#confirmTenantConnection").closest("label").hidden = preflight;
    qs("#authenticationDetails").hidden = preflight;
    setGroup("domain", hasService("Domain")); setGroup("vps", hasService("VPS")); setGroup("aws", hasProvider("AWS")); setGroup("azure", hasProvider("Azure")); setGroup("gcp", hasProvider("GCP")); setGroup("tailscale", hasService("Tailscale")); setGroup("m365", hasProvider("Microsoft365")); setGroup("delegated", hasProvider("Microsoft365") && qs("#authMode").value !== "AppOnly"); setGroup("active", active);
    qs("#controlLevel").disabled = preflight;
    const controls = plannedControls(); qs("#controlCount").textContent = `${controls.length} controls planned`;
    qs("#planLimitations").textContent = preflight ? "Preflight verifies the local engine only and never appears as a security posture assessment." : active ? "Active adds only catalogued Domain/VPS probes for declared targets. It does not make an assessment comprehensive by itself." : "The plan includes only catalogued controls available for the selected services and level.";
    renderAuthPlan(); renderReview();
    document.dispatchEvent(new CustomEvent("claudit:draft-changed"));
}

function operationRequest() {
    const mode = qs("#opMode").value;
    return {mode, requestId: state.draftRequestId || `web-${crypto.randomUUID()}`, title: mode === "preflight" ? "Engine preflight" : `${activeProfile()} · ${qs("#domain").value || qs("#vpsTarget").value || "provider scope"}`, controlLevel: mode === "preflight" ? "Formal" : qs("#controlLevel").value,
        confirmTenantConnection: qs("#confirmTenantConnection").checked, confirmActiveProbes: qs("#confirmActiveProbes").checked,
        service: mode === "preflight" ? [state.services[0]?.Name || "Entra"] : selectedServices(), format: qs("#format").value,
        tenantName: qs("#tenantName").value, environment: qs("#environment").value, authMode: qs("#authMode").value, graphAuthMode: qs("#graphAuthMode").value,
        tenantId: qs("#tenantId").value, clientId: qs("#clientId").value, certificateThumbprint: qs("#certificateThumbprint").value, organization: qs("#organization").value,
        runPester: false, azureSubscription: qs("#azureSubscription").value, azureTenant: qs("#azureTenant").value, awsProfile: qs("#awsProfile").value, awsRegion: qs("#awsRegion").value,
        gcpProject: qs("#gcpProject").value, gcpAccount: qs("#gcpAccount").value, gcpOrganization: qs("#gcpOrganization").value,
        tailscaleTailnet: qs("#tailscaleTailnet").value, tailscaleApiTokenEnv: qs("#tailscaleApiTokenEnv").value, tailscaleAuthScheme: qs("#tailscaleAuthScheme").value,
        domain: qs("#domain").value.trim().toLowerCase().replace(/\.$/, ""), domainSubdomain: qs("#domainSubdomain").value,
        vpsTarget: qs("#vpsTarget").value, vpsSshUser: qs("#vpsSshUser").value, vpsSshPort: qs("#vpsSshPort").value, vpsAllowedPublicPort: qs("#vpsAllowedPublicPort").value,
    };
}

function validateStep(step) {
    const request = operationRequest();
    if (step === 2 && request.mode !== "preflight") {
        if (!request.service.length) throw new Error("Select at least one audit service.");
        if (request.service.includes("Domain") && !request.domain) throw new Error("Enter the authorized root domain.");
        if (request.service.includes("VPS") && !request.vpsTarget) throw new Error("Enter the authorized VPS target.");
    }
    if (step === 4 && request.mode !== "preflight" && ["Passive", "Active"].includes(request.controlLevel) && !request.confirmTenantConnection) throw new Error("Authorize the declared read-only DNS/provider connections.");
    if (step === 4 && request.controlLevel === "Active" && !request.confirmActiveProbes) throw new Error("Authorize the bounded active probes.");
}
function setWizardStep(next) {
    state.wizardStep = Math.max(1, Math.min(5, next));
    qsa(".wizard-step").forEach(node => { node.hidden = Number(node.dataset.step) !== state.wizardStep; });
    qsa("[data-step-indicator]").forEach(node => { node.toggleAttribute("aria-current", Number(node.dataset.stepIndicator) === state.wizardStep); node.classList.toggle("complete", Number(node.dataset.stepIndicator) < state.wizardStep); });
    qs("#wizardBack").hidden = state.wizardStep === 1; qs("#wizardNext").hidden = state.wizardStep === 5; qs("#startOp").hidden = state.wizardStep !== 5;
    qs("#wizardTitle").textContent = ["Choose the assessment objective", "Declare the authorized scope", "Review available controls", "Confirm access and authorization", "Review the executable plan"][state.wizardStep - 1];
    qs("#wizardStatus").textContent = ""; renderReview(); qs(".wizard-content").scrollTop = 0;
}
function openWizard() { state.draftRequestId = `web-${crypto.randomUUID()}`; selectTab("operations"); qs("#operationWizard").hidden = false; qs("#newOperation").setAttribute("aria-expanded", "true"); setWizardStep(1); qs("#operationWizard").scrollIntoView({block: "start"}); }
function closeWizard() { qs("#operationWizard").hidden = true; qs("#newOperation").setAttribute("aria-expanded", "false"); qs("#newOperation").focus(); }

async function startOperation() {
    validateStep(4); const body = operationRequest(); const button = qs("#startOp"); button.disabled = true; button.textContent = "Starting…";
    try { const operation = await api("/api/operations", {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify(body)}); state.draftRequestId = ""; closeWizard(); await refresh(); await selectOperation(operation.Id); showToast("Operation started. Progress is available in Operations."); }
    finally { button.disabled = false; button.textContent = "Start operation"; }
}

function assessmentReports() { const scope = qs("#scopeFilter").value; return state.reports.filter(report => ["passive", "active"].includes(report.Operation?.Command) && (!scope || targetOf(report) === scope)); }
async function reportData(report) { if (!report) return null; if (!state.reportCache.has(report.RelativePath)) state.reportCache.set(report.RelativePath, api(`/api/report?path=${encodeURIComponent(report.RelativePath)}`)); return state.reportCache.get(report.RelativePath); }
async function compareReport(path, currentDocument) {
    const reports = assessmentReports(); const index = reports.findIndex(item => item.RelativePath === path); const currentReport = reports[index];
    if (!currentReport || index < 0) return {comparable:false, reason:"Assessment is outside the selected scope.", changes:new Map()};
    const previous = reports.slice(index + 1).find(item => targetOf(item) === targetOf(currentReport) && JSON.stringify(item.Operation?.Services || []) === JSON.stringify(currentReport.Operation?.Services || []));
    if (!previous) return {comparable:false, reason:"No earlier assessment with the same target and services.", changes:new Map()};
    const previousDocument = await reportData(previous); const before = new Map((previousDocument.findings || []).map(item => [item.finding_id || `${item.service}|${item.id}`, item])); const changes = new Map();
    for (const finding of currentDocument.findings || []) { const key=finding.finding_id || `${finding.service}|${finding.id}`; const old=before.get(key); let change="Unchanged"; if(!old)change="New";else if(old.status==="fail"&&finding.status==="pass")change="Fixed";else if(old.status!=="fail"&&finding.status==="fail")change="Regressed";else if(old.status!==finding.status)change="Changed";else if(old.evidence_sha256&&finding.evidence_sha256&&old.evidence_sha256!==finding.evidence_sha256)change="EvidenceChanged";changes.set(key,change);before.delete(key); }
    for (const [key] of before) changes.set(key,"Removed");
    return {comparable:true, previous, changes};
}
function outcomeSummary(findings) {
    const count = key => findings.filter(finding => finding.status === key).length;
    const assessed = findings.filter(finding => ["pass", "fail", "warning"].includes(finding.status)).length;
    const applicable = assessed + count("unknown") + count("error");
    return {confirmed: findings.filter(finding => finding.status === "fail" && ["high", "critical"].includes(finding.severity)).length, warning: count("warning"), gaps: count("unknown") + count("error"), coverage: applicable ? 100 * assessed / applicable : 0, assessed, applicable};
}
async function renderOverview() {
    const report = assessmentReports()[0]; const empty = !report; qs("#overviewEmpty").hidden = !empty; qs("#overviewPanels").hidden = empty;
    if (!report) { ["#mConfirmed", "#mWarnings", "#mCoverage", "#mGaps", "#mChanges"].forEach(selector => qs(selector).textContent = "—"); qs("#overviewContext").textContent = "No valid assessment is available for the selected scope."; return; }
    let documentData;
    try { documentData = await reportData(report); } catch (error) { qs("#overviewPanels").hidden = true; qs("#overviewEmpty").hidden = false; qs("#overviewEmpty h3").textContent = "Assessment evidence is unreadable"; qs("#overviewEmpty p").textContent = error.message; return; }
    const findings = Array.isArray(documentData.findings) ? documentData.findings : []; const summary = outcomeSummary(findings); const scopeReports = assessmentReports(); const comparison = await compareReport(report.RelativePath, documentData).catch(() => ({comparable:false,changes:new Map()}));
    qs("#mConfirmed").textContent = summary.confirmed; qs("#mWarnings").textContent = summary.warning; qs("#mCoverage").textContent = `${summary.coverage.toFixed(1)}%`; qs("#mGaps").textContent = summary.gaps; qs("#mChanges").textContent = comparison.comparable ? [...comparison.changes.values()].filter(value => !["Unchanged","EvidenceChanged"].includes(value)).length : "No baseline";
    qs("#overviewContext").textContent = `${report.Summary?.Assessment || "Assessment"} · ${targetOf(report)} · observed ${localTime(documentData.generated_at || report.LastWriteUtc)}`;
    const priority = {critical: 0, high: 1, medium: 2, low: 3, info: 4}; const salient = findings.filter(f => ["fail", "warning", "error"].includes(f.status)).sort((a,b) => (priority[a.severity] ?? 9) - (priority[b.severity] ?? 9)).slice(0,5);
    replaceChildren(qs("#riskList"), salient.length ? salient.map(finding => { const button = element("button", {className: "risk-row", attrs: {type: "button"}}, [pill(finding.status), pill(finding.severity, "severity"), element("span", {}, [element("strong", {text: finding.title}), element("small", {text: `${finding.category || "other"} · ${finding.id}`})])]); button.addEventListener("click", () => openReport(report.RelativePath, {term: finding.id})); return button; }) : [element("div", {className: "positive-state", text: "No failed, warning or error results in this assessment."})]);
    const matrix = new Map(); findings.forEach(f => { const key = f.category || "other"; const row = matrix.get(key) || {pass:0,fail:0,warning:0,unknown:0,error:0}; if (row[f.status] !== undefined) row[f.status]++; matrix.set(key,row); });
    const matrixItems = [...matrix].slice(0,7);
    replaceChildren(qs("#controlMatrix"), [element("div", {className:"matrix-head"}, [element("span", {text:"Family"}), ...["Fail","Warn","?","Err","Pass"].map(label => element("span", {text:label}))]), ...matrixItems.map(([category, counts]) => element("button", {className: "matrix-row", attrs: {type:"button"}}, [element("strong", {text: category}), ...["fail","warning","unknown","error","pass"].map(status => element("span", {className: status, text: counts[status] || "·", attrs: {title: status}}))]))]);
    replaceChildren(qs("#assessmentHistory"), scopeReports.slice(0,6).reverse().map(item => { const total = Math.max(1, (item.Summary?.Pass || 0)+(item.Summary?.Problems || 0)+(item.Summary?.NotEvaluated || 0)); const height = Math.max(8, Math.round(100*(item.Summary?.Problems || 0)/total)); return element("button", {className:"history-point", attrs:{type:"button",title:`${localTime(item.LastWriteUtc)} · ${item.Summary?.Problems || 0} problems`}}, [element("i", {attrs:{style:`height:${height}%`}}), element("span", {text:new Date(item.LastWriteUtc).toLocaleDateString(undefined,{month:"short",day:"numeric"})})]); }));
    replaceChildren(qs("#evidenceQuality"), [element("div", {className:"quality-score"}, [element("strong", {text:`${summary.assessed}/${summary.applicable}`}), element("span", {text:"applicable results assessed"})]), element("p", {text: summary.gaps ? `${summary.gaps} controls lack usable evidence. Resolve collection or access gaps before treating posture as complete.` : "No unknown or error results in this assessment. Scope limitations still apply."}), element("button", {className:"quiet", text:"Inspect evidence gaps", attrs:{type:"button","data-result-preset":"gaps"}})]);
    qsa("#controlMatrix button").forEach((button,index) => button.addEventListener("click", () => openReport(report.RelativePath,{category:matrixItems[index][0]})));
    qs("#evidenceQuality button")?.addEventListener("click", () => openReport(report.RelativePath,{preset:"gaps"}));
}

function renderScopeFilter() { const select = qs("#scopeFilter"), previous = select.value; const scopes = [...new Set(state.reports.filter(r => ["passive","active"].includes(r.Operation?.Command)).map(targetOf))]; replaceChildren(select,[new Option("All scopes",""),...scopes.map(scope => new Option(scope,scope))]); if (scopes.includes(previous)) select.value=previous; }
function renderOperations() {
    const filter = qs("#operationStatusFilter").value; const operations = state.operations.filter(op => !filter || op.Status === filter); qs("#operationCount").textContent = `${operations.length} of ${state.operations.length} operations`;
    if (!operations.length) { replaceChildren(qs("#operationsBody"), [element("tr", {}, [element("td", {className:"empty-cell",text:"No operations match this view.",attrs:{colspan:5}})])]); return; }
    replaceChildren(qs("#operationsBody"), operations.map(operation => { const row=element("tr", {className:operation.Id===state.selectedOperation?"selected":"",attrs:{tabindex:"0"}}, [element("td",{},[element("strong",{text:operation.Title || `${operation.Command} assessment`}),element("small",{text:operation.Id})]),element("td",{text:targetOf(operation)}),element("td",{text:operation.EffectiveControlLevel || operation.ControlLevel}),element("td",{},[pill(operation.Status)]),element("td",{text:localTime(operation.StartedUtc)})]); row.addEventListener("click",()=>selectOperation(operation.Id)); row.addEventListener("keydown",event=>{if(event.key==="Enter")selectOperation(operation.Id);}); return row; }));
    const running=state.operations.filter(op=>op.Status==="Running").length; qs("#runningBadge").hidden=!running; qs("#runningBadge").textContent=running;
}
async function selectOperation(id) {
    state.selectedOperation=id; renderOperations(); const operation=state.operations.find(item=>item.Id===id); if(!operation)return;
    qs("#logTitle").textContent=`${operation.Title || operation.Command} · ${targetOf(operation)}`; qs("#latestRun").textContent=operation.Id; qs("#latestStatus").textContent=operation.Status; qs("#latestEvidence").textContent=operation.EvidenceStatus || "unknown"; qs("#operationMeta").textContent=`Output: ${operation.OutputDirectory || "not recorded"}${operation.ExitCode === null || operation.ExitCode === undefined ? "" : ` · exit code ${operation.ExitCode}`}`; qs("#logPane").textContent="Loading operation output…";
    try { const data=await api(`/api/operations/log?id=${encodeURIComponent(id)}`); qs("#logPane").textContent=`${data.stdout || ""}${data.stderr ? `\n\n[stderr]\n${data.stderr}` : ""}` || "No log output yet."; } catch(error){qs("#logPane").textContent=error.message;}
    const report=state.reports.find(item=>item.Operation?.Id===id); const actions=[]; if(report){const button=element("button",{className:"primary",text:"Open assessment results",attrs:{type:"button"}});button.addEventListener("click",()=>openReport(report.RelativePath));actions.push(button);} replaceChildren(qs("#operationResultAction"),actions);
}
function renderReports() {
    const term=qs("#reportFilter").value.trim().toLowerCase(); const reports=assessmentReports().filter(report=>`${targetOf(report)} ${(report.Operation?.Services||[]).join(" ")} ${report.Summary?.Assessment||""}`.toLowerCase().includes(term)); qs("#reportCount").textContent=`${reports.length} assessments shown · ${state.reportTotal} report files retained`;
    replaceChildren(qs("#reportsBody"),reports.length?reports.map(report=>{const row=element("tr",{className:report.RelativePath===state.selectedReport?"selected":"",attrs:{tabindex:"0"}},[element("td",{},[element("strong",{text:report.Summary?.Assessment||"Assessment"}),element("small",{text:(report.Operation?.Services||[]).join(", ")})]),element("td",{text:targetOf(report)}),element("td",{text:`${report.Summary?.Coverage ?? "—"}%`}),element("td",{text:localTime(report.LastWriteUtc)})]);row.addEventListener("click",()=>openReport(report.RelativePath));row.addEventListener("keydown",e=>{if(e.key==="Enter")openReport(report.RelativePath);});return row;}):[element("tr",{},[element("td",{className:"empty-cell",text:"No passive or active assessments match this view.",attrs:{colspan:4}})])]);
}
function selectTab(id, updateHash=true) { qsa("[role='tab']").forEach(button=>{const selected=button.dataset.tab===id;button.setAttribute("aria-selected",String(selected));button.tabIndex=selected?0:-1;});qsa(".tab").forEach(panel=>{panel.hidden=panel.id!==id;});if(updateHash)history.replaceState(null,"",`#${id}`); }
function openReport(path, filter={}) { selectTab("results"); state.selectedReport=path; renderReports(); document.dispatchEvent(new CustomEvent("claudit:open-report",{detail:{path,filter}})); }

async function refresh() {
    if(state.refreshPending)return state.refreshPending;
    state.refreshPending=(async()=>{try{const snapshot=await api("/api/state");const reports=snapshot.reports||[];while(reports.length<(snapshot.reportTotal||0)){const page=await api(`/api/reports?offset=${reports.length}&limit=500`);if(!page.length)break;reports.push(...page);}Object.assign(state,{services:snapshot.services||[],authCatalog:snapshot.authCatalog||[],controlCatalog:snapshot.controlCatalog||[],baselineCapabilities:snapshot.baselineCapabilities||[],dnsResolver:snapshot.dnsResolver||null,reports,operations:snapshot.operations||[],overview:snapshot.overview||{},reportTotal:snapshot.reportTotal||0});const signature=state.services.map(s=>`${s.Name}:${s.Provider}`).join("|");if(signature!==state.serviceSignature){state.serviceSignature=signature;renderServices();}if(document.activeElement!==qs("#retentionCount"))qs("#retentionCount").value=snapshot.retentionCount||100;renderScopeFilter();renderOperations();renderReports();await renderOverview();qs("#contextFreshness").textContent=`Updated ${new Date().toLocaleTimeString()} · ${assessmentReports().length} assessments`;document.dispatchEvent(new CustomEvent("claudit:state-refreshed",{detail:snapshot}));setConnection(true);}catch(error){setConnection(false,error.message);throw error;}finally{state.refreshPending=null;}})();return state.refreshPending;
}

function bindEvents() {
    qsa("[role='tab']").forEach(button=>{button.addEventListener("click",()=>selectTab(button.dataset.tab));button.addEventListener("keydown",event=>{if(!["ArrowLeft","ArrowRight"].includes(event.key))return;const tabs=qsa("[role='tab']"),next=tabs[(tabs.indexOf(button)+(event.key==="ArrowRight"?1:-1)+tabs.length)%tabs.length];event.preventDefault();selectTab(next.dataset.tab);next.focus();});});
    ["#overviewNewOperation","#emptyNewOperation","#newOperation"].forEach(selector=>qs(selector).addEventListener("click",openWizard)); qs("#closeWizard").addEventListener("click",closeWizard);
    qsa("input[name='profile']").forEach(input=>input.addEventListener("change",()=>applyProfile(input.value)));qsa("#operationWizard input, #operationWizard select").forEach(input=>input.addEventListener("change",refreshWizard));
    qs("#wizardNext").addEventListener("click",()=>{try{validateStep(state.wizardStep);setWizardStep(state.wizardStep+1);}catch(error){qs("#wizardStatus").textContent=error.message;}});qs("#wizardBack").addEventListener("click",()=>setWizardStep(state.wizardStep-1));qs("#startOp").addEventListener("click",()=>startOperation().catch(error=>{qs("#wizardStatus").textContent=error.message;showToast(error.message,"error");}));
    qs("#operationStatusFilter").addEventListener("change",renderOperations);["#reportFilter","#reportStatusFilter","#reportSeverityFilter"].forEach(selector=>qs(selector).addEventListener("input",()=>{renderReports();document.dispatchEvent(new CustomEvent("claudit:result-filter"));}));qs("#scopeFilter").addEventListener("change",()=>{renderReports();renderOverview();});
    qs("#refreshAll").addEventListener("click",()=>refresh().catch(error=>showToast(error.message,"error")));qs("#reloadReports").addEventListener("click",()=>refresh().catch(error=>showToast(error.message,"error")));
    qs("#openLatestReport").addEventListener("click",()=>{const report=assessmentReports()[0];if(report)openReport(report.RelativePath);});qsa("[data-result-preset]").forEach(button=>button.addEventListener("click",()=>{const report=assessmentReports()[0];if(report)openReport(report.RelativePath,{preset:button.dataset.resultPreset});}));
    qs("#openSettings").addEventListener("click",()=>qs("#settingsDialog").showModal());qs("#closeSettings").addEventListener("click",()=>qs("#settingsDialog").close());qs("#saveRetention").addEventListener("click",async()=>{try{await api("/api/settings",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({retentionCount:Number(qs("#retentionCount").value)})});qs("#settingsDialog").close();showToast("Retention setting saved.");await refresh();}catch(error){showToast(error.message,"error");}});
    document.addEventListener("claudit:session-selected",event=>{const scope=event.detail?.scope||{};const target=scope.domain||scope.vpsTarget||scope.awsProfile||scope.azureSubscription||scope.gcpProject||"";if([...qs("#scopeFilter").options].some(option=>option.value===target))qs("#scopeFilter").value=target;renderReports();renderOverview();});
}

window.claudit={state,api,refresh,openReport,openWizard,operationRequest,selectTab,showToast,renderOverview,compareReport};
bindEvents();const initial=location.hash.slice(1);if(["overview","operations","results"].includes(initial))selectTab(initial,false);refresh().catch(error=>showToast(error.message,"error"));
function scheduleRefresh() { setTimeout(async () => { if (!document.hidden) await refresh().catch(() => {}); scheduleRefresh(); }, state.operations.some(op => op.Status === "Running") ? 5000 : 30000); }
scheduleRefresh();
