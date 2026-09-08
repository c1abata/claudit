"use strict";

(() => {
    const parameter = new URLSearchParams(window.location.search).get("report");
    const reportsTab = document.querySelector("#tab-reports");
    const reportsBody = document.querySelector("#reportsBody");
    if (!reportsTab || !reportsBody) return;

    const inspector = document.createElement("section");
    inspector.id = "operatorReport";
    inspector.className = "operator-report";
    inspector.hidden = true;
    document.querySelector("#reports .panel-body").append(inspector);
    const overviewContent = document.querySelector("#resultsOverviewContent");
    const latestButton = document.querySelector("#openLatestReport");

    const text = (tag, value, className = "") => {
        const node = document.createElement(tag);
        node.textContent = String(value ?? "—");
        if (className) node.className = className;
        return node;
    };
    const status = (finding) => text("span", finding.status, `operator-status ${finding.status || "unknown"}`);
    const count = (summary, key) => Number(summary[key] || 0);

    function render(documentData, path) {
        const summary = documentData.summary || {};
        const findings = Array.isArray(documentData.findings) ? documentData.findings : [];
        const title = text("h2", "Operator report");
        const subtitle = text("p", `Generated ${documentData.generated_at || "unknown"} · ${path}`, "operator-subtitle");
        const close = text("button", "Close", "quiet");
        close.type = "button";
        close.addEventListener("click", () => { inspector.hidden = true; history.replaceState(null, "", "/#reports"); });
        const heading = document.createElement("div"); heading.className = "operator-heading"; heading.append(title, close);
        const metrics = document.createElement("div"); metrics.className = "operator-metrics";
        [["Coverage", `${Number(summary.coverage || 0).toFixed(1)}%`], ["Findings", count(summary, "total")], ["Failed", count(summary, "failed")], ["Warnings", count(summary, "warnings")], ["Not assessed", count(summary, "not_assessed")]].forEach(([label, value]) => {
            const metric = document.createElement("div"); metric.className = "operator-metric"; metric.append(text("strong", value), text("span", label)); metrics.append(metric);
        });
        const toolbar = document.createElement("div"); toolbar.className = "operator-toolbar";
        const filter = document.createElement("input"); filter.type = "search"; filter.placeholder = "Filter control, service, title, remediation"; filter.setAttribute("aria-label", "Filter findings");
        const stateFilter = document.createElement("select"); stateFilter.setAttribute("aria-label", "Filter finding status");
        ["All statuses", "fail", "warning", "unknown", "error", "pass", "info"].forEach((value) => { const option = new Option(value, value === "All statuses" ? "" : value); stateFilter.add(option); });
        toolbar.append(filter, stateFilter);
        const table = document.createElement("table"); table.className = "operator-findings";
        table.innerHTML = "<thead><tr><th>Status</th><th>Control</th><th>Service</th><th>Finding and remediation</th></tr></thead>";
        const body = document.createElement("tbody"); table.append(body);
        const draw = () => {
            const term = filter.value.trim().toLowerCase(); const selected = stateFilter.value;
            body.replaceChildren();
            const visible = findings.filter((finding) => !selected || finding.status === selected).filter((finding) => `${finding.id} ${finding.service} ${finding.title} ${finding.detail} ${finding.remediation}`.toLowerCase().includes(term));
            if (!visible.length) { const row = document.createElement("tr"); const cell = text("td", "No findings match the selected filters.", "empty-cell"); cell.colSpan = 4; row.append(cell); body.append(row); return; }
            visible.forEach((finding) => {
                const row = document.createElement("tr");
                const findingCell = document.createElement("td"); findingCell.append(text("strong", finding.title || "Untitled finding"), text("p", finding.detail || "No evidence detail provided.", "operator-detail"), text("p", `Remediation: ${finding.remediation || "No remediation provided."}`, "operator-remediation"));
                row.append(text("td", "", "").appendChild(status(finding)).parentElement, text("td", finding.id), text("td", finding.service), findingCell); body.append(row);
            });
        };
        filter.addEventListener("input", draw); stateFilter.addEventListener("change", draw); draw();
        inspector.replaceChildren(heading, subtitle, metrics, toolbar, document.createElement("div")); inspector.lastElementChild.append(table); inspector.hidden = false;
    }

    async function load(path) {
        reportsTab.click();
        inspector.hidden = false; inspector.textContent = "Loading operator report…";
        try {
            const response = await fetch(`/api/report?path=${encodeURIComponent(path)}`, {cache: "no-store"});
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            render(await response.json(), path);
        } catch (error) { inspector.textContent = `Cannot load report: ${error.message}`; }
    }

    function overviewMetric(label, value, tone = "") {
        const metric = document.createElement("div"); metric.className = `results-overview-metric ${tone}`;
        metric.append(text("strong", value), text("span", label)); return metric;
    }

    async function renderOverview() {
        if (!overviewContent) return;
        try {
            const response = await fetch("/api/state", {cache: "no-store"});
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const overview = (await response.json()).overview || {};
            const latest = overview.latest;
            overviewContent.replaceChildren();
            if (!latest) { overviewContent.append(text("p", "No passive or active assessment is retained. Choose Read-only assessment, select Domain only, enter one authorized root domain, then use Passive before opening the report.", "muted")); latestButton.hidden = true; return; }
            const summary = latest.Summary || {};
            const metrics = document.createElement("div"); metrics.className = "results-overview-metrics";
            metrics.append(overviewMetric("Assessments", overview.analysisRuns || 0), overviewMetric("Coverage", `${Number(summary.Coverage || 0).toFixed(1)}%`), overviewMetric("Failures", summary.Fail || 0, "danger"), overviewMetric("Warnings", summary.Warning || 0, "warning"), overviewMetric("Not assessed", summary.NotEvaluated || 0, "warning"));
            const operation = latest.Operation || {};
            const meta = text("p", `${summary.Assessment || "Assessment"} · ${(operation.Services || []).join(", ") || "unknown scope"}${operation.Domain ? ` · ${operation.Domain}` : ""} · ${localTime(latest.LastWriteUtc)}`, "results-overview-meta");
            const salient = document.createElement("div"); salient.className = "results-overview-findings";
            const items = overview.salient || [];
            salient.append(text("h3", items.length ? "Priority findings" : "Assessment result"));
            if (!items.length) salient.append(text("p", "No failed, warning or execution-error findings in the latest report.", "muted"));
            items.forEach((finding) => { const item = document.createElement("div"); item.className = "results-overview-finding"; item.append(status(finding), text("strong", finding.title), text("span", `${finding.service} · ${finding.id}`), text("p", finding.remediation || "No remediation provided.")); salient.append(item); });
            overviewContent.append(metrics, meta, salient);
            latestButton.hidden = false; latestButton.onclick = () => load(latest.RelativePath);
        } catch (error) { overviewContent.textContent = `Cannot load assessment summary: ${error.message}`; }
    }

    async function remove(path) {
        if (!window.confirm("Delete this report and all of its generated artifacts? This cannot be undone.")) return;
        try {
            const response = await fetch(`/api/report?path=${encodeURIComponent(path)}`, {method: "DELETE", headers: {"x-claudit-token": document.body.dataset.requestToken}});
            if (!response.ok) throw new Error((await response.json()).error || `HTTP ${response.status}`);
            inspector.hidden = true;
            document.querySelector("#reloadReports").click();
        } catch (error) { window.alert(`Cannot delete report: ${error.message}`); }
    }

    function decorate() {
        reportsBody.querySelectorAll("a[href^='/api/report?path=']").forEach((raw) => {
            const path = new URL(raw.href).searchParams.get("path");
            if (!path || !path.endsWith("claudit-report.json") || raw.dataset.operatorLink) return;
            raw.dataset.operatorLink = "true"; raw.textContent = "Raw";
            const analyze = document.createElement("a"); analyze.className = "link"; analyze.href = `/?report=${encodeURIComponent(path)}#reports`; analyze.textContent = "Analyze";
            analyze.addEventListener("click", (event) => { event.preventDefault(); load(path); });
            const removeButton = text("button", "Delete", "quiet"); removeButton.type = "button"; removeButton.addEventListener("click", () => remove(path));
            raw.before(analyze, document.createTextNode(" · ")); raw.after(document.createTextNode(" · "), removeButton);
        });
    }
    const observer = new MutationObserver(decorate);
    observer.observe(reportsBody, {childList: true, subtree: true});
    decorate();
    document.addEventListener("claudit:state-refreshed", () => { renderOverview(); });
    renderOverview();
    if (parameter) load(parameter);
})();
