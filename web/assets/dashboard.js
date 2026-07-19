"use strict";

const state = {
    services: [],
    authCatalog: [],
    reports: [],
    operations: [],
    selectedOperation: null,
    serviceSignature: "",
};

const requestToken = document.body.dataset.requestToken || "";
const qs = (selector, root = document) => root.querySelector(selector);
const qsa = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const providerIcons = {
    Microsoft365: "/assets/icons/cloud/icons8-azure-1-50.png",
    Azure: "/assets/icons/cloud/icons8-azure-50.png",
    AWS: "/assets/icons/cloud/icons8-amazon-aws-50.png",
    GCP: "/assets/icons/cloud/icons8-google-cloud-50.png",
    Internet: "/assets/icons/cloud/icons8-cloudflare-50.png",
    MultiCloud: "/assets/icons/cloud/icons8-cloud-50.png",
    SaaS: "/assets/icons/cloud/icons8-cloud-50.png",
    VPS: "/assets/icons/cloud/icons8-cloud-50.png",
};

function element(tag, options = {}, children = []) {
    const node = document.createElement(tag);
    if (options.className) node.className = options.className;
    if (options.text !== undefined) node.textContent = String(options.text);
    if (options.attrs) {
        for (const [name, value] of Object.entries(options.attrs)) {
            if (value !== null && value !== undefined) node.setAttribute(name, String(value));
        }
    }
    for (const child of children) {
        if (child !== null && child !== undefined) {
            node.append(child instanceof Node ? child : document.createTextNode(String(child)));
        }
    }
    return node;
}

function replaceChildren(target, children) {
    target.replaceChildren(...children);
}

function formatBytes(value) {
    let number = Number(value) || 0;
    if (!number) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
    let index = 0;
    while (number >= 1024 && index < units.length - 1) {
        number /= 1024;
        index += 1;
    }
    return `${number.toFixed(index ? 1 : 0)} ${units[index]}`;
}

function localTime(iso) {
    if (!iso) return "";
    const date = new Date(iso);
    return Number.isNaN(date.getTime()) ? String(iso) : date.toLocaleString();
}

function pill(text) {
    const label = String(text || "Info");
    const tone = label.toLowerCase().replace(/[^a-z0-9_-]/g, "") || "info";
    return element("span", { className: `pill ${tone}`, text: label });
}

function showToast(message, tone = "info") {
    const region = qs("#toastRegion");
    const toast = element("div", {
        className: `toast ${tone}`,
        text: message,
        attrs: { role: tone === "error" ? "alert" : "status" },
    });
    region.append(toast);
    window.setTimeout(() => toast.remove(), 5000);
}

function setConnection(connected, detail = "") {
    const status = qs("#connectionState");
    const label = qs("#serverState");
    status.dataset.state = connected ? "online" : "offline";
    label.textContent = connected ? "Connected" : "Disconnected";
    status.title = detail || (connected ? "Local dashboard is reachable" : "Local dashboard is not reachable");
}

function selectedServices() {
    return qsa(".service-checkbox:checked").map((input) => input.value);
}

function selectedSpecs() {
    const names = new Set(selectedServices());
    return state.services.filter((service) => names.has(service.Name));
}

function hasProvider(provider) {
    return selectedSpecs().some((service) => service.Provider === provider);
}

function hasService(name) {
    return selectedServices().includes(name);
}

function renderServices() {
    const target = qs("#serviceList");
    const previous = new Set(selectedServices());
    const firstRender = !target.children.length;
    const cards = state.services.map((service, index) => {
        const id = `service-${index}`;
        const input = element("input", {
            className: "service-checkbox",
            attrs: {
                id,
                type: "checkbox",
                value: service.Name,
            },
        });
        input.checked = firstRender ? Boolean(service.Default) : previous.has(service.Name);
        input.addEventListener("change", refreshWizard);

        const icon = element("img", {
            className: "service-icon",
            attrs: {
                src: providerIcons[service.Provider] || providerIcons.MultiCloud,
                alt: "",
                width: "24",
                height: "24",
                loading: "lazy",
            },
        });
        return element("label", { className: "service-option", attrs: { for: id } }, [
            input,
            icon,
            element("span", { className: "service-name", text: service.Name }),
            element("span", { className: "service-provider", text: service.Provider }),
        ]);
    });
    replaceChildren(target, cards);
    refreshWizard();
}

function setGroup(className, visible) {
    qsa(`.${className}`).forEach((node) => {
        node.hidden = !visible;
    });
}

function authMethod(provider) {
    const appOnly = qs("#authMode").value === "AppOnly";
    if (provider === "Microsoft365") {
        if (appOnly) return "AppCertificate";
        return qs("#graphAuthMode").value === "Browser" ? "DelegatedBrowser" : "DelegatedDeviceCode";
    }
    if (provider === "Azure") return "AzCli";
    if (provider === "AWS") return "AwsCliProfile";
    if (provider === "GCP") return "Gcloud";
    if (provider === "SaaS") return "ApiTokenEnv";
    if (provider === "VPS") return "LocalOrSsh";
    if (provider === "Internet") return "Public";
    return "ExistingProviderContexts";
}

function methodDescription(provider, method) {
    const match = state.authCatalog.find((item) => item.Provider === provider && item.Method === method);
    return match ? match.Description : "";
}

function buildAuthPlan() {
    const specs = selectedSpecs();
    const plan = [];
    if (hasService("Domain")) {
        plan.push({
            stage: 10,
            name: "Public domain recon",
            provider: "Internet",
            method: "Public",
            services: ["Domain"],
            gate: "Authorized domain scope",
        });
    }

    const microsoft = specs.filter((item) => item.Provider === "Microsoft365").map((item) => item.Name);
    if (microsoft.length) {
        const method = authMethod("Microsoft365");
        plan.push({
            stage: 20,
            name: "Microsoft 365 credential gate",
            provider: "Microsoft365",
            method,
            services: microsoft,
            gate: "Graph/Exchange read-only connection",
        });
        plan.push({
            stage: 30,
            name: "Microsoft 365 authenticated controls",
            provider: "Microsoft365",
            method,
            services: microsoft,
            gate: "Connected session",
        });
    }

    for (const provider of ["Azure", "AWS", "GCP", "SaaS", "VPS", "MultiCloud"]) {
        const services = specs.filter((item) => item.Provider === provider).map((item) => item.Name);
        if (!services.length) continue;
        const method = authMethod(provider);
        plan.push({
            stage: 20,
            name: `${provider} credential gate`,
            provider,
            method,
            services,
            gate: "CLI/API identity validation",
        });
        plan.push({
            stage: 30,
            name: `${provider} authenticated controls`,
            provider,
            method,
            services,
            gate: "Provider read-only context",
        });
    }
    return plan.sort((left, right) => left.stage - right.stage || left.provider.localeCompare(right.provider));
}

function renderAuthPlan() {
    const target = qs("#authPlan");
    const plan = buildAuthPlan();
    if (!plan.length) {
        replaceChildren(target, [element("div", { className: "muted", text: "Select at least one service." })]);
        return;
    }

    const gates = plan.map((item) => element("div", { className: "auth-gate" }, [
        element("div", { className: "auth-gate-title", text: `${item.stage}. ${item.name}` }),
        element("div", { className: "auth-gate-rule", text: item.gate }),
        element("div", {
            className: "auth-gate-meta",
            text: `${item.provider} / ${item.method} / ${item.services.join(", ")}`,
        }),
        element("div", { className: "auth-gate-hint", text: methodDescription(item.provider, item.method) }),
    ]));
    replaceChildren(target, gates);
}

function refreshWizard() {
    const microsoft = hasProvider("Microsoft365");
    const appOnly = qs("#authMode").value === "AppOnly";
    const active = qs("#controlLevel").value === "Active";
    const vps = hasService("VPS");

    setGroup("m365", microsoft);
    setGroup("delegated", microsoft && !appOnly);
    setGroup("apponly", microsoft && appOnly);
    setGroup("azure", hasProvider("Azure"));
    setGroup("aws", hasProvider("AWS"));
    setGroup("gcp", hasProvider("GCP"));
    setGroup("tailscale", hasService("Tailscale"));
    setGroup("domain", hasService("Domain"));
    setGroup("vps", vps);
    setGroup("active", active);
    qsa(".active.vps").forEach((node) => {
        node.hidden = !(active && vps);
    });
    renderAuthPlan();
}

function reportSignalText(report) {
    const summary = report.Summary;
    if (!summary) return "raw file";
    if (summary.Kind === "audit") {
        return `${summary.Outcome || "Unknown"} / ${summary.Problems || 0} problems / ${summary.Error || 0} errors / ${summary.Coverage ?? 100}% coverage`;
    }
    if (summary.Kind === "preflight") {
        return `${summary.Status || "Info"} ${summary.Fail || 0} fail, ${summary.Warning || 0} warn`;
    }
    if (summary.Error) return "parse error";
    return summary.Kind || "raw file";
}

function reportSignal(report) {
    const summary = report.Summary;
    if (!summary) return element("span", { className: "muted", text: "Raw file" });
    if (summary.Kind === "audit") return document.createTextNode(reportSignalText(report));
    if (summary.Kind === "preflight") {
        const wrapper = element("span");
        wrapper.append(pill(summary.Status), document.createTextNode(` ${summary.Fail || 0} fail, ${summary.Warning || 0} warn`));
        return wrapper;
    }
    return document.createTextNode(summary.Error ? "Parse error" : (summary.Kind || "Raw file"));
}

function latestAudit() {
    return state.reports.find((report) => report.Summary && report.Summary.Kind === "audit");
}

function renderMetrics() {
    const latest = latestAudit();
    qs("#mReports").textContent = state.reports.length;
    qs("#mRuns").textContent = state.operations.length;
    qs("#mRunning").textContent = state.operations.filter((operation) => operation.Status === "Running").length;
    qs("#mProblems").textContent = latest?.Summary?.Problems || 0;
    qs("#mNotEvaluated").textContent = latest?.Summary?.NotEvaluated || 0;
    qs("#mErrors").textContent = latest?.Summary?.Error || 0;
}

function renderActivitySummary() {
    const latest = state.operations[0];
    qs("#latestRun").textContent = latest?.Id || "None";
    qs("#latestStatus").textContent = latest?.Status || "Idle";
}

function emptyRow(columns, message) {
    const cell = element("td", { className: "empty-cell", text: message, attrs: { colspan: columns } });
    return element("tr", {}, [cell]);
}

function renderOperations() {
    const target = qs("#operationsBody");
    if (!state.operations.length) {
        replaceChildren(target, [emptyRow(6, "No operations yet. Start a preflight from Overview.")]);
        return;
    }

    const rows = state.operations.map((operation) => {
        const logButton = element("button", {
            className: "quiet",
            text: "View log",
            attrs: { type: "button", "data-operation-id": operation.Id },
        });
        logButton.addEventListener("click", () => {
            loadLog(operation.Id).catch((error) => showToast(error.message, "error"));
            selectTab("overview");
        });

        const statusCell = element("td", {}, [pill(operation.Status)]);
        if (operation.ExitCode !== null && operation.ExitCode !== undefined) {
            statusCell.append(document.createTextNode(`  code ${operation.ExitCode}`));
        }
        return element("tr", {}, [
            element("td", {}, [
                element("span", { className: "cell-title", text: operation.Id }),
                element("span", { className: "cell-subtle", text: localTime(operation.StartedUtc) }),
            ]),
            element("td", { text: `${operation.Mode} / ${operation.ControlLevel || "Passive"}` }),
            statusCell,
            element("td", { text: (operation.Services || []).join(", ") }),
            element("td", {}, [element("span", { className: "cell-subtle", text: operation.OutputDirectory || "" })]),
            element("td", {}, [logButton]),
        ]);
    });
    replaceChildren(target, rows);
}

function renderReports() {
    const target = qs("#reportsBody");
    const filter = qs("#reportFilter").value.trim().toLowerCase();
    const rows = state.reports.filter((report) => {
        const haystack = `${report.Name} ${report.RelativePath} ${reportSignalText(report)}`.toLowerCase();
        return haystack.includes(filter);
    });

    if (!rows.length) {
        const message = filter ? "No reports match this filter." : "No report files found.";
        replaceChildren(target, [emptyRow(6, message)]);
        return;
    }

    replaceChildren(target, rows.map((report) => {
        const open = element("a", {
            className: "link",
            text: "Open",
            attrs: {
                href: `/api/report?path=${encodeURIComponent(report.RelativePath)}`,
                target: "_blank",
                rel: "noopener",
            },
        });
        return element("tr", {}, [
            element("td", {}, [
                element("span", { className: "cell-title", text: report.Name }),
                element("span", { className: "cell-subtle", text: report.RelativePath }),
            ]),
            element("td", { text: report.Extension }),
            element("td", { text: localTime(report.LastWriteUtc) }),
            element("td", {}, [reportSignal(report)]),
            element("td", { text: formatBytes(report.SizeBytes) }),
            element("td", {}, [open]),
        ]);
    }));
}

async function api(path, options = {}) {
    const headers = { ...(options.headers || {}), "x-claudit-token": requestToken };
    const response = await fetch(path, { ...options, headers });
    const text = await response.text();
    if (!response.ok) {
        let message = text || `Request failed (${response.status})`;
        try {
            const parsed = JSON.parse(text);
            message = parsed.error || message;
        } catch {
            // Keep the server text when the response is not JSON.
        }
        throw new Error(message);
    }
    return text ? JSON.parse(text) : null;
}

async function refresh() {
    try {
        const snapshot = await api("/api/state");
        state.services = snapshot.services || [];
        state.authCatalog = snapshot.authCatalog || [];
        state.reports = snapshot.reports || [];
        state.operations = snapshot.operations || [];

        const signature = state.services.map((service) => `${service.Name}:${service.Provider}`).join("|");
        if (signature !== state.serviceSignature) {
            state.serviceSignature = signature;
            renderServices();
        }
        if (document.activeElement !== qs("#retentionCount")) {
            qs("#retentionCount").value = snapshot.retentionCount || 100;
        }
        refreshWizard();
        renderMetrics();
        renderActivitySummary();
        renderOperations();
        renderReports();
        setConnection(true);
    } catch (error) {
        setConnection(false, error.message);
        throw error;
    }
}

async function loadLog(id) {
    state.selectedOperation = id;
    qs("#logPane").textContent = "Loading operation output…";
    const data = await api(`/api/operations/log?id=${encodeURIComponent(id)}`);
    const output = `${data.stdout || ""}${data.stderr ? `\n\n[stderr]\n${data.stderr}` : ""}`;
    qs("#logPane").textContent = output || "No log output yet.";
    qs("#logTitle").textContent = id;
}

function retentionValue() {
    const value = Number(qs("#retentionCount").value);
    if (!Number.isInteger(value) || value < 1 || value > 10000) {
        throw new Error("Results to keep must be an integer between 1 and 10000.");
    }
    return value;
}

async function withBusy(button, busyLabel, action) {
    const original = button.textContent;
    button.disabled = true;
    button.textContent = busyLabel;
    try {
        return await action();
    } finally {
        button.disabled = false;
        button.textContent = original;
    }
}

async function saveRetention() {
    const value = retentionValue();
    await api("/api/settings", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ retentionCount: value }),
    });
    await refresh();
    showToast(`Retention updated to ${value} completed runs.`);
}

function operationRequest() {
    return {
        mode: qs("#opMode").value,
        retentionCount: retentionValue(),
        controlLevel: qs("#controlLevel").value,
        confirmActiveProbes: qs("#confirmActiveProbes").value === "true",
        activeTimeoutMs: qs("#activeTimeoutMs").value,
        vpsProbePort: qs("#vpsProbePort").value,
        service: selectedServices(),
        format: qs("#format").value,
        tenantName: qs("#tenantName").value,
        environment: qs("#environment").value,
        authMode: qs("#authMode").value,
        graphAuthMode: qs("#graphAuthMode").value,
        tenantId: qs("#tenantId").value,
        clientId: qs("#clientId").value,
        certificateThumbprint: qs("#certificateThumbprint").value,
        organization: qs("#organization").value,
        runPester: qs("#runPester").value === "true",
        azureSubscription: qs("#azureSubscription").value,
        azureTenant: qs("#azureTenant").value,
        awsProfile: qs("#awsProfile").value,
        awsRegion: qs("#awsRegion").value,
        gcpProject: qs("#gcpProject").value,
        gcpAccount: qs("#gcpAccount").value,
        gcpOrganization: qs("#gcpOrganization").value,
        tailscaleTailnet: qs("#tailscaleTailnet").value,
        tailscaleApiTokenEnv: qs("#tailscaleApiTokenEnv").value,
        tailscaleAuthScheme: qs("#tailscaleAuthScheme").value,
        domain: qs("#domain").value,
        domainSubdomain: qs("#domainSubdomain").value,
        vpsTarget: qs("#vpsTarget").value,
        vpsSshUser: qs("#vpsSshUser").value,
        vpsSshPort: qs("#vpsSshPort").value,
        vpsAllowedPublicPort: qs("#vpsAllowedPublicPort").value,
    };
}

async function startOperation() {
    const body = operationRequest();
    if (!body.service.length) throw new Error("Select at least one service before starting.");
    if (body.controlLevel === "Active" && !body.confirmActiveProbes) {
        throw new Error("Active controls require explicit authorization for the selected targets.");
    }
    const operation = await api("/api/operations", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
    });
    await refresh();
    await loadLog(operation.Id);
    showToast(`Operation ${operation.Id} started.`);
}

function selectTab(id) {
    qsa("[role='tab']").forEach((button) => {
        const selected = button.dataset.tab === id;
        button.setAttribute("aria-selected", String(selected));
        button.tabIndex = selected ? 0 : -1;
    });
    qsa(".tab").forEach((panel) => {
        panel.hidden = panel.id !== id;
    });
}

function bindEvents() {
    qsa("[role='tab']").forEach((button) => {
        button.addEventListener("click", () => selectTab(button.dataset.tab));
        button.addEventListener("keydown", (event) => {
            if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
            const tabs = qsa("[role='tab']");
            const current = tabs.indexOf(button);
            const delta = event.key === "ArrowRight" ? 1 : -1;
            const next = tabs[(current + delta + tabs.length) % tabs.length];
            event.preventDefault();
            selectTab(next.dataset.tab);
            next.focus();
        });
    });

    qs("#authMode").addEventListener("change", refreshWizard);
    qs("#graphAuthMode").addEventListener("change", refreshWizard);
    qs("#controlLevel").addEventListener("change", refreshWizard);
    qs("#reportFilter").addEventListener("input", renderReports);

    qs("#saveRetention").addEventListener("click", (event) => {
        withBusy(event.currentTarget, "Saving…", saveRetention).catch((error) => showToast(error.message, "error"));
    });
    qs("#startOp").addEventListener("click", (event) => {
        withBusy(event.currentTarget, "Starting…", startOperation).catch((error) => showToast(error.message, "error"));
    });
    qs("#refreshAll").addEventListener("click", (event) => {
        withBusy(event.currentTarget, "Refreshing…", refresh).catch((error) => showToast(error.message, "error"));
    });
    qs("#reloadReports").addEventListener("click", (event) => {
        withBusy(event.currentTarget, "Refreshing…", refresh).catch((error) => showToast(error.message, "error"));
    });
}

bindEvents();
refresh().catch((error) => showToast(error.message, "error"));
window.setInterval(() => {
    if (document.hidden) return;
    refresh()
        .then(() => state.selectedOperation ? loadLog(state.selectedOperation) : null)
        .catch(() => {});
}, 5000);
