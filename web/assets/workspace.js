"use strict";
(() => {
  const el = id => document.getElementById(id);
  let selected = "";
  async function request(url, body) {
    const response = await fetch(url, body === undefined ? {cache: "no-store"} : {
      method: "POST", headers: {"Content-Type": "application/json", "x-claudit-token": document.body.dataset.requestToken}, body: JSON.stringify(body)
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
    return data;
  }
  async function remove(url) {
    const response = await fetch(url, {method: "DELETE", headers: {"x-claudit-token": document.body.dataset.requestToken}});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
    return data;
  }
  const paragraph = (parent, text) => {const p = document.createElement("p"); p.textContent = text; parent.append(p);};
  async function load() {
    if (!selected) return;
    const session = await request(`/api/session?id=${encodeURIComponent(selected)}`);
    const plan = await request(`/api/session/plan?id=${encodeURIComponent(selected)}`);
    el("sessionContext").textContent = `${session.title} · ${session.scope.service.join(", ")} · ${session.scope.domain || session.scope.vpsTarget || "Provider scope"} · ${session.operations.length} runs${session.archived ? " · archived read-only" : ""}`;
    el("sessionHistory").replaceChildren();
    for (const event of session.history.slice(-20).reverse()) paragraph(el("sessionHistory"), `${event.at} · ${event.kind}: ${event.text || event.question || event.operation}`);
    const planPanel = el("sessionPlan"); planPanel.replaceChildren();
    for (const step of plan.steps) paragraph(planPanel, step);
    paragraph(planPanel, `Executable controls: ${plan.controls.map(item => item.id).join(", ") || "none for this scope"}.`);
    for (const question of plan.suggestedQuestions) paragraph(planPanel, `Ask: ${question}`);
    for (const limitation of plan.limitations) paragraph(planPanel, `Boundary: ${limitation}`);
    return session;
  }
  async function index() {
    const sessions = await request("/api/sessions");
    el("sessionSelect").replaceChildren(new Option("All assessments", ""));
    for (const session of sessions) el("sessionSelect").add(new Option(`${session.title}${session.archived ? " (archived)" : session.status === "error" ? " (unreadable)" : ""}`, session.id));
    el("sessionSelect").value = selected;
    await load();
  }
  function bind(id, action) {
    el(id).addEventListener("click", async () => {
      el(id).disabled = true; el("sessionStatus").textContent = "Working…";
      try {await action(); el("sessionStatus").textContent = "Saved locally.";}
      catch (error) {el("sessionStatus").textContent = error.message;}
      finally {el(id).disabled = false;}
    });
  }
  bind("sessionCreate", async () => {
    const scope = operationRequest();
    const records = new Map();
    for (const line of el("sessionDns").value.split("\n").filter(s => s.trim())) {
      const parts = line.split("|");
      if (parts.length < 3) throw new Error("DNS rows need name | type | value.");
      const name = parts.shift().trim(), type = parts.shift().trim().toUpperCase(), value = parts.join("|").trim();
      const key = `${name}|${type}`;
      if (!records.has(key)) records.set(key, {name, type, values: []});
      if (value) records.get(key).values.push(value);
    }
    const expectedStatuses = {};
    for (const line of el("sessionExpected").value.split("\n").filter(s => s.trim())) {
      const parts = line.split("|").map(s => s.trim());
      if (parts.length !== 2) throw new Error("Expected control rows need ID | status.");
      expectedStatuses[parts[0]] = parts[1];
    }
    const session = await request("/api/sessions", {title: el("sessionTitle").value, scope, dnsRecords: [...records.values()], expectedStatuses});
    selected = session.id; await index();
  });
  bind("sessionDnsImport", async () => {
    const file = el("sessionDnsFile").files[0];
    if (!file) throw new Error("Choose a provider JSON export first.");
    const scope = operationRequest();
    if (!scope.domain) throw new Error("Declare the authorized root domain in New operation.");
    const result = await request("/api/session/dns/import", {provider: el("sessionDnsProvider").value, domain: scope.domain, data: JSON.parse(await file.text())});
    el("sessionDns").value = result.records.flatMap(record => record.values.map(value => `${record.name} | ${record.type} | ${value}`)).join("\n");
  });
  bind("sessionReload", index);
  bind("sessionExport", async () => {
    if (!selected) throw new Error("Select a work session first.");
    const data = await request(`/api/session/export?id=${encodeURIComponent(selected)}`);
    const link = document.createElement("a"); link.href = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], {type: "application/json"}));
    link.download = `claudit-session-${selected}.json`; link.click(); URL.revokeObjectURL(link.href);
  });
  bind("sessionDnsExport", async () => {
    if (!selected) throw new Error("Select a domain work session first.");
    const data = await request(`/api/session/dns/export?id=${encodeURIComponent(selected)}`);
    const link = document.createElement("a"); link.href = URL.createObjectURL(new Blob([data.content], {type: data.mediaType}));
    link.download = data.filename; link.click(); URL.revokeObjectURL(link.href);
  });
  bind("sessionArchive", async () => {
    if (!selected) throw new Error("Select an active work session first.");
    await request("/api/session/archive", {id: selected}); await index();
  });
  bind("sessionDelete", async () => {
    if (!selected) throw new Error("Select an archived work session first.");
    if (!window.confirm("Permanently delete this archived session? Export it first if it must be retained.")) return;
    await remove(`/api/session?id=${encodeURIComponent(selected)}`); selected = ""; await index();
  });
  bind("sessionQuarantine", async () => {
    if (!selected) throw new Error("Select an unreadable work session first.");
    await request("/api/session/quarantine", {id: selected}); selected = ""; await index();
  });
  el("sessionSelect").addEventListener("change", async () => {
    selected = el("sessionSelect").value; el("sessionAnswer").replaceChildren();
    try {
      const session = await load();
      document.dispatchEvent(new CustomEvent("claudit:session-selected", {detail: session}));
    } catch (error) {el("sessionStatus").textContent = error.message;}
  });
  bind("sessionRun", async () => {
    if (!selected) throw new Error("Save or select a work session first.");
    const session = await load();
    const scope = session.scope || {};
    document.querySelector("input[name='profile'][value='advanced']").checked = true;
    document.querySelectorAll(".service-checkbox").forEach(input => {input.disabled = false; input.checked = (scope.service || []).includes(input.value);});
    for (const [key, value] of Object.entries(scope)) {const input = el(key); if (input && typeof value === "string") input.value = value;}
    el("controlLevel").value = el("sessionLevel").value[0].toUpperCase() + el("sessionLevel").value.slice(1);
    el("confirmTenantConnection").checked = el("sessionConnection").checked;
    el("confirmActiveProbes").checked = el("sessionActive").checked;
    el("sessionDialog").close(); window.claudit.openWizard();
  });
  async function query(kind) {
    if (!selected) throw new Error("Save or select a work session first.");
    const result = await request("/api/session/query", {id: selected, question: el("sessionQuestion").value, kind});
    const panel = el("sessionAnswer"); panel.replaceChildren(); paragraph(panel, result.answer);
    if (result.source) {
      const a = document.createElement("a"); a.textContent = "Open cited evidence";
      a.href = `/api/report?path=${encodeURIComponent(result.source)}`; a.target = "_blank"; a.rel = "noopener"; panel.append(a);
      for (const [filename, title] of (result.dnsPlan?.length ? [["claudit-dns-plan.jsonl", "DNS change plan"], ["claudit-dns-evidence.jsonl", "DNS observations"]] : [])) {
        const link = document.createElement("a"); link.textContent = title; link.href = `/api/report?path=${encodeURIComponent(result.source.replace("claudit-report.json", filename))}`; link.target = "_blank"; link.rel = "noopener"; panel.append(link);
      }
    }
    for (const f of result.findings || []) {
      const article = document.createElement("article");
      paragraph(article, `${f.id} · ${f.status} · ${f.title}`); paragraph(article, f.detail); paragraph(article, `Next step: ${f.remediation}`); panel.append(article);
    }
    for (const row of result.dnsPlan || []) {
      const article = document.createElement("article"); paragraph(article, `${row.name} · ${row.type}`);
      paragraph(article, `Expected: ${row.expected.join(", ") || "Absent"}`);
      paragraph(article, `Observed: ${row.observed === null ? "Unavailable" : row.observed.join(", ") || "Absent"}`);
      paragraph(article, row.action); panel.append(article);
    }
    for (const change of result.configurationDrift || []) paragraph(panel, `${change.id}: expected ${change.expected}, observed ${change.observed}.`);
    await load();
  }
  bind("sessionAsk", () => query("query")); bind("sessionNote", () => query("note"));
  el("sessionManage").addEventListener("click", () => el("sessionDialog").showModal());
  el("closeSession").addEventListener("click", () => el("sessionDialog").close());
  index().catch(error => {el("sessionStatus").textContent = error.message;});
})();
