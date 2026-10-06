/**
 * SAQRIntel frontend — workspace UI, live WebSocket scans, findings, reports.
 */
/* global bootstrap, renderNetworkGraph */

const state = {
  workspace: null,
  authModal: null,
  settingsModal: null,
  pendingScan: null,
};

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || JSON.stringify(body);
    } catch (_) { /* ignore */ }
    throw new Error(detail);
  }
  if (res.status === 204) return null;
  return res.json();
}

function showWorkspaces() {
  document.getElementById("view-workspaces").classList.remove("d-none");
  document.getElementById("view-dashboard").classList.add("d-none");
  state.workspace = null;
  loadWorkspaces();
}

function openWorkspace(ws) {
  state.workspace = ws;
  document.getElementById("view-workspaces").classList.add("d-none");
  document.getElementById("view-dashboard").classList.remove("d-none");
  document.getElementById("nav-ws-name").textContent = ws.name;
  document.getElementById("live-log").textContent = "";
  setScanStatus("idle");
  refreshAll();
}

async function loadWorkspaces() {
  const list = document.getElementById("ws-list");
  list.innerHTML = '<div class="text-secondary p-2">Loading…</div>';
  try {
    const workspaces = await api("/api/workspaces");
    if (!workspaces.length) {
      list.innerHTML = '<div class="text-secondary p-2">No workspaces yet — create one above.</div>';
      return;
    }
    list.innerHTML = "";
    workspaces.forEach((ws) => {
      const a = document.createElement("button");
      a.type = "button";
      a.className = "list-group-item list-group-item-action d-flex justify-content-between align-items-center";
      a.innerHTML = `<span><strong>${escapeHtml(ws.name)}</strong><br><small class="text-secondary">${escapeHtml(ws.description || "")}</small></span>
        <span class="badge text-bg-dark">#${ws.id}</span>`;
      a.onclick = () => openWorkspace(ws);
      list.appendChild(a);
    });
  } catch (err) {
    list.innerHTML = `<div class="text-danger p-2">${escapeHtml(err.message)}</div>`;
  }
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function selectedModules() {
  return [...document.querySelectorAll(".mod-check:checked")].map((el) => el.value);
}

function setScanStatus(status) {
  const el = document.getElementById("scan-status");
  el.textContent = status;
  el.className = "badge " + (
    status === "running" ? "text-bg-primary" :
    status === "completed" ? "text-bg-success" :
    status === "error" ? "text-bg-danger" : "text-bg-secondary"
  );
}

function appendLog(line) {
  const pre = document.getElementById("live-log");
  pre.textContent += line + "\n";
  pre.scrollTop = pre.scrollHeight;
}

function beginScan(authorized) {
  const target = document.getElementById("scan-target").value.trim();
  if (!target) {
    alert("Enter a target domain, IP, or URL.");
    return;
  }
  const modules = selectedModules();
  if (!modules.length) {
    alert("Select at least one module.");
    return;
  }

  const options = {
    dns_brute: document.getElementById("opt-dns-brute").checked,
    do_fuzz: document.getElementById("opt-do-fuzz").checked,
  };

  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws/scan`);
  let terminal = false;
  setScanStatus("running");
  document.getElementById("live-log").textContent = "";
  appendLog(`Connecting… target=${target} modules=${modules.join(",")}`);

  ws.onopen = () => {
    ws.send(JSON.stringify({
      workspace_id: state.workspace.id,
      target,
      modules,
      authorized: !!authorized,
      authorization_ack: authorized ? "I_CONFIRM_AUTHORIZATION" : null,
      options,
    }));
  };

  ws.onmessage = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { appendLog(ev.data); return; }
    if (msg.type === "log") appendLog(msg.message);
    else if (msg.type === "status") appendLog(msg.message);
    else if (msg.type === "done") {
      terminal = true;
      setScanStatus(msg.status || "completed");
      appendLog(`DONE scan_id=${msg.scan_id} status=${msg.status}`);
      appendLog(JSON.stringify(msg.summary || {}, null, 2));
      refreshAll();
    } else if (msg.type === "error") {
      terminal = true;
      setScanStatus("error");
      appendLog("ERROR: " + msg.message);
    }
  };

  ws.onerror = () => {
    if (!terminal) {
      setScanStatus("error");
      appendLog("WebSocket error (scan may still be running on the server — refresh Findings)");
    }
  };

  ws.onclose = () => {
    // Do not force idle if we already got done/error; if still running, warn
    if (!terminal && document.getElementById("scan-status").textContent === "running") {
      setScanStatus("running");
      appendLog("Live stream disconnected — backend may still be writing findings. Check Results shortly.");
    }
  };
}

function requestScan() {
  const modules = selectedModules();
  const needsAuth = modules.some((m) => m === "network" || m === "web");
  const target = document.getElementById("scan-target").value.trim();
  if (needsAuth) {
    document.getElementById("auth-target-label").textContent = target || "(no target)";
    document.getElementById("auth-confirm").checked = false;
    document.getElementById("btn-auth-continue").disabled = true;
    state.authModal.show();
  } else {
    beginScan(false);
  }
}

async function refreshFindings(module) {
  if (!state.workspace) return;
  const q = module ? `?module=${encodeURIComponent(module)}` : "";
  const findings = await api(`/api/workspaces/${state.workspace.id}/findings${q}`);
  loadRisk();

  // Results cards
  const cards = document.getElementById("results-cards");
  cards.innerHTML = "";
  if (!findings.length) {
    cards.innerHTML = '<div class="col-12 text-secondary">No findings yet — run a scan.</div>';
  } else {
    findings.forEach((f) => {
      const col = document.createElement("div");
      col.className = "col-md-6 col-xl-4";
      col.innerHTML = `
        <div class="finding-card">
          <div class="d-flex justify-content-between mb-1">
            <span class="badge text-bg-dark">${escapeHtml(f.module)}</span>
            <span class="badge text-bg-${sevClass(f.severity)}">${escapeHtml(f.severity)}</span>
          </div>
          <div class="fw-semibold mb-1">${escapeHtml(f.title)}</div>
          ${controlBadges(f)}
          <pre>${escapeHtml(JSON.stringify(f.data_json, null, 2))}</pre>
        </div>`;
      cards.appendChild(col);
    });
  }

  // Findings table
  const tbody = document.querySelector("#findings-table tbody");
  tbody.innerHTML = "";
  findings.forEach((f) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${f.id}</td>
      <td>${escapeHtml(f.module)}</td>
      <td>${escapeHtml(f.title)}</td>
      <td>
        <select class="form-select form-select-sm sev-select" data-id="${f.id}">
          ${["Info", "Low", "Medium", "High"].map((s) =>
            `<option value="${s}" ${s === f.severity ? "selected" : ""}>${s}</option>`
          ).join("")}
        </select>
      </td>
      <td class="small">${escapeHtml(f.created_at || "")}</td>
      <td class="small">${controlText(f)}</td>`;
    tbody.appendChild(tr);
  });

  tbody.querySelectorAll(".sev-select").forEach((sel) => {
    sel.onchange = async () => {
      await api(`/api/findings/${sel.dataset.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          severity: sel.value,
          workspace_id: state.workspace.id,
        }),
      });
      refreshFindings(module);
    };
  });
}

function controlsOf(f) {
  const d = f.data_json || {};
  return Array.isArray(d.compliance) ? d.compliance : [];
}

function controlLabel(c) {
  return (c.framework === "NCA ECC" ? "NCA " : "ISO ") + c.control;
}

function controlBadges(f) {
  const list = controlsOf(f);
  if (!list.length) return "";
  const badges = list.map((c) =>
    `<span class="badge text-bg-light border me-1 mb-1" title="${escapeHtml(c.name)}">${escapeHtml(controlLabel(c))}</span>`
  ).join("");
  return `<div class="mb-2">${badges}</div>`;
}

function controlText(f) {
  return controlsOf(f).map((c) => escapeHtml(controlLabel(c))).join(", ");
}

async function loadRisk() {
  const box = document.getElementById("risk-panel");
  if (!box || !state.workspace) return;
  try {
    const r = await api(`/api/workspaces/${state.workspace.id}/risk`);
    const color = { Critical: "danger", High: "warning", Moderate: "info", Low: "success" }[r.rating] || "secondary";
    const c = r.counts || {};
    box.innerHTML = `
      <div class="finding-card">
        <div class="d-flex justify-content-between align-items-center mb-2">
          <div class="fw-semibold">Risk score (latest scan)</div>
          <span class="badge text-bg-${color} fs-6">${r.score}/100 - ${escapeHtml(r.rating)}</span>
        </div>
        <div class="progress mb-2" style="height: 12px;">
          <div class="progress-bar bg-${color}" style="width: ${r.score}%"></div>
        </div>
        <div class="small text-secondary">High: ${c.High || 0} | Medium: ${c.Medium || 0} | Low: ${c.Low || 0} | Info: ${c.Info || 0}</div>
      </div>`;
  } catch (_) {
    box.innerHTML = "";
  }
}

function sevClass(sev) {
  return { High: "danger", Medium: "warning", Low: "info", Info: "secondary" }[sev] || "secondary";
}

async function refreshGraph() {
  if (!state.workspace) return;
  const graph = await api(`/api/workspaces/${state.workspace.id}/graph`);
  renderNetworkGraph("network-graph", graph);
}

async function refreshReports() {
  if (!state.workspace) return;
  const reports = await api(`/api/reports?workspace_id=${state.workspace.id}`);
  const ul = document.getElementById("report-list");
  ul.innerHTML = "";
  if (!reports.length) {
    ul.innerHTML = '<li class="list-group-item text-secondary">No reports yet.</li>';
    return;
  }
  reports.forEach((r) => {
    const li = document.createElement("li");
    li.className = "list-group-item d-flex justify-content-between";
    li.innerHTML = `<span>${escapeHtml(r.filename)}</span>
      <a class="btn btn-sm btn-outline-light" href="${r.url}">Download</a>`;
    ul.appendChild(li);
  });
}

async function refreshAll() {
  try {
    await refreshFindings("");
    await refreshGraph();
    await refreshReports();
  } catch (err) {
    console.error(err);
  }
}

async function loadSettingsForm() {
  const s = await api("/api/settings");
  document.getElementById("set-rate").value = s.rate_limit_rps;
  document.getElementById("set-threads").value = s.thread_count;
  document.getElementById("set-nmap").value = s.nmap_ports;
  document.getElementById("set-sub-wl").value = s.subdomain_wordlist;
  document.getElementById("set-fuzz-wl").value = s.fuzzer_wordlist;
  document.getElementById("set-depth").value = s.crawl_max_depth;
  document.getElementById("set-pages").value = s.crawl_max_pages;
}

async function saveSettings() {
  const body = {
    rate_limit_rps: parseFloat(document.getElementById("set-rate").value),
    thread_count: parseInt(document.getElementById("set-threads").value, 10),
    nmap_ports: document.getElementById("set-nmap").value,
    subdomain_wordlist: document.getElementById("set-sub-wl").value,
    fuzzer_wordlist: document.getElementById("set-fuzz-wl").value,
    crawl_max_depth: parseInt(document.getElementById("set-depth").value, 10),
    crawl_max_pages: parseInt(document.getElementById("set-pages").value, 10),
  };
  await api("/api/settings", { method: "PUT", body: JSON.stringify(body) });
  state.settingsModal.hide();
}

async function generateReport(fmt) {
  if (!state.workspace) return;
  const target = document.getElementById("scan-target").value.trim() || undefined;
  const res = await api("/api/reports", {
    method: "POST",
    body: JSON.stringify({
      workspace_id: state.workspace.id,
      target,
      format: fmt,
    }),
  });
  const box = document.getElementById("report-links");
  box.innerHTML = `<div class="alert alert-success">Report ready:
    <a href="${res.url}" class="alert-link">${escapeHtml(res.filename)}</a></div>`;
  refreshReports();
}

document.addEventListener("DOMContentLoaded", () => {
  state.authModal = new bootstrap.Modal("#authModal");
  state.settingsModal = new bootstrap.Modal("#settingsModal");

  document.getElementById("btn-create-ws").onclick = async () => {
    const name = document.getElementById("new-ws-name").value.trim();
    const description = document.getElementById("new-ws-desc").value.trim();
    if (!name) return;
    const ws = await api("/api/workspaces", {
      method: "POST",
      body: JSON.stringify({ name, description }),
    });
    document.getElementById("new-ws-name").value = "";
    document.getElementById("new-ws-desc").value = "";
    openWorkspace(ws);
  };

  document.getElementById("btn-back-ws").onclick = showWorkspaces;
  document.getElementById("nav-home").onclick = (e) => { e.preventDefault(); showWorkspaces(); };
  document.getElementById("btn-run-scan").onclick = requestScan;
  document.getElementById("btn-reload-graph").onclick = refreshGraph;
  document.getElementById("btn-pdf").onclick = () => generateReport("pdf");
  document.getElementById("btn-json").onclick = () => generateReport("json");

  document.getElementById("btn-settings").onclick = async () => {
    await loadSettingsForm();
    state.settingsModal.show();
  };
  document.getElementById("btn-save-settings").onclick = saveSettings;

  document.getElementById("auth-confirm").onchange = (e) => {
    document.getElementById("btn-auth-continue").disabled = !e.target.checked;
  };
  document.getElementById("btn-auth-continue").onclick = () => {
    state.authModal.hide();
    beginScan(true);
  };

  document.querySelectorAll("#result-pills .nav-link").forEach((btn) => {
    btn.onclick = () => {
      document.querySelectorAll("#result-pills .nav-link").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      refreshFindings(btn.dataset.module || "");
    };
  });

  // Reload graph when tab shown (vis needs visible container)
  document.querySelector('[data-bs-target="#tab-graph"]')?.addEventListener("shown.bs.tab", refreshGraph);

  loadWorkspaces();
});
