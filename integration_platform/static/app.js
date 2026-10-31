/* PlugSec UI - plain JS, no build step, no CDN. */
"use strict";

const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const ENTITY_FIELDS = {  // overwritten from /api/meta at boot (single source of truth is the server)
  user: ["id", "name", "email", "status", "last_login"],
  device: ["id", "hostname", "ip", "os", "owner", "last_seen"],
  event: ["id", "type", "severity", "timestamp", "description", "host", "src_ip", "dst_ip", "user"],
};
const TIME_FIELD = { user: "last_login", device: "last_seen", event: "timestamp" };
const fmtN = (n) => Number(n || 0).toLocaleString();
const SEVERITIES = ["info", "low", "medium", "high", "critical"];
const ENV_REF = /^\$\{[A-Za-z_][A-Za-z0-9_]*\}$/;

const state = { tab: "alerts", meta: {}, integrations: [], names: {}, tick: 0, busy: false };

/* ------------------------------------------------------------------ helpers */
async function api(path, { method = "GET", body } = {}) {
  const res = await fetch(path, {
    method,
    headers: body !== undefined ? { "Content-Type": "application/json" } : {},
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (!res.ok) {
    const err = new Error(`HTTP ${res.status}`);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

function errorList(e) {
  const d = e && e.data;
  if (d && Array.isArray(d.errors)) return d.errors;
  if (d && typeof d.detail === "string") return [d.detail];
  if (d && Array.isArray(d.detail)) return d.detail.map((x) => `${(x.loc || []).slice(1).join(".")}: ${x.msg}`);
  return [e && e.message ? (e.message === "Failed to fetch" ? "Platform not reachable - is run_all.py running?" : e.message) : String(e)];
}

function toast(msg, kind = "") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = msg;
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), kind === "err" ? 7000 : 4000);
}

function fmtTime(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  if (isNaN(d)) return esc(iso);
  const sameDay = d.toDateString() === new Date().toDateString();
  return sameDay ? d.toLocaleTimeString() : `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
}

function ago(iso) {
  if (!iso) return "never";
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 0) return `in ${-s}s`;
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

const sevBadge = (s) => `<span class="sev ${esc(s)}">${esc(s)}</span>`;
const pretty = (o) => esc(JSON.stringify(o, null, 2));
const jiraUrl = () => state.meta.jira_board_url || "#";

function ticketLink(key) {
  return key ? `<a class="ticket" href="${esc(jiraUrl())}" target="_blank" title="Open the Jira board">${esc(key)}</a>` : `<span class="muted">-</span>`;
}

function openModal(title, html) {
  $("#modalTitle").textContent = title;
  $("#modalBody").innerHTML = html;
  $("#modal").classList.remove("hidden");
}
const closeModal = () => $("#modal").classList.add("hidden");

function storeGet(key, fallback) {
  try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; } catch { return fallback; }
}
function storeSet(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* storage unavailable */ }
}

/* ------------------------------------------------------------------ tabs + polling */
function showTab(tab) {
  state.tab = tab;
  $$(".tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  $$(".panel").forEach((p) => p.classList.toggle("active", p.id === `tab-${tab}`));
  storeSet("tab", tab);
  if (location.hash !== `#${tab}`) history.replaceState(null, "", `#${tab}`);
  if (tab === "wizard") renderWizard();
  refresh();
}

async function refresh() {
  if (state.busy) return;
  state.busy = true;
  try {
    if (state.tab === "alerts") {
      if (state.tick % 4 === 0 || !state.integrations.length) await loadIntegrations();
      await refreshAlerts();
    } else if (state.tab === "users" || state.tab === "devices") {
      if (state.tick % 4 === 0 || !state.integrations.length) await loadIntegrations();
      await refreshEntity(state.tab);
    } else if (state.tab === "integrations") {
      await loadIntegrations();
      renderIntegrations();
    } else if (state.tab === "actions") {
      await refreshActions();
    }
    $(".live").classList.remove("stale");
    $(".live").lastChild.textContent = "Live";
  } catch (e) {
    $(".live").classList.add("stale");
    $(".live").lastChild.textContent = "Disconnected";
  } finally {
    state.busy = false;
    state.tick++;
  }
}

async function loadIntegrations() {
  const data = await api("/api/integrations");
  state.integrations = data.items;
  state.loadErrors = data.load_errors || {};
  state.names = Object.fromEntries(data.items.map((i) => [i.name, i.display_name]));
  state.notifications = data.notifications || [];
  renderBanner();
  const options = ['<option value="">All sources</option>'].concat(
    data.items.map((i) => `<option value="${esc(i.name)}">${esc(i.display_name)}</option>`)).join("");
  $$(".src-filter").forEach((sel) => {
    if (sel.dataset.sig === options) return;
    const current = sel.value;
    sel.innerHTML = options;
    sel.dataset.sig = options;
    sel.value = current;
  });
}

/* B-4: repeated-failure alerts. Shown as a banner (always) - also sent to Slack / email when configured. */
function renderBanner() {
  const open = (state.notifications || []).filter((n) => n.kind === "failure_alert");
  const latest = {};
  (state.notifications || []).forEach((n) => { if (!(n.integration in latest)) latest[n.integration] = n; });
  const active = Object.values(latest).filter((n) => n.kind === "failure_alert");
  const box = $("#failureBanner");
  box.classList.toggle("hidden", !active.length);
  box.innerHTML = active.map((n) => `<div>🚨 <b>${esc(state.names[n.integration] || n.integration)}</b>: ${esc(n.message)}
    <span class="muted small">· ${esc(ago(n.created_at))} · sent to: ${esc(n.channels.join(", "))}</span></div>`).join("");
  return open;
}

/* ------------------------------------------------------------------ users / devices */
const ENTITY_TAB = {
  users: { entity: "user", api: "/api/users", cols: (u) => [esc(u.name || "-"), esc(u.email || "-"), u.status ? `<span class="chip">${esc(u.status)}</span>` : "-",
    fmtTime(u.last_login)] },
  devices: { entity: "device", api: "/api/devices", cols: (d) => [`<b>${esc(d.hostname || "-")}</b>`, `<span class="mono">${esc(d.ip || "-")}</span>`,
    esc(d.os || "-"), esc(d.owner || "-"), fmtTime(d.last_seen)] },
};

async function refreshEntity(tab) {
  const conf = ENTITY_TAB[tab];
  const q = new URLSearchParams({ limit: 200, source: $(`#f_${tab}`).value });
  const [data, st] = await Promise.all([api(`${conf.api}?${q}`), api("/api/stats")]);
  const counts = st[tab];
  $(`#${tab}Counters`).innerHTML = `<div class="counter"><div class="c-label">${tab}</div><div class="c-value">${fmtN(counts.total)}</div></div>`
    + Object.entries(counts.by_source).map(([src, n]) => `<div class="counter"><div class="c-label">${esc(state.names[src] || src)}</div><div class="c-value">${fmtN(n)}</div></div>`).join("");
  $(`#${tab}Meta`).textContent = `Showing ${data.items.length} of ${fmtN(data.total)} · one table, one schema, every source · refreshes every 3 s`;
  $(`#${tab}Empty`).classList.toggle("hidden", data.items.length > 0);
  $(`#${tab}Table tbody`).innerHTML = data.items.map((r) => `<tr>${conf.cols(r).map((c) => `<td>${c}</td>`).join("")}
    <td><span class="chip src">${esc(state.names[r.source] || r.source)}</span></td><td class="mono small">${esc(r.id)}</td>
    <td class="mono small nowrap">${fmtTime(r.fetched_at)}</td></tr>`).join("");
}

/* ------------------------------------------------------------------ alerts */
const alerts = { offset: 0, limit: 50, seen: new Set(), primed: false, expanded: new Set(), total: 0 };

async function refreshAlerts() {
  const q = new URLSearchParams({ limit: alerts.limit, offset: alerts.offset, source: $("#fSource").value, severity: $("#fSeverity").value });
  const [ev, st] = await Promise.all([api(`/api/events?${q}`), api("/api/stats")]);
  $("#cTotal").textContent = fmtN(st.events.total);
  $("#cCritical").textContent = st.critical;
  $("#cHigh").textContent = st.high;
  $("#cTools").textContent = `${st.tools_connected}/${st.tools_total}`;
  $("#cTickets").textContent = st.tickets;
  alerts.total = ev.total;
  const from = ev.total ? alerts.offset + 1 : 0;
  $("#alertsMeta").textContent = `Showing ${from}-${alerts.offset + ev.items.length} of ${ev.total} · refreshes every 3 s`;
  $("#prevPage").disabled = alerts.offset === 0;
  $("#nextPage").disabled = alerts.offset + alerts.limit >= ev.total;
  $("#alertsEmpty").classList.toggle("hidden", ev.items.length > 0);

  const rows = ev.items.map((e) => {
    const key = `${e.source}|${e.id}`;
    const fresh = alerts.primed && !alerts.seen.has(key);
    alerts.seen.add(key);
    const where = e.host || e.src_ip || "-";
    const dst = e.dst_ip ? ` <span class="muted">→ ${esc(e.dst_ip)}</span>` : "";
    let html = `<tr class="clickable ${fresh ? "fresh" : ""}" data-key="${esc(key)}">
      <td class="nowrap mono">${fmtTime(e.timestamp)}</td>
      <td><span class="chip src">${esc(state.names[e.source] || e.source)}</span></td>
      <td>${sevBadge(e.severity)}</td>
      <td class="mono small">${esc(e.type)}</td>
      <td>${esc(e.description)}</td>
      <td class="mono nowrap">${esc(where)}${dst}</td>
      <td class="mono">${esc(e.user || "-")}</td>
      <td>${ticketLink(e.ticket_key)}</td>
      <td class="mono small nowrap">${fmtTime(e.fetched_at)}</td></tr>`;
    if (alerts.expanded.has(key)) {
      const { raw, ...norm } = e;
      html += `<tr class="raw-row"><td colspan="9"><div class="split" style="margin:0">
        <div><div class="box-title">Raw record from ${esc(e.source)}</div><div class="box"><pre class="json">${pretty(raw)}</pre></div></div>
        <div><div class="box-title">Normalised (common schema)</div><div class="box"><pre class="json">${pretty(norm)}</pre></div></div>
      </div></td></tr>`;
    }
    return html;
  });
  alerts.primed = true;
  $("#alertsTable tbody").innerHTML = rows.join("");
}

/* ------------------------------------------------------------------ integrations */
function renderIntegrations() {
  const cards = state.integrations.map((i) => {
    const h = i.health;
    const lr = h.last_run || {};
    const err = h.last_error && h.status !== "not_configured"
      ? `<div class="error-box"><span class="when">Last error · ${esc(ago(h.last_error.at))}</span>${esc(h.last_error.error)}</div>` : "";
    const c = h.counts || {};
    const countText = ["users", "devices", "events"].filter((k) => c[k]).map((k) => `${fmtN(c[k])} ${k}`).join(", ") || "no records yet";
    const headline = `${h.summary}${lr.finished_at ? `, ${ago(lr.finished_at)}` : ""}, ${countText}`;
    const streamChips = (i.streams || []).map((s) => `<span class="chip" title="${esc(s.endpoint)}">${esc(s.name)} → ${esc(s.entity)} · ${esc(s.pagination)}</span>`).join("");
    const notConfigured = h.status === "not_configured"
      ? `<div class="notice-box">Not configured: set ${h.missing.map((m) => `<code>${esc(m)}</code>`).join(", ")} in <code>.env</code> (or store them in the vault), then Run now.</div>` : "";
    const lastStreams = ((lr.detail || {}).streams || []).filter((s) => s.status && s.status !== "ok");
    return `<div class="card ${h.colour}">
      <div class="card-head">
        <span class="dot ${h.colour}"></span>
        <div><div class="card-title">${esc(i.display_name)}</div><div class="card-sub">${esc(i.name)} · ${esc(i.base_url)}</div></div>
        <span class="health-label ${h.colour}">${esc(h.running ? "Running…" : h.summary)}</span>
      </div>
      <div class="headline">${esc(i.display_name)}: ${esc(headline)}</div>
      <div><span class="chip">auth: ${esc(i.auth_type)}</span><span class="chip">every ${i.schedule_seconds >= 60 ? `${i.schedule_seconds / 60} min` : `${i.schedule_seconds}s`}</span>${i.seeded ? "" : '<span class="chip src">added live</span>'}</div>
      <div class="chip-row">${streamChips}</div>
      ${notConfigured}
      <div class="stats">
        <div class="stat"><div class="k">Last run</div><div class="v">${lr.records_fetched ?? "-"}</div></div>
        <div class="stat"><div class="k">Users</div><div class="v">${fmtN(c.users)}</div></div>
        <div class="stat"><div class="k">Devices</div><div class="v">${fmtN(c.devices)}</div></div>
        <div class="stat"><div class="k">Events</div><div class="v">${fmtN(c.events)}</div></div>
      </div>
      ${lastStreams.length ? `<div class="meta-line">${lastStreams.map((s) => `<span>${esc(s.name)}: ${esc(s.status)}</span>`).join("")}</div>` : ""}
      <div class="meta-line">
        <span>Last run: <b>${esc(ago(lr.finished_at))}</b> ${lr.status ? `(${esc(lr.status)})` : ""}</span>
        <span>Next: ${esc(h.next_run ? ago(h.next_run) : "-")}</span>
        <span>Pages: ${lr.pages ?? "-"} · retries: ${lr.retries ?? 0} (total ${h.totals.retries}) · runs: ${h.totals.runs} · failed: ${h.totals.errors}</span>
        ${h.failure_streak ? `<span class="status-bad">${h.failure_streak} consecutive failure(s)${h.failure_alerted ? " · alert sent" : ""}</span>` : ""}
      </div>
      ${err}
      ${(h.warnings || []).length || (i.scopes || []).length ? `<div class="chip-row">
        ${(i.scopes || []).map((s) => `<span class="chip ${i.risky_scopes.includes(s) ? "bad" : ""}" title="credential scope">🔑 ${esc(s)}</span>`).join("")}
        ${(h.warnings || []).map((w) => `<span class="chip ${w.kind === "scope" ? "bad" : "warn"}">⚠ ${esc(w.text)}</span>`).join("")}</div>` : ""}
      ${h.status === "suspicious" ? `<div class="error-box"><span class="when">Exfiltration guard · ${esc(ago(h.state.since))}</span>
        Pulled ${h.state.detail.records} records in one run: ${h.state.detail.ratio}x the baseline of ${h.state.detail.baseline} (threshold ${h.state.detail.threshold}).
        Connector paused; a critical alert was raised.</div>` : ""}
      ${h.status === "revoked" ? `<div class="error-box"><span class="when">Revoked · ${esc(ago(h.state.since))}</span>
        Stored secret(s) wiped: ${esc((h.state.detail.secrets || []).join(", "))}. Store a new secret to reconnect.</div>` : ""}
      ${h.quarantined_total ? `<div class="chip-row"><span class="chip warn">⚠ ${h.quarantined_total} quarantined${lr.records_quarantined ? ` (${lr.records_quarantined} in last run)` : ""}</span>
        <button class="btn small ghost" data-act="quarantine" data-name="${esc(i.name)}">View</button></div>` : ""}
      <div class="card-actions">
        ${h.status === "suspicious" ? `
        <button class="btn small danger" data-act="review" data-name="${esc(i.name)}">🔍 Review</button>
        <button class="btn small" data-act="resume" data-name="${esc(i.name)}">Resume</button>
        <button class="btn small danger" data-act="revoke" data-name="${esc(i.name)}">Revoke</button>` : h.status === "revoked" ? "" : `
        <button class="btn small" data-act="run" data-name="${esc(i.name)}" ${i.enabled && h.status !== "not_configured" ? "" : "disabled"}>▶ Run now</button>
        <button class="btn small" data-act="${i.enabled ? "disable" : "enable"}" data-name="${esc(i.name)}">${i.enabled ? "Disable" : "Enable"}</button>`}
        <button class="btn small ghost" data-act="view" data-name="${esc(i.name)}">View config</button>
        ${i.seeded ? "" : `<button class="btn small danger" data-act="delete" data-name="${esc(i.name)}">Delete</button>`}
      </div>
    </div>`;
  });
  $("#integrationCards").innerHTML = cards.join("") || '<div class="empty">No integrations yet.</div>';
  const errs = Object.entries(state.loadErrors || {});
  $("#loadErrors").classList.toggle("hidden", !errs.length);
  $("#loadErrors").innerHTML = errs.map(([file, list]) =>
    `<div class="error-box"><span class="when">Config file ${esc(file)} could not be loaded</span>${list.map(esc).join("<br>")}</div>`).join("");
}

async function integrationAction(act, name) {
  try {
    if (act === "run") {
      toast(`Running ${state.names[name] || name}…`);
      const r = await api(`/api/integrations/${name}/run`, { method: "POST" });
      if (r.status === "success" || r.status === "partial") {
        const waits = (r.retry_log || []).filter((l) => l.includes("waited")).join("; ");
        toast(`${state.names[name]}: ${r.records_fetched} records (${r.records_new} new) in ${r.pages} page(s)${r.quarantined ? `, ${r.quarantined} quarantined` : ""}${r.retries ? `, ${r.retries} retr${r.retries === 1 ? "y" : "ies"}` : ""}${waits ? ` (${waits})` : ""}`, r.status === "success" ? "ok" : "err");
      } else {
        toast(`${state.names[name]}: ${r.error}`, "err");
      }
    } else if (act === "enable" || act === "disable") {
      await api(`/api/integrations/${name}/${act}`, { method: "POST" });
      toast(`${state.names[name]} ${act}d`, "ok");
    } else if (act === "delete") {
      if (!confirm(`Delete integration "${state.names[name] || name}"? Its stored events stay.`)) return;
      await api(`/api/integrations/${name}`, { method: "DELETE" });
      toast("Integration deleted", "ok");
    } else if (act === "resume") {
      await api(`/api/integrations/${name}/resume`, { method: "POST" });
      closeModal();
      toast(`${state.names[name]} resumed`, "ok");
    } else if (act === "revoke") {
      if (!confirm(`Revoke ${state.names[name] || name}? This disables the connector and wipes its stored secret(s) from the vault.`)) return;
      const r = await api(`/api/integrations/${name}/revoke`, { method: "POST" });
      closeModal();
      toast(`${state.names[name]} revoked - wiped ${r.wiped_secrets.join(", ")}`, "ok");
    } else if (act === "review") {
      const d = await api(`/api/integrations/${name}`);
      const g = d.health.state.detail, ev = d.guard_event;
      const runs = d.recent_runs.map((r) => `<tr class="${r.status === "suspicious" ? "raw-row" : ""}"><td class="mono nowrap">${fmtTime(r.started_at)}</td>
        <td class="${r.status === "success" ? "status-ok" : "status-bad"}">${esc(r.status)}</td><td>${r.records_fetched}</td><td>${r.pages}</td></tr>`).join("");
      openModal(`Review: ${d.display_name} flagged SUSPICIOUS`, `
        <div class="error-box" style="font-size:13px">One run pulled <b>${g.records}</b> records: <b>${g.ratio}x</b> the rolling baseline of ${g.baseline}
          (median of the last ${g.baseline_runs} runs; threshold ${g.threshold} = max(min_records, ${g.multiplier}x baseline)).
          This is the pattern of a stolen token being used for a bulk export (cf. the 2025 Salesloft Drift OAuth-token breach).</div>
        <p>Alert: ${ev ? `${sevBadge(ev.severity)} ${esc(ev.description)} ${ticketLink(ev.ticket_key)}` : "-"}</p>
        <div class="box-title">Recent runs</div>
        <div class="table-wrap"><table class="grid"><thead><tr><th>Started</th><th>Status</th><th>Records</th><th>Pages</th></tr></thead><tbody>${runs}</tbody></table></div>
        <div class="card-actions" style="margin-top:14px">
          <button class="btn" data-act="resume" data-name="${esc(name)}">Resume (false positive)</button>
          <button class="btn danger" data-act="revoke" data-name="${esc(name)}">Revoke token</button></div>`);
      return;
    } else if (act === "quarantine") {
      const q = await api(`/api/integrations/${name}/quarantine`);
      const rows = q.items.map((r) => `<tr><td class="mono nowrap">${fmtTime(r.created_at)}</td><td class="mono small">${esc(r.stream || "")}</td><td class="status-bad">${esc(r.reason)}</td>
        <td><pre class="json">${pretty(r.raw)}</pre></td></tr>`).join("");
      openModal(`${state.names[name] || name} - ${q.total} quarantined record(s)`,
        `<p class="muted">Records that failed validation are parked here with the reason; the run continues and good records are still ingested.</p>
        <div class="table-wrap"><table class="grid"><thead><tr><th>When</th><th>Stream</th><th>Reason</th><th>Raw record</th></tr></thead><tbody>${rows}</tbody></table></div>`);
      return;
    } else if (act === "view") {
      const d = await api(`/api/integrations/${name}`);
      const runs = d.recent_runs.map((r) => `<tr><td class="mono nowrap">${fmtTime(r.started_at)}</td>
        <td class="${r.status === "error" ? "status-bad" : "status-ok"}">${esc(r.status)}</td><td>${r.records_fetched}</td><td>${r.records_new}</td>
        <td>${r.pages}</td><td>${r.retries}</td><td class="mono small">${esc(r.error || "")}</td></tr>`).join("");
      openModal(`${d.display_name} - config`, `<pre class="yaml">${esc(d.yaml)}</pre>
        <div class="box-title">Recent runs</div>
        <div class="table-wrap"><table class="grid"><thead><tr><th>Started</th><th>Status</th><th>Fetched</th><th>New</th><th>Pages</th><th>Retries</th><th>Error</th></tr></thead>
        <tbody>${runs || '<tr><td colspan="7" class="muted">No runs yet</td></tr>'}</tbody></table></div>`);
      return;
    }
  } catch (e) {
    toast(errorList(e).join("; "), "err");
  }
  await loadIntegrations();
  if (state.tab === "integrations") renderIntegrations();
}

/* ------------------------------------------------------------------ actions tab */
async function refreshActions() {
  const [acts, res] = await Promise.all([api("/api/actions"), api("/api/actions/results?limit=100")]);
  if (!state.integrations.length) await loadIntegrations();
  state.actions = acts.items;
  $("#actionCards").innerHTML = acts.items.map((a) => `<div class="card">
      <div class="card-head"><span class="dot ${a.enabled ? "green" : "grey"}"></span>
        <div><div class="card-title">${esc(a.display_name)}</div><div class="card-sub">${esc(a.name)} → ${esc(a.target)}</div></div>
        <span class="health-label ${a.enabled ? "green" : "grey"}">${a.enabled ? "Enabled" : "Disabled"}</span></div>
      <div>${Object.entries(a.when).map(([k, v]) => `<span class="chip">${esc(k)}: ${esc([].concat(v).join(", "))}</span>`).join("") || '<span class="chip">every event</span>'}</div>
      <div class="stats" style="grid-template-columns:repeat(2,1fr)">
        <div class="stat"><div class="k">Succeeded</div><div class="v">${a.stats.success}</div></div>
        <div class="stat"><div class="k">Failed</div><div class="v ${a.stats.failed ? "warn" : ""}">${a.stats.failed}</div></div>
      </div>
      <div class="card-actions"><button class="btn small ghost" data-yaml="${esc(a.name)}">View config</button>
        <a class="btn small ghost" href="${esc(jiraUrl())}" target="_blank">Jira board ↗</a></div>
    </div>`).join("") || '<div class="empty">No actions configured.</div>';
  $("#resultsEmpty").classList.toggle("hidden", res.items.length > 0);
  $("#resultsTable tbody").innerHTML = res.items.map((r) => `<tr>
      <td class="mono nowrap">${fmtTime(r.created_at)}</td><td>${esc(r.action)}</td>
      <td class="mono small">${esc(state.names[r.event_source] || r.event_source)} · ${esc(r.event_id)}</td>
      <td class="${r.status === "success" ? "status-ok" : "status-bad"}">${esc(r.status)}</td>
      <td>${ticketLink(r.ticket_key)}</td><td>${r.attempts}</td><td class="mono small">${esc(r.error || "")}</td></tr>`).join("");
}

/* ================================================================== WIZARD */
const STEPS = [
  { id: "basics", title: "Basics", prefixes: ["name", "display_name", "base_url", "schedule_seconds", "enabled"] },
  { id: "auth", title: "Auth", prefixes: ["auth", "scopes"] },
  { id: "request", title: "Request", prefixes: ["streams.0.endpoint", "streams.0.method", "streams.0.params", "streams.0.name"] },
  { id: "pagination", title: "Pagination", prefixes: ["streams.0.pagination"] },
  { id: "mapping", title: "Mapping", prefixes: ["streams.0.mapping", "streams.0.records_path", "streams.0.transforms", "streams.0.entity", "streams.0"] },
  { id: "test", title: "Test", prefixes: [] },
  { id: "save", title: "Save", prefixes: [] },
];

const AUTH_DEFAULTS = {
  none: { type: "none" },
  bearer: { type: "bearer", token: "" },
  api_key: { type: "api_key", header: "X-API-Key", api_key: "" },
  basic: { type: "basic", username: "", password: "" },
  oauth2_client_credentials: { type: "oauth2_client_credentials", token_url: "/oauth2/v1/token", client_id: "", client_secret: "" },
};
const PAGINATION_DEFAULTS = {
  none: { type: "none" },
  page: { type: "page", page_param: "page", size_param: "page_size", page_size: 10, total_pages_path: "", max_pages: 10 },
  offset: { type: "offset", limit_param: "limit", offset_param: "offset", limit: 10, max_pages: 10 },
  cursor: { type: "cursor", cursor_path: "", cursor_param: "cursor", max_pages: 10 },
  link: { type: "link", next_path: "", max_pages: 10 },
};
const copy = (o) => JSON.parse(JSON.stringify(o));

const ENTITY_STREAM_NAME = { user: "users", device: "devices", event: "events" };
const newStream = (entity = "event") => ({
  name: ENTITY_STREAM_NAME[entity], entity, endpoint: "/", method: "GET", params: {},
  pagination: copy(PAGINATION_DEFAULTS.none), records_path: "", mapping: {},
  transforms: { severity_map: {}, time_format: "iso8601" },
});

function newDraft() {
  return {
    name: "", display_name: "", enabled: true, base_url: "https://",
    auth: copy(AUTH_DEFAULTS.none),
    schedule_seconds: 900,
    retry: { max_retries: 3, backoff: "exponential", base_seconds: 1 },
    streams: [newStream()],
  };
}
/** The stream the wizard edits (a config may hold more; edit those in the YAML panel). */
const S = () => wiz.draft.streams[0];

const savedWiz = storeGet("wizard", null);
const wiz = (savedWiz && savedWiz.draft && Array.isArray(savedWiz.draft.streams) ? savedWiz : null) || { step: 0, maxStep: 0, draft: newDraft(), sample: "", suggestion: null, test: null, saved: null };

/** Guarantee the nested objects the form binds to exist (YAML edits may remove them). */
function ensureShape(d) {
  const base = newDraft();
  for (const k of ["auth", "retry"]) if (typeof d[k] !== "object" || d[k] === null || Array.isArray(d[k])) d[k] = base[k];
  if (!Array.isArray(d.streams) || !d.streams.length || typeof d.streams[0] !== "object") d.streams = [newStream()];
  const st = d.streams[0];
  const fresh = newStream(ENTITY_FIELDS[st.entity] ? st.entity : "event");
  for (const k of ["params", "pagination", "mapping", "transforms"]) if (typeof st[k] !== "object" || st[k] === null || Array.isArray(st[k])) st[k] = fresh[k];
  if (typeof st.transforms.severity_map !== "object" || st.transforms.severity_map === null) st.transforms.severity_map = {};
  for (const k of ["name", "entity", "endpoint", "method"]) if (!st[k]) st[k] = fresh[k];
  if (!d.auth.type) d.auth.type = "none";
  if (!st.pagination.type) st.pagination.type = "none";
  return d;
}

const getPath = (o, path) => path.split(".").reduce((a, k) => (a == null ? undefined : a[k]), o);
function setPath(o, path, value) {
  const keys = path.split(".");
  let node = o;
  keys.slice(0, -1).forEach((k) => { if (typeof node[k] !== "object" || node[k] === null) node[k] = {}; node = node[k]; });
  const last = keys[keys.length - 1];
  if (value === undefined) delete node[last]; else node[last] = value;
}

/** Copy of the draft without empty values: what we send to the server and show as YAML. */
function clean(v) {
  if (Array.isArray(v)) return v.map(clean);
  if (v && typeof v === "object") {
    const out = {};
    for (const [k, val] of Object.entries(v)) {
      const c = clean(val);
      if (c === "" || c === null || c === undefined) continue;
      if (typeof c === "object" && !Array.isArray(c) && !Object.keys(c).length && k !== "mapping") continue;
      out[k] = c;
    }
    return out;
  }
  return v;
}

/* ---------- tiny YAML dumper (parsing is done server-side by PyYAML) ---------- */
function yScalar(v) {
  if (v === null || v === undefined) return "null";
  if (typeof v === "boolean" || typeof v === "number") return String(v);
  const s = String(v);
  const needsQuote = s === "" || /^\s|\s$/.test(s) || /[:#{}[\],&*!|>'"%@`\\]/.test(s) || s.startsWith("-") || s.startsWith("?")
    || /^(true|false|null|yes|no|on|off|~)$/i.test(s) || /^[-+]?(\d[\d_]*)?(\.\d+)?([eE][-+]?\d+)?$/.test(s) || s.includes("${");
  return needsQuote ? JSON.stringify(s) : s;
}
const yKey = (k) => (/^[A-Za-z_][\w-]*$/.test(k) && !/^(true|false|null|yes|no|on|off)$/i.test(k) ? k : JSON.stringify(k));
const isObj = (v) => v && typeof v === "object" && !Array.isArray(v);
function yamlLines(obj, depth) {
  const pad = "  ".repeat(depth);
  const out = [];
  for (const [k, v] of Object.entries(obj)) {
    if (isObj(v)) {
      if (!Object.keys(v).length) out.push(`${pad}${yKey(k)}: {}`);
      else { out.push(`${pad}${yKey(k)}:`); out.push(...yamlLines(v, depth + 1)); }
    } else if (Array.isArray(v)) {
      if (!v.length) out.push(`${pad}${yKey(k)}: []`);
      else {
        out.push(`${pad}${yKey(k)}:`);
        v.forEach((x) => {
          if (isObj(x) && Object.keys(x).length) {
            // block style: "- first: value" then the other keys aligned under it (e.g. streams)
            const inner = yamlLines(x, depth + 2);
            out.push(`${pad}  - ${inner[0].trimStart()}`, ...inner.slice(1));
          } else out.push(`${pad}  - ${isObj(x) || Array.isArray(x) ? JSON.stringify(x) : yScalar(x)}`);
        });
      }
    } else out.push(`${pad}${yKey(k)}: ${yScalar(v)}`);
  }
  return out;
}
const toYaml = (obj) => yamlLines(obj, 0).join("\n") + "\n";

function saveWizard() { storeSet("wizard", wiz); }

function syncYaml(force = false) {
  const ed = $("#yamlEditor");
  if (force || document.activeElement !== ed) {
    ed.value = toYaml(clean(wiz.draft));
    $("#yamlStatus").textContent = "in sync";
    $("#yamlStatus").classList.remove("err");
  }
  saveWizard();
}

let yamlTimer = null;
function onYamlInput() {
  $("#yamlStatus").textContent = "parsing…";
  $("#yamlStatus").classList.remove("err");
  clearTimeout(yamlTimer);
  yamlTimer = setTimeout(async () => {
    try {
      const r = await api("/api/convert", { method: "POST", body: { yaml: $("#yamlEditor").value } });
      wiz.draft = ensureShape(Object.assign(newDraftShell(), r.config));
      $("#yamlStatus").textContent = "in sync";
      renderStep();
      saveWizard();
    } catch (e) {
      $("#yamlStatus").textContent = errorList(e)[0];
      $("#yamlStatus").classList.add("err");
    }
  }, 450);
}
/* Keys the form always expects, in display order, without default values that YAML removed on purpose. */
const newDraftShell = () => ({ name: "", display_name: "" });

/* ---------- field renderers ---------- */
function input(path, label, { type = "text", placeholder = "", hint = "", full = false, secret = false } = {}) {
  let v = getPath(wiz.draft, path);
  if (Array.isArray(v)) v = v.join(", ");
  const secretErr = secret && v && !ENV_REF.test(v) ? "Use an environment variable reference like ${OKTA_CLIENT_SECRET}. Never paste the secret itself." : "";
  return `<div class="field ${full ? "full" : ""}"><label for="f_${path}">${esc(label)}</label>
    <input id="f_${path}" data-path="${path}" data-type="${type}" type="${type === "number" ? "number" : "text"}" value="${esc(v ?? "")}" placeholder="${esc(placeholder)}" ${secret ? 'data-secret="1" autocomplete="off"' : ""} class="${secretErr ? "invalid" : ""}">
    ${hint ? `<span class="hint">${hint}</span>` : ""}<span class="err" data-err-for="${path}">${esc(secretErr)}</span>
    ${secret ? `<button class="btn small ghost" type="button" data-store-secret="${path}" style="align-self:flex-start">🔒 Store a value in the vault…</button>` : ""}</div>`;
}

function select(path, label, options, { full = false, switchKind = "", hint = "" } = {}) {
  const v = getPath(wiz.draft, path);
  return `<div class="field ${full ? "full" : ""}"><label>${esc(label)}</label>
    <select data-path="${path}" ${switchKind ? `data-switch="${switchKind}"` : ""}>
      ${options.map((o) => { const [val, text] = Array.isArray(o) ? o : [o, o]; return `<option value="${esc(val)}" ${val === v ? "selected" : ""}>${esc(text)}</option>`; }).join("")}
    </select>${hint ? `<span class="hint">${hint}</span>` : ""}</div>`;
}

function kvEditor(path, label, { keyPh = "key", valPh = "value", valueOptions = null } = {}) {
  const obj = getPath(wiz.draft, path) || {};
  const rows = Object.entries(obj).concat([["", ""]]);
  return `<div class="field full"><label>${esc(label)}</label><div class="kv" data-kv="${path}">
    ${rows.map(([k, v]) => `<div class="kv-row">
      <input data-kv-key value="${esc(k)}" placeholder="${esc(keyPh)}">
      ${valueOptions
        ? `<select data-kv-val><option value=""></option>${valueOptions.map((o) => `<option ${o === v ? "selected" : ""}>${o}</option>`).join("")}</select>`
        : `<input data-kv-val value="${esc(v)}" placeholder="${esc(valPh)}">`}
      <button class="btn small ghost" data-kv-del title="Remove">✕</button></div>`).join("")}
  </div></div>`;
}

/* ---------- steps ---------- */
function stepBasics() {
  return `<h3>Basics</h3><p class="lead">Name the tool and point at its API.</p><div class="form-grid">
    ${input("display_name", "Display name", { placeholder: "Mock Okta" })}
    ${input("name", "Integration id", { placeholder: "okta", hint: "lowercase, digits, underscores - used as the event source" })}
    ${input("base_url", "Base URL", { placeholder: "https://www.cisa.gov", full: true, hint: "May reference .env, e.g. https://${OKTA_DOMAIN}" })}
    ${input("schedule_seconds", "Run every (seconds)", { type: "number", placeholder: "900", hint: "900 = every 15 minutes" })}
    ${select("enabled", "Start enabled", [["true", "Yes"], ["false", "No"]])}
  </div>`;
}

function stepAuth() {
  const t = wiz.draft.auth.type;
  const fields = {
    none: `<p class="hint-line field full">No credentials - for public feeds.</p>`,
    bearer: input("auth.token", "Token", { secret: true, placeholder: "${MY_TOOL_TOKEN}", full: true, hint: "Sent as <code>Authorization: Bearer …</code>" }),
    api_key: input("auth.header", "Header name", { placeholder: "X-API-Key" }) + input("auth.api_key", "API key", { secret: true, placeholder: "${MY_TOOL_API_KEY}" }),
    basic: input("auth.username", "Username", { placeholder: "${MY_TOOL_USER}", hint: "Plain value or ${VAR}" }) + input("auth.password", "Password", { secret: true, placeholder: "${MY_TOOL_PASSWORD}" }),
    oauth2_client_credentials: input("auth.token_url", "Token URL", { placeholder: "/oauth2/v1/token", hint: "Full URL or path on the base URL" })
      + input("auth.client_id", "Client id", { placeholder: "${OKTA_CLIENT_ID}" })
      + input("auth.client_secret", "Client secret", { secret: true, placeholder: "${OKTA_CLIENT_SECRET}" }),
  }[t] || "";
  return `<h3>Authentication</h3><p class="lead">Secrets are never stored here: reference an environment variable from <code>.env</code>, e.g. <code>\${OKTA_CLIENT_SECRET}</code>.</p>
    <div class="form-grid">${select("auth.type", "Auth type", [["none", "None (public)"], ["bearer", "Bearer token"], ["api_key", "API key header"], ["basic", "Basic auth"], ["oauth2_client_credentials", "OAuth2 client credentials"]], { full: true, switchKind: "auth" })}
    ${fields}
    ${input("scopes", "Scopes (comma-separated)", { type: "list", full: true, placeholder: "okta.logs.read", hint: "Permissions this credential holds. Least privilege: read-only scopes. For OAuth2 they are requested at the token endpoint." })}
    <div class="field full" id="scopeBadge">${scopeBadge()}</div>
    </div>`;
}

const RISKY_SCOPE = /write|admin|manage|delete|owner|root|modify|put|create|update|full|\*|^api$/i;
function scopeBadge() {
  const risky = (wiz.draft.scopes || []).filter((s) => RISKY_SCOPE.test(s));
  return risky.length ? `<span class="chip bad">⚠ Write/admin scope: ${esc(risky.join(", "))}. A log connector should be read-only.</span>` : "";
}

function stepRequest() {
  return `<h3>Request</h3><p class="lead">Which endpoint returns the records? Use <code>{{ last_sync }}</code> in a param for incremental sync (B-1).</p><div class="form-grid">
    ${input("streams.0.endpoint", "Endpoint path", { placeholder: "/api/v1/logs", full: true })}
    ${select("streams.0.method", "Method", ["GET", "POST"])}
    ${input("streams.0.name", "Stream name", { placeholder: "events", hint: "One config can hold several streams (users, events...)" })}
    ${kvEditor("streams.0.params", "Query params (optional)", { keyPh: "since", valPh: "{{ last_sync }}" })}
  </div>`;
}

function stepPagination() {
  const t = S().pagination.type;
  const fields = {
    none: `<p class="hint-line field full">Single request per run.</p>`,
    page: input("streams.0.pagination.page_param", "Page param", { placeholder: "page" }) + input("streams.0.pagination.size_param", "Page-size param", { placeholder: "page_size" })
      + input("streams.0.pagination.page_size", "Page size", { type: "number" }) + input("streams.0.pagination.total_pages_path", "Total pages path (optional)", { placeholder: "total_pages", hint: "JMESPath in the response" }),
    offset: input("streams.0.pagination.limit_param", "Limit param", { placeholder: "limit" }) + input("streams.0.pagination.offset_param", "Offset param", { placeholder: "offset" })
      + input("streams.0.pagination.limit", "Page size (limit)", { type: "number" }) + input("streams.0.pagination.total_path", "Total count path (optional)", { placeholder: "totalResults" }),
    cursor: input("streams.0.pagination.cursor_path", "Cursor path in response", { placeholder: "meta.next_cursor", hint: "JMESPath; stops when empty/null" }) + input("streams.0.pagination.cursor_param", "Cursor query param", { placeholder: "cursor" }),
    link: input("streams.0.pagination.next_path", "Next URL path in body (optional)", { placeholder: "links.next", full: true, hint: 'Empty = follow the <code>Link: &lt;…&gt;; rel="next"</code> header (Okta, GitHub style). Links to other hosts are refused.' }),
  }[t] || "";
  return `<h3>Pagination</h3><p class="lead">How does the API split results across pages?</p><div class="form-grid">
    ${select("streams.0.pagination.type", "Pagination type", [["none", "None"], ["page", "Page number"], ["offset", "Limit / offset"], ["cursor", "Cursor / token"], ["link", "Next link (Link header)"]], { switchKind: "pagination" })}
    ${t === "none" ? "" : input("streams.0.pagination.max_pages", "Max pages per run", { type: "number" })}
    ${fields}</div>`;
}

function confBar(c) {
  const pct = Math.round((c || 0) * 100);
  const colour = c >= 0.8 ? "var(--green)" : c >= 0.5 ? "var(--amber)" : "var(--red)";
  return `<div class="conf"><div class="conf-bar"><span style="width:${pct}%;background:${colour}"></span></div><span class="small mono">${pct}%</span></div>`;
}

function stepMapping() {
  const s = wiz.suggestion;
  const paths = s ? s.available_paths.map((p) => p.path) : [];
  const datalist = `<datalist id="pathOptions">${paths.map((p) => `<option value="${esc(p)}">`).join("")}</datalist>`;
  let ai = "";
  if (s) {
    const isAi = s.engine.startsWith("AI");
    const hint = s.pagination_hint || {};
    const showHint = hint.type && hint.type !== S().pagination.type;
    ai = `<div class="ai-box">
      <div class="ai-head"><span class="engine-badge ${isAi ? "ai" : "rules"}">${esc(s.engine)}</span>
        <span class="muted small">${esc(s.fallback_reason || "")}</span><span class="spacer"></span>
        <span class="small muted">records_path: <code>${esc(s.records_path || "(root list)")}</code> · ${s.record_count} records · time: <code>${esc(s.time_format)}</code></span></div>
      ${showHint ? `<div class="hint-line">Pagination hint: <b>${esc(hint.type)}</b> - ${esc((hint.evidence || []).join(" "))} <button class="btn small" id="applyPagination">Use ${esc(hint.type)} pagination</button></div>` : ""}
      <table class="grid mapping-table"><thead><tr><th>Common field</th><th>← Tool field</th><th>Example</th><th>Confidence</th><th></th></tr></thead><tbody>
      ${s.fields.map((f, i) => {
        const tag = f.status === "needs_manual" ? '<span class="tag manual">needs manual</span>'
          : f.status === "low_confidence" ? `<span class="tag warn" title="${esc(f.note)}">check</span>` : `<span class="tag ${f.source === "ai" ? "ai" : "rules"}">${f.source === "ai" ? "AI" : "rules"}</span>`;
        return `<tr><td class="mono">${f.field}</td><td><input list="pathOptions" data-sugg="${i}" value="${esc(f.path)}" placeholder="(not mapped)"></td>
          <td class="mono small">${esc(f.example === undefined || f.example === null ? "" : JSON.stringify(f.example))}</td><td>${confBar(f.confidence)}</td><td>${tag}</td></tr>`;
      }).join("")}</tbody></table>
      ${s.entity === "event" ? `<div class="hint-line">Severity map: <code>${esc(JSON.stringify(s.severity_map))}</code>${s.default_severity ? ` · default severity: <b>${esc(s.default_severity)}</b>` : ""}</div>` : ""}
      ${(s.notes || []).map((n) => `<div class="hint-line">Note: ${esc(n)}</div>`).join("")}
      <button class="btn primary" id="applySuggestion">✓ Apply to config</button> <span class="muted small">AI suggests, code verifies every path against the sample, you approve.</span>
    </div>`;
  }
  const st = S();
  const entity = st.entity;
  return `<h3>Field mapping</h3><p class="lead">Pick the common-schema entity, fetch (or paste) one sample response, let the assistant suggest the mapping, then review.</p>
    ${datalist}
    <div class="form-grid">${select("streams.0.entity", "This stream fills the common table", [["event", "Events / alerts"], ["user", "Users"], ["device", "Devices"]], { switchKind: "entity", full: true,
      hint: `Fields: ${ENTITY_FIELDS[entity].join(", ")} (+ source, fetched_at automatically)` })}</div>
    <div class="field full"><label>Sample API response (JSON)</label><textarea id="sampleInput" class="sample-area" spellcheck="false" placeholder='{"data": [...]}'>${esc(wiz.sample)}</textarea></div>
    <div style="display:flex;gap:8px;margin-top:8px"><button class="btn" id="fetchSample">⇣ Fetch sample from API</button><button class="btn primary" id="suggestBtn">✦ Suggest mapping</button></div>
    ${ai}
    <h3 style="margin-top:18px">Mapping (saved in config)</h3>
    <div class="form-grid">
      ${input("streams.0.records_path", "Records path", { placeholder: "data.alerts", hint: "JMESPath to the list of records; empty = response is the list" })}
      ${select("streams.0.transforms.time_format", `Time format (${TIME_FIELD[entity]})`, [["iso8601", "ISO 8601"], ["epoch_s", "Epoch seconds"], ["epoch_ms", "Epoch milliseconds"]])}
      ${ENTITY_FIELDS[entity].map((f) => `<div class="field"><label>${f}</label><input list="pathOptions" data-path="streams.0.mapping.${f}" value="${esc(st.mapping[f] || "")}" placeholder="(not mapped)"></div>`).join("")}
      ${entity === "event" ? select("streams.0.transforms.default_severity", "Default severity (no/unknown value)", SEVERITIES) : ""}
      ${entity === "event" ? kvEditor("streams.0.transforms.severity_map", "Severity map (tool value → common severity)", { keyPh: "alert", valueOptions: SEVERITIES }) : ""}
    </div>`;
}

function stepTest() {
  const t = wiz.test;
  let out = "";
  if (t && t.ok) {
    const others = (t.streams || []).length > 1 ? `<div class="hint-line">Streams: ${t.streams.map((x) => `${esc(x.name)} (${esc(x.entity)}): ${esc(x.status)}${x.normalised ? `, ${x.normalised.length} normalised` : ""}`).join(" · ")}</div>` : "";
    out = others + `<div class="success-box">✓ Normalised ${t.raw.length} sample record(s) from ${t.pages} page(s)${t.retries ? `, ${t.retries} retr${t.retries === 1 ? "y" : "ies"} (${esc(t.retry_log.join("; "))})` : ""}. Nothing was saved.</div>
      <div class="split">
        <div><div class="box-title">Raw (from the tool)</div><div class="box"><pre class="json">${pretty(t.raw)}</pre></div></div>
        <div><div class="box-title">Normalised (common schema)</div><div class="box"><pre class="json">${pretty(t.normalised)}</pre></div></div>
      </div>
      ${(t.quarantined || []).length ? `<div class="step-errors"><b>${t.quarantined.length} record(s) would be quarantined:</b><ul>${t.quarantined.map((q) => `<li>${esc(q.reason)}</li>`).join("")}</ul></div>` : ""}`;
  } else if (t) {
    out = `<div class="step-errors"><b>Test failed${t.stage === "validation" ? " (config is invalid)" : ""}:</b><ul>${t.errors.map((e) => `<li>${esc(e)}</li>`).join("")}</ul></div>`;
  }
  return `<h3>Test</h3><p class="lead">Runs this config once against the real API <b>without saving</b>, and shows the first 5 records raw vs normalised.</p>
    <button class="btn primary" id="runTest">▶ Run test</button>${out ? `<div style="margin-top:14px">${out}</div>` : ""}`;
}

function stepSave() {
  const d = clean(wiz.draft);
  const st = (d.streams || [])[0] || {};
  const map = Object.entries(st.mapping || {}).map(([k, v]) => `${k} ← ${v}`).join(", ");
  const saved = wiz.saved
    ? `<div class="success-box" style="margin-top:14px">✓ ${esc(wiz.saved)} <div style="margin-top:8px;display:flex;gap:8px">
        <button class="btn small" data-goto="${({ user: "users", device: "devices" })[st.entity] || "alerts"}">See the data</button><button class="btn small" data-goto="integrations">View health</button></div></div>` : "";
  return `<h3>Save &amp; go live</h3><p class="lead">Saving writes <code>configs/integrations/${esc(d.name || "…")}.yaml</code> and schedules it immediately - no restart, no code.</p>
    <dl class="summary-list">
      <dt>Integration</dt><dd>${esc(d.display_name || "-")} (${esc(d.name || "-")})</dd>
      <dt>Endpoint</dt><dd>${esc(st.method || "GET")} ${esc((d.base_url || "") + (st.endpoint || ""))}</dd>
      <dt>Entity</dt><dd>${esc(st.entity)} → ${esc((st.entity || "event") + "s")} table</dd>
      <dt>Auth</dt><dd>${esc(d.auth?.type)}</dd>
      <dt>Pagination</dt><dd>${esc(st.pagination?.type)}</dd>
      <dt>Schedule</dt><dd>every ${esc(d.schedule_seconds)}s</dd>
      <dt>Mapping</dt><dd>${esc(map || "-")}</dd>
    </dl>
    <div style="margin-top:16px;display:flex;gap:8px"><button class="btn primary" id="saveBtn">Save &amp; go live</button>
    <button class="btn danger hidden" id="overwriteBtn">Overwrite existing</button></div>${saved}`;
}

const STEP_RENDER = { basics: stepBasics, auth: stepAuth, request: stepRequest, pagination: stepPagination, mapping: stepMapping, test: stepTest, save: stepSave };

function renderStepper() {
  $("#stepper").innerHTML = STEPS.map((s, i) =>
    `<li data-step="${i}" class="${i === wiz.step ? "active" : i < wiz.maxStep || (i < wiz.step) ? "done" : ""}">${s.title}</li>`).join("");
}

function renderStep() {
  const step = STEPS[wiz.step];
  $("#stepBody").innerHTML = STEP_RENDER[step.id]();
  // <select> for booleans: reflect the real value
  const enabledSel = $('select[data-path="enabled"]');
  if (enabledSel) enabledSel.value = String(wiz.draft.enabled !== false);
  $("#wizBack").disabled = wiz.step === 0;
  $("#wizNext").classList.toggle("hidden", wiz.step === STEPS.length - 1);
  $("#wizNext").textContent = wiz.step === STEPS.length - 2 ? "Continue to save ›" : "Next ›";
  renderStepper();
}

function renderWizard() {
  wiz.draft = ensureShape(wiz.draft);
  renderStep();
  syncYaml(true);
}

function showStepErrors(list) {
  const box = $("#stepErrors");
  box.classList.toggle("hidden", !list.length);
  box.innerHTML = list.length ? `<b>Please fix:</b><ul>${list.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>` : "";
}

/** Validate the current step: client checks + server validation filtered to this step's fields. */
async function validateStep() {
  const step = STEPS[wiz.step];
  const errs = [];
  $$("#stepBody [data-secret]").forEach((el) => {
    if (el.value && !ENV_REF.test(el.value)) errs.push(`${el.dataset.path} must be an environment variable reference like \${MY_TOOL_TOKEN}`);
  });
  if (step.id === "mapping" && !Object.values(S().mapping).some(Boolean)) errs.push("Map at least one field (id is a good start)");
  if (!step.prefixes.length) return errs;
  try {
    await api("/api/integrations/validate", { method: "POST", body: { config: clean(wiz.draft) } });
  } catch (e) {
    for (const msg of errorList(e)) {
      if (e.status !== 422 || step.prefixes.some((p) => msg === p || msg.startsWith(p + " ") || msg.startsWith(p + ".") || msg.startsWith(p + ":"))) errs.push(msg);
    }
  }
  return [...new Set(errs)];
}

async function goStep(target) {
  if (target > wiz.step) {
    const errs = await validateStep();
    showStepErrors(errs);
    if (errs.length) return;
  } else {
    showStepErrors([]);
  }
  wiz.step = Math.max(0, Math.min(target, STEPS.length - 1));
  wiz.maxStep = Math.max(wiz.maxStep, wiz.step);
  renderStep();
  saveWizard();
}

function readKv(container) {
  const obj = {};
  $$(".kv-row", container).forEach((row) => {
    const k = $("[data-kv-key]", row).value.trim();
    const v = $("[data-kv-val]", row).value;
    if (k) obj[k] = v;
  });
  return obj;
}

function onWizardInput(ev) {
  const el = ev.target;
  if (el.dataset.path) {
    const path = el.dataset.path;
    let value = el.value;
    if (el.dataset.switch === "auth") { wiz.draft.auth = copy(AUTH_DEFAULTS[value]); renderStep(); syncYaml(); return; }
    if (el.dataset.switch === "pagination") { S().pagination = copy(PAGINATION_DEFAULTS[value]); renderStep(); syncYaml(); return; }
    if (el.dataset.switch === "entity") {
      Object.assign(S(), { entity: value, name: ENTITY_STREAM_NAME[value], mapping: {} });
      if (value !== "event") S().transforms = { time_format: S().transforms.time_format || "iso8601" };
      wiz.suggestion = null;
      renderStep(); syncYaml(); return;
    }
    if (path === "enabled") value = value === "true";
    else if (el.dataset.type === "number") value = value === "" ? undefined : Number(value);
    else if (el.dataset.type === "list") { value = value.split(/[,\s]+/).filter(Boolean); if (!value.length) value = undefined; }
    else if (path.includes(".mapping.") && value.trim() === "") value = undefined;
    setPath(wiz.draft, path, value);
    if (el.dataset.secret) {
      const bad = el.value && !ENV_REF.test(el.value);
      el.classList.toggle("invalid", bad);
      const msg = $(`[data-err-for="${CSS.escape(path)}"]`);
      if (msg) msg.textContent = bad ? "Use an environment variable reference like ${OKTA_CLIENT_SECRET}. Never paste the secret itself." : "";
    }
    if (path === "scopes" && $("#scopeBadge")) $("#scopeBadge").innerHTML = scopeBadge();
    syncYaml();
    return;
  }
  const kv = el.closest("[data-kv]");
  if (kv) {
    setPath(wiz.draft, kv.dataset.kv, readKv(kv));
    // keep one empty row available at the bottom
    const rows = $$(".kv-row", kv);
    const last = rows[rows.length - 1];
    if ($("[data-kv-key]", last).value.trim() && ev.type === "change") renderStep();
    syncYaml();
    return;
  }
  if (el.dataset.sugg !== undefined && wiz.suggestion) {
    wiz.suggestion.fields[Number(el.dataset.sugg)].path = el.value.trim();
    saveWizard();
  }
  if (el.id === "sampleInput") { wiz.sample = el.value; saveWizard(); }
}

async function onWizardClick(ev) {
  const el = ev.target.closest("button, li[data-step]");
  if (!el) return;
  if (el.matches("li[data-step]")) {
    const target = Number(el.dataset.step);
    if (target <= wiz.maxStep || target === wiz.step + 1) goStep(target);
    return;
  }
  if (el.hasAttribute("data-store-secret")) {
    const path = el.dataset.storeSecret;
    const name = prompt("Secret name (it becomes a ${NAME} reference in the config):", (getPath(wiz.draft, path) || "").replace(/^\$\{|\}$/g, "") || "MY_TOOL_SECRET");
    if (!name) return;
    const value = prompt(`Value for ${name} (stored encrypted at rest; it is never shown again):`);
    if (!value) return;
    try {
      const r = await api("/api/secrets", { method: "POST", body: { name, value } });
      setPath(wiz.draft, path, r.reference);
      toast(`${name} stored encrypted in the vault`, "ok");
      renderStep(); syncYaml();
    } catch (e) { showStepErrors(errorList(e)); }
    return;
  }
  if (el.hasAttribute("data-kv-del")) {
    const kv = el.closest("[data-kv]");
    el.closest(".kv-row").remove();
    setPath(wiz.draft, kv.dataset.kv, readKv(kv));
    renderStep(); syncYaml();
    return;
  }
  switch (el.id) {
    case "fetchSample": return fetchSample(el);
    case "suggestBtn": return suggest(el);
    case "applySuggestion": return applySuggestion();
    case "applyPagination": {
      const { evidence, ...hint } = wiz.suggestion.pagination_hint;
      S().pagination = Object.assign(copy(PAGINATION_DEFAULTS[hint.type]), hint);
      toast(`Pagination set to ${hint.type}`, "ok");
      renderStep(); syncYaml();
      return;
    }
    case "runTest": return runTest(el);
    case "saveBtn": return save(false);
    case "overwriteBtn": return save(true);
  }
}

async function withBusy(btn, label, fn) {
  const original = btn.textContent;
  btn.disabled = true;
  btn.textContent = label;
  try { await fn(); } finally { btn.disabled = false; btn.textContent = original; }
}

async function fetchSample(btn) {
  await withBusy(btn, "Fetching…", async () => {
    try {
      const r = await api("/api/integrations/sample", { method: "POST", body: { config: clean(wiz.draft), stream: 0 } });
      if (!r.ok) { showStepErrors(r.errors); return; }
      wiz.sample = JSON.stringify(r.sample, null, 2);
      wiz.linkHeader = !!r.link_next;
      $("#sampleInput").value = wiz.sample;
      showStepErrors([]);
      toast(r.trimmed ? `Sample fetched: showing 20 of ${fmtN(r.record_count)} records` : `Sample fetched: ${r.record_count} records`, "ok");
    } catch (e) { showStepErrors(errorList(e)); return; }
  });
  if (wiz.sample) await suggest($("#suggestBtn"));
}

async function suggest(btn) {
  const text = $("#sampleInput").value.trim();
  if (!text) { showStepErrors(["Paste a sample API response first, or fetch one from the API"]); return; }
  await withBusy(btn, "Analysing…", async () => {
    try {
      if (text !== wiz.sample) wiz.linkHeader = false; // pasted by hand: no response headers available
      wiz.sample = text;
      wiz.suggestion = await api("/api/ai/suggest-mapping", { method: "POST", body: { sample: text, entity: S().entity, link_header: !!wiz.linkHeader } });
      showStepErrors([]);
      renderStep();
      saveWizard();
    } catch (e) { showStepErrors(errorList(e)); }
  });
}

function applySuggestion() {
  const s = wiz.suggestion;
  const st = S();
  st.mapping = Object.fromEntries(s.fields.filter((f) => f.path).map((f) => [f.field, f.path]));
  st.records_path = s.records_path || "";
  st.transforms.time_format = s.time_format;
  if (st.entity === "event") {
    st.transforms.severity_map = { ...s.severity_map };
    if (s.default_severity) st.transforms.default_severity = s.default_severity;
  }
  toast("Mapping applied - review it below", "ok");
  renderStep();
  syncYaml();
}

async function runTest(btn) {
  await withBusy(btn, "Testing…", async () => {
    try {
      wiz.test = await api("/api/integrations/test", { method: "POST", body: { config: clean(wiz.draft) } });
    } catch (e) {
      wiz.test = { ok: false, stage: e.data?.stage || "request", errors: errorList(e) };
    }
  });
  renderStep();
  saveWizard();
}

async function save(overwrite) {
  try {
    const r = await api(`/api/integrations${overwrite ? "?overwrite=true" : ""}`, { method: "POST", body: { config: clean(wiz.draft) } });
    wiz.saved = r.message;
    showStepErrors([]);
    toast(r.message, "ok");
    await loadIntegrations();
  } catch (e) {
    const errs = errorList(e);
    showStepErrors(errs);
    renderStep();
    if (errs.some((m) => m.includes("already exists"))) $("#overwriteBtn").classList.remove("hidden");
    return;
  }
  renderStep();
  saveWizard();
}

function resetWizard() {
  Object.assign(wiz, { step: 0, maxStep: 0, draft: newDraft(), sample: "", suggestion: null, test: null, saved: null });
  showStepErrors([]);
  renderWizard();
}

/* ------------------------------------------------------------------ boot */
async function boot() {
  $$(".tab").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));
  document.addEventListener("click", (ev) => {
    const go = ev.target.closest("[data-goto]");
    if (go) showTab(go.dataset.goto);
    const menu = $("#settingsMenu");
    if (ev.target.closest("#settingsBtn")) menu.classList.toggle("hidden");
    else if (!ev.target.closest("#settingsMenu")) menu.classList.add("hidden");
  });
  $("#fSource").addEventListener("change", () => { alerts.offset = 0; refresh(); });
  $("#fSeverity").addEventListener("change", () => { alerts.offset = 0; refresh(); });
  $$(".src-filter").forEach((sel) => sel.addEventListener("change", () => refresh()));
  $("#prevPage").addEventListener("click", () => { alerts.offset = Math.max(0, alerts.offset - alerts.limit); refresh(); });
  $("#nextPage").addEventListener("click", () => { alerts.offset += alerts.limit; refresh(); });
  $("#alertsTable tbody").addEventListener("click", (ev) => {
    const row = ev.target.closest("tr[data-key]");
    if (!row || ev.target.closest("a")) return;
    const key = row.dataset.key;
    if (alerts.expanded.has(key)) alerts.expanded.delete(key); else alerts.expanded.add(key);
    refreshAlerts().catch(() => {});
  });
  $("#integrationCards").addEventListener("click", (ev) => {
    const b = ev.target.closest("button[data-act]");
    if (b) integrationAction(b.dataset.act, b.dataset.name);
  });
  $("#actionCards").addEventListener("click", (ev) => {
    const b = ev.target.closest("button[data-yaml]");
    if (!b) return;
    const a = (state.actions || []).find((x) => x.name === b.dataset.yaml);
    if (a) openModal(`${a.display_name} - config`, `<pre class="yaml">${esc(a.yaml)}</pre>`);
  });
  $("#modalBody").addEventListener("click", (ev) => {
    const b = ev.target.closest("button[data-act]");
    if (b) integrationAction(b.dataset.act, b.dataset.name);
  });
  $("#modalClose").addEventListener("click", closeModal);
  $("#modal").addEventListener("click", (ev) => { if (ev.target.id === "modal") closeModal(); });
  document.addEventListener("keydown", (ev) => { if (ev.key === "Escape") closeModal(); });

  $("#stepBody").addEventListener("input", onWizardInput);
  $("#stepBody").addEventListener("change", onWizardInput);
  $("#stepBody").addEventListener("click", onWizardClick);
  $("#stepper").addEventListener("click", onWizardClick);
  $("#wizNext").addEventListener("click", () => goStep(wiz.step + 1));
  $("#wizBack").addEventListener("click", () => goStep(wiz.step - 1));
  $("#wizNew").addEventListener("click", () => { if (confirm("Discard this draft and start a new integration?")) resetWizard(); });
  $("#yamlEditor").addEventListener("input", onYamlInput);
  $("#yamlEditor").addEventListener("keydown", (ev) => {
    if (ev.key === "Tab") { // indent with spaces instead of leaving the editor
      ev.preventDefault();
      const ed = ev.target, s = ed.selectionStart;
      ed.setRangeText("  ", s, ed.selectionEnd, "end");
      onYamlInput();
    }
  });
  $("#yamlEditor").addEventListener("blur", () => { if (!$("#yamlStatus").classList.contains("err")) setTimeout(() => syncYaml(), 500); });

  $("#demoControlsBtn").addEventListener("click", () => {
    $("#settingsMenu").classList.add("hidden");
    const options = state.integrations.filter((i) => i.enabled && /^http:\/\/(localhost|127\.0\.0\.1)/.test(i.base_url)).map((i) => `<option value="${esc(i.name)}" ${i.name === "acme_firewall" ? "selected" : ""}>${esc(i.display_name)}</option>`).join("");
    openModal("Demo controls", `<p class="muted">Deterministic triggers for the live demo. Each arms a one-shot fault on the mock tool and runs the connector immediately.</p>
      <div class="demo-grid">
        <div class="card"><div class="card-title">Wrong key</div><div class="muted small">Real GitHub API with an invalid token: real HTTP 401, "Authentication failed", no retries.</div>
          <button class="btn primary" data-demo="wrong-key">Call GitHub with a wrong key</button></div>
        <div class="card"><div class="card-title">Rate limit (Retry-After)</div><div class="muted small">Firewall returns HTTP 429 with Retry-After: 5. The run waits 5 s, then succeeds.</div>
          <button class="btn primary" data-demo="retry-after">429 with Retry-After: 5</button></div>
        <div class="card"><div class="card-title">Network off</div><div class="muted small">One Firewall run against a dead address: retries at 1s, 2s, 4s, then FAILED.</div>
          <button class="btn primary" data-demo="network-off">Network off mid-run</button></div>
        <div class="card"><div class="card-title">Repeated failure (B-4)</div><div class="muted small">3 failed Firewall runs in a row: ONE Slack alert + banner, then a good run: "recovered".</div>
          <button class="btn danger" data-demo="repeated-failure">Fail 3 times, then recover</button></div>
        <div class="card"><div class="card-title">Rate limit (two 429s)</div><div class="muted small">Firewall returns exactly two HTTP 429s, then succeeds.</div>
          <button class="btn primary" data-demo="firewall-429">Trigger 429 on next Firewall run</button></div>
        <div class="card"><div class="card-title">2 · Bad data</div><div class="muted small">One record with an unparseable timestamp; it is quarantined, the run continues.</div>
          <select id="demoConnector">${options}</select>
          <button class="btn primary" data-demo="malformed">Send a malformed record on next run</button></div>
        <div class="card"><div class="card-title">3 · Stolen token (INC-05)</div><div class="muted small">Next AWS CloudTrail page returns ~20x normal volume, like a bulk export with a stolen token.</div>
          <button class="btn danger" data-demo="bulk-export">Simulate stolen-token bulk export</button></div>
      </div><div id="demoResult" class="hint-line"></div>`);
  });
  $("#modalBody").addEventListener("click", async (ev) => {
    const b = ev.target.closest("button[data-demo]");
    if (!b) return;
    const kind = b.dataset.demo;
    const body = kind === "malformed" ? { connector: $("#demoConnector").value } : {};
    await withBusy(b, "Running…", async () => {
      try {
        const { result: r } = await api(`/api/demo/${kind}`, { method: "POST", body });
        const waits = (r.retry_log || []).join("; ");
        const msg = r.status === "done" ? `${r.failed_runs} failed runs -> ${r.alerts.length} alert (${(r.alerts[0] || {}).channels}); then ${r.recovery_run}: ${(r.recovery || {}).message || ""}`
          : r.status === "auth_failed" ? `${r.error} (retries: ${r.retries})`
          : r.status === "suspicious" ? `SUSPICIOUS: ${r.suspicious.records} records vs baseline ${r.suspicious.baseline} - connector auto-paused, critical alert raised`
          : r.status === "error" ? `Run FAILED: ${r.error}`
          : `Run ${r.status}: ${r.records_fetched} records, ${r.retries} retr${r.retries === 1 ? "y" : "ies"}, ${r.quarantined} quarantined${waits ? ` · ${waits}` : ""}`;
        $("#demoResult").textContent = msg;
        toast(msg, r.status === "success" ? "ok" : "err");
        await loadIntegrations();
        refresh();
      } catch (e) { toast(errorList(e).join("; "), "err"); }
    });
  });

  $("#resetBtn").addEventListener("click", async () => {
    $("#settingsMenu").classList.add("hidden");
    if (!confirm("Reset the demo? This clears all alerts, tickets and run history, and removes integrations added during the demo.")) return;
    try {
      const r = await api("/api/demo/reset", { method: "POST" });
      alerts.seen.clear(); alerts.primed = false; alerts.offset = 0; alerts.expanded.clear();
      resetWizard();
      toast(`Demo reset${r.removed_integrations.length ? ` - removed ${r.removed_integrations.join(", ")}` : ""}${r.jira_cleared ? " - Jira board cleared" : ""}`, "ok");
      await loadIntegrations();
      refresh();
    } catch (e) { toast(errorList(e).join("; "), "err"); }
  });

  try {
    state.meta = await api("/api/meta");
    Object.assign(ENTITY_FIELDS, state.meta.entity_fields || {});
    $("#jiraLink").href = jiraUrl();
    $("#jiraLinkMenu").href = jiraUrl();
  } catch { /* shown via the Live indicator */ }
  const fromHash = location.hash.slice(1);
  showTab(["alerts", "users", "devices", "integrations", "wizard", "actions"].includes(fromHash) ? fromHash : storeGet("tab", "alerts"));
  setInterval(refresh, 3000);
}

boot();
