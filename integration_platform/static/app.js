/* PlugSec UI - plain JS, no build step, no CDN. */
"use strict";

const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const ENTITY_FIELDS = {  // overwritten from /api/meta at boot (single source of truth is the server)
  user: ["id", "name", "email", "status", "last_login"],
  device: ["id", "hostname", "ip", "os", "owner", "last_seen"],
  event: ["id", "type", "severity", "timestamp", "description", "host", "src_ip", "dst_ip", "user", "resource"],
  repository: ["id", "full_name", "url", "description", "summary", "summary_source", "topics", "primary_language", "languages", "visibility",
    "is_fork", "is_archived", "default_branch", "stars", "forks", "open_issues", "created_at", "last_pushed_at", "dependabot_status"],
};
const TIME_FIELD = { user: "last_login", device: "last_seen", event: "timestamp", repository: "last_pushed_at" };
const SEVERITIES = ["info", "low", "medium", "high", "critical"];
const ENV_REF = /^\$\{[A-Za-z_][A-Za-z0-9_]*\}$/;
const ROLE_RANK = { viewer: 0, analyst: 1, admin: 2 };
const REFRESH_MS = 5000;
const fmtN = (n) => Number(n || 0).toLocaleString("en-US");
/** Labelled mocks (Demo source (Mock)) stay out of the live data views; they exist only for the demo controls. */
const isMock = (i) => /\bmock\b/i.test(i.display_name || "");
const cap = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : "");
const copy = (o) => JSON.parse(JSON.stringify(o));

const state = { page: "overview", me: null, meta: {}, integrations: [], names: {}, notifications: [], tick: 0, busy: false };

/* ------------------------------------------------------------------ icons (inline SVG, offline) */
const ICONS = {
  overview: '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
  events: '<path d="M12 3 2.5 19.5h19z"/><path d="M12 10v4m0 3h.01"/>',
  users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><path d="M16 4.5a3.5 3.5 0 0 1 0 7m2.5 8.5a6.5 6.5 0 0 0-3-5.5"/>',
  devices: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8m-4-4v4"/>',
  integrations: '<path d="M8 3v5m8-5v5M5 8h14v3a7 7 0 0 1-14 0zm7 10v3"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  actions: '<path d="M4 12h4l3-8 4 16 3-8h2"/>',
  audit: '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6M8 13h8m-8 4h5"/>',
  flask: '<path d="M9 3h6m-5 0v6L4.5 19a1.5 1.5 0 0 0 1.3 2h12.4a1.5 1.5 0 0 0 1.3-2L14 9V3"/><path d="M7 15h10"/>',
  moon: '<path d="M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  x: '<path d="M6 6l12 12M18 6 6 18"/>',
  more: '<circle cx="5" cy="12" r="1.2"/><circle cx="12" cy="12" r="1.2"/><circle cx="19" cy="12" r="1.2"/>',
  lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  play: '<path d="M7 4v16l13-8z"/>',
  chevrons: '<path d="m15 18-6-6 6-6"/>',
  check: '<path d="m5 12 5 5 9-10"/>',
  copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
  alert: '<circle cx="12" cy="12" r="9"/><path d="M12 8v5m0 3h.01"/>',
  catalog: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><path d="M17.5 14v7M14 17.5h7"/>',
  external: '<path d="M14 4h6v6M20 4l-9 9"/><path d="M19 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h5"/>',
  repo: '<path d="M5 4.5A2.5 2.5 0 0 1 7.5 2H19v16H7.5A2.5 2.5 0 0 0 5 20.5z"/><path d="M5 20.5A2.5 2.5 0 0 0 7.5 23H19v-5M9 7h6"/>',
};
const svg = (name) => `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] || ""}</svg>`;
const icon = (name, cls = "ico") => `<span class="${cls}">${svg(name)}</span>`;
function hydrateIcons(root = document) { $$("[data-icon]", root).forEach((el) => { el.innerHTML = svg(el.dataset.icon); }); }

/* ------------------------------------------------------------------ api + session */
async function api(path, { method = "GET", body } = {}) {
  const res = await fetch(path, {
    method, credentials: "same-origin",
    headers: body !== undefined ? { "Content-Type": "application/json" } : {},
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (res.status === 401 && path !== "/api/auth/login") { showLogin(); }
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
  return [e && e.message ? (e.message === "Failed to fetch" ? "Platform not reachable: is run_all.py running?" : e.message) : String(e)];
}

const can = (role) => state.me && ROLE_RANK[state.me.role] >= ROLE_RANK[role];
const lockTip = (role) => `${cap(role)} only`;

/** A button that is locked (lock icon + tooltip) for users below `role`. */
function gatedBtn(role, label, attrs = "", cls = "btn secondary sm") {
  if (can(role)) return `<button class="${cls}" ${attrs}>${label}</button>`;
  return `<button class="${cls} locked" disabled title="${lockTip(role)}" aria-label="${esc(label.replace(/<[^>]+>/g, ""))} (${lockTip(role)})">${icon("lock", "lock")}${label}</button>`;
}

function storeGet(key, fallback) {
  try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; } catch { return fallback; }
}
function storeSet(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* storage unavailable */ }
}

/* ------------------------------------------------------------------ formatting components */
function relTime(iso) {
  if (!iso) return "never";
  const d = new Date(iso);
  if (isNaN(d)) return String(iso);
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  const abs = Math.abs(s);
  const unit = abs < 60 ? null : abs < 3600 ? [Math.floor(abs / 60), "min"] : abs < 86400 ? [Math.floor(abs / 3600), "h"] : abs < 30 * 86400 ? [Math.floor(abs / 86400), "d"] : "date";
  if (unit === null) return s >= 0 ? "just now" : "in a moment";
  if (unit === "date") return d.toLocaleDateString("en-US", { day: "numeric", month: "short", year: d.getFullYear() === new Date().getFullYear() ? undefined : "numeric" });
  return s >= 0 ? `${unit[0]} ${unit[1]} ago` : `in ${unit[0]} ${unit[1]}`;
}
const fullTime = (iso) => { const d = new Date(iso); return isNaN(d) ? String(iso || "") : d.toLocaleString("en-US", { dateStyle: "medium", timeStyle: "medium" }); };
const timeHtml = (iso) => (iso ? `<time datetime="${esc(iso)}" title="${esc(fullTime(iso))}">${esc(relTime(iso))}</time>` : '<span class="muted">-</span>');
const sevPill = (s) => (s ? `<span class="pill ${SEVERITIES.includes(s) ? esc(s) : "info"}"><i></i>${esc(cap(s))}</span>` : '<span class="muted">-</span>');
const srcName = (src) => state.names[src] || src || "";
const initials = (name) => (String(name || "?").replace(/[^A-Za-z0-9 ]+/g, " ").trim().split(/\s+/).slice(0, 2).map((w) => w[0]).join("") || "?").toUpperCase();
const sourceTag = (src) => `<span class="tag" title="${esc(srcName(src))}"><b>${esc(initials(srcName(src)).slice(0, 1))}</b><span>${esc(srcName(src))}</span></span>`;
const cell = (value, cls = "") => (value ? `<span class="${cls}" title="${esc(value)}">${esc(value)}</span>` : '<span class="muted">-</span>');
const mono = (value) => cell(value, "mono");

function ticketLink(key) {
  if (!key) return '<span class="muted">-</span>';
  const base = state.meta.jira_base_url;
  const href = base ? `${base}/browse/${encodeURIComponent(key)}` : state.meta.jira_board_url || "#";
  return `<a class="ticket-link" href="${esc(href)}" target="_blank" rel="noopener" title="Open ${esc(key)} in Jira">${esc(key)}</a>`;
}

const STATUS = {
  healthy: ["Healthy", "ok"], degraded: ["Warning", "warn"], partial: ["Warning", "warn"], pending: ["Pending", "idle"],
  error: ["Failing", "bad"], auth_failed: ["Auth failed", "bad"], suspicious: ["Suspicious", "bad"], disabled: ["Paused", "idle"],
  not_configured: ["Not configured", "idle"], revoked: ["Revoked", "bad"],
};
const statusOf = (h) => (h.running ? ["Running", "ok"] : STATUS[h.status] || [cap(h.status), "idle"]);
const statusPill = (h) => { const [label, cls] = statusOf(h); return `<span class="pill ${cls}"><i></i>${esc(label)}</span>`; };
const AUTH_LABEL = { none: "No auth", bearer: "Bearer", api_key: "API key", basic: "Basic", oauth2_client_credentials: "OAuth2", session_login: "Session login" };
const PAGING_LABEL = { link: "Link header", offset: "Offset", page: "Page number", cursor: "Cursor", none: "No paging" };

function emptyRow(cols, title, text = "") {
  text = cap(text.replace(/^[:\s]+/, ""));
  return `<tr class="empty-row"><td colspan="${cols}" style="max-width:none;height:auto"><div class="empty"><b>${esc(title)}</b>${esc(text)}</div></td></tr>`;
}
const rangeText = (offset, shown, total) => (total ? `${fmtN(offset + 1)}-${fmtN(offset + shown)} of ${fmtN(total)}` : "No results");
const skeletonRows = (cols, n = 6) => Array.from({ length: n }, () => `<tr class="skeleton">${"<td></td>".repeat(cols)}</tr>`).join("");

function toast(msg, kind = "") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = msg;
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), kind === "err" ? 7000 : 4000);
}

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); toast("Copied", "ok"); } catch {
    const ta = Object.assign(document.createElement("textarea"), { value: text });
    document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove(); toast("Copied", "ok");
  }
}

/* ------------------------------------------------------------------ drawer + menu */
let drawerCleanup = null;
function openDrawer(kicker, title, html, onClose = null) {
  $("#drawerKicker").innerHTML = kicker;
  $("#drawerTitle").textContent = title;
  $("#drawerBody").innerHTML = html;
  hydrateIcons($("#drawer"));
  $("#drawer").classList.add("open");
  $("#drawer").setAttribute("aria-hidden", "false");
  $("#scrim").classList.remove("hidden");
  drawerCleanup = onClose;
  setTimeout(() => $("#drawerClose").focus(), 50);
}
function closeDrawer() {
  $("#drawer").classList.remove("open");
  $("#drawer").setAttribute("aria-hidden", "true");
  $("#scrim").classList.add("hidden");
  $$(".table tr.selected").forEach((r) => r.classList.remove("selected"));
  if (drawerCleanup) { drawerCleanup(); drawerCleanup = null; }
}
const kvList = (pairs) => `<dl class="kvlist">${pairs.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join("")}</dl>`;
const rawBlock = (obj, title = "Raw JSON", open = false) => {
  const text = JSON.stringify(obj, null, 2);
  return `<details class="raw" ${open ? "open" : ""}><summary>${esc(title)}<button class="btn ghost sm" data-copy="${esc(text)}">${icon("copy")}Copy</button></summary><pre class="code">${esc(text)}</pre></details>`;
};

/** items: [{label, act, danger, role, disabled, sep}] -> calls onPick(act). */
function openMenu(anchor, items, onPick) {
  const menu = $("#menu");
  menu.innerHTML = items.map((it, i) => it.sep ? "<hr>" : (() => {
    const locked = it.role && !can(it.role);
    return `<button role="menuitem" data-i="${i}" class="${it.danger ? "danger" : ""}" ${locked || it.disabled ? "disabled" : ""} ${locked ? `title="${lockTip(it.role)}"` : ""}>${esc(it.label)}${locked ? icon("lock", "lock") : ""}</button>`;
  })()).join("");
  menu.classList.remove("hidden");
  const r = anchor.getBoundingClientRect();
  const w = menu.offsetWidth, h = menu.offsetHeight;
  menu.style.left = `${Math.max(8, Math.min(r.right - w, innerWidth - w - 8))}px`;
  menu.style.top = `${r.bottom + h + 8 > innerHeight ? r.top - h - 6 : r.bottom + 6}px`;
  menu.onclick = (ev) => {
    const b = ev.target.closest("button[data-i]");
    if (!b || b.disabled) return;
    closeMenu();
    onPick(items[Number(b.dataset.i)].act);
  };
  const first = $("button:not(:disabled)", menu);
  if (first) first.focus();
}
const closeMenu = () => $("#menu").classList.add("hidden");

/* ------------------------------------------------------------------ navigation */
const NAV = [
  { page: "overview", label: "Overview", icon: "overview", desc: "Health of your connections and what happened in the last 24 hours." },
  { page: "events", label: "Events", icon: "events", desc: "Every alert and event from every connected tool, in one common format." },
  { page: "users", label: "Users", icon: "users", desc: "Accounts from your identity and work tools, in one table." },
  { page: "devices", label: "Devices", icon: "devices", desc: "Hosts and endpoints reported by your tools." },
  { page: "repositories", label: "Repositories", icon: "repo", desc: "Every repository the GitHub token can see: what it is, its languages and its open Dependabot alerts." },
  { page: "integrations", label: "Integrations", icon: "integrations", desc: "Connections to your security tools: health, last run and records pulled." },
  { page: "catalog", label: "Catalog", icon: "catalog", desc: "Tools customers use: what each API needs, and whether a ready template exists." },
  { page: "wizard", label: "Add integration", icon: "plus", role: "admin", desc: "Connect a new tool with a config file, not code." },
  { page: "actions", label: "Actions & tickets", icon: "actions", desc: "Automatic follow-ups: Jira tickets for serious alerts and Slack alerts on repeated failures." },
  { page: "audit", label: "Audit log", icon: "audit", role: "admin", desc: "Who signed in and what they changed." },
];

function renderNav() {
  $("#nav").innerHTML = NAV.map((n) => {
    const locked = n.role && !can(n.role);
    return locked
      ? `<span class="nav-item" aria-disabled="true" title="${lockTip(n.role)}" data-page="${n.page}" style="cursor:not-allowed;opacity:.6">${icon(n.icon)}<span class="nav-label">${esc(n.label)}</span>${icon("lock", "lock")}</span>`
      : `<a class="nav-item" href="#${n.page}" data-page="${n.page}" title="${esc(n.label)}">${icon(n.icon)}<span class="nav-label">${esc(n.label)}</span></a>`;
  }).join("");
  $$("[data-role]").forEach((el) => {
    if (el.id === "demoBtn") el.classList.toggle("hidden", !can(el.dataset.role));
    else if (!can(el.dataset.role)) {
      el.classList.add("locked"); el.setAttribute("aria-disabled", "true"); el.title = lockTip(el.dataset.role);
      el.removeAttribute("href");
      if (!$(".lock", el)) el.insertAdjacentHTML("afterbegin", icon("lock", "lock"));
    }
  });
}

function showPage(page) {
  const nav = NAV.find((n) => n.page === page) || NAV[0];
  state.page = nav.page;
  $$(".nav-item[data-page]").forEach((a) => a.classList.toggle("active", a.dataset.page === nav.page));
  $$(".page").forEach((p) => p.classList.toggle("active", p.id === `page-${nav.page}`));
  $("#pageTitle").textContent = nav.label;
  $("#pageDesc").textContent = nav.desc;
  document.title = `${nav.label} · PlugSec`;
  closeMenu();
  if (nav.role && !can(nav.role)) {
    $(`#page-${nav.page}`).innerHTML = `<div class="card"><div class="empty"><b>${lockTip(nav.role)}</b>Ask an admin if you need access to ${esc(nav.label.toLowerCase())}.</div></div>`;
    return;
  }
  if (nav.page === "wizard") {
    if (state.freshWizard) startFreshWizard();
    else if (state.wizardNotice) showDraftNotice(state.wizardNotice);
    else noteRestoredDraft();
    state.freshWizard = false;
    state.wizardNotice = "";
    renderWizard();
  }
  const SKELETON = { events: ["#eventsTable", 6], users: ["#usersTable", 5], devices: ["#devicesTable", 6], audit: ["#auditTable", 6] };
  const sk = SKELETON[nav.page];
  if (sk && !$(`${sk[0]} tbody`).children.length) $(`${sk[0]} tbody`).innerHTML = skeletonRows(sk[1]);
  refresh(true);
}

/* ------------------------------------------------------------------ refresh loop */
async function refresh(force = false) {
  if (!state.me) return;
  if (state.busy) { if (force) state.pending = true; return; }  // a page change while loading: run again right after
  if (!force && (document.hidden || $("#drawer").classList.contains("open"))) return;  // don't reflow under an open drawer
  state.busy = true;
  try {
    const page = state.page;
    if (force || state.tick % 3 === 0 || !state.integrations.length) await loadIntegrations();
    if (page === "overview") await renderOverview();
    else if (page === "events") await renderEvents();
    else if (page === "users") await renderUsers();
    else if (page === "devices") await renderDevices();
    else if (page === "repositories") await renderRepositories();
    else if (page === "integrations") await renderIntegrations();
    else if (page === "actions") await renderActions();
    else if (page === "catalog") await renderCatalog(force);
    else if (page === "audit" && can("admin")) await renderAudit();
    $("#liveDot").classList.remove("stale");
    $("#liveDot span").textContent = "Live";
  } catch (e) {
    if (e.status !== 401) { $("#liveDot").classList.add("stale"); $("#liveDot span").textContent = "Disconnected"; }
  } finally {
    state.busy = false;
    state.tick++;
    if (state.pending) { state.pending = false; refresh(true); }
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
    data.items.filter((i) => !isMock(i)).map((i) => `<option value="${esc(i.name)}">${esc(i.display_name)}</option>`)).join("");
  $$(".src-filter").forEach((sel) => {
    if (sel.dataset.sig === options) return;
    const current = sel.value;
    sel.innerHTML = options;
    sel.dataset.sig = options;
    sel.value = current;
  });
}

/* B-4: repeated-failure alerts. Always shown as a banner; also sent to Slack / email when configured. */
function renderBanner() {
  const latest = {};
  state.notifications.forEach((n) => { if (!(n.integration in latest)) latest[n.integration] = n; });
  const active = Object.values(latest).filter((n) => n.kind === "failure_alert");
  const box = $("#failureBanner");
  box.classList.toggle("hidden", !active.length);
  box.innerHTML = active.map((n) => `<div><b>${esc(srcName(n.integration))}</b>: ${esc(n.message)} <span class="muted sm">· ${timeHtml(n.created_at)} · sent to ${esc(n.channels.join(", "))}</span></div>`).join("");
}

/* ------------------------------------------------------------------ overview */
async function renderOverview() {
  const [st, crit] = await Promise.all([api("/api/stats"), api("/api/events?severity=critical&limit=5")]);
  const ints = state.integrations.filter((i) => !isMock(i));
  const by = (cls) => ints.filter((i) => statusOf(i.health)[1] === cls).length;
  const healthy = ints.filter((i) => i.health.colour === "green").length;
  const warn = by("warn"), bad = by("bad");
  const d = st.last_24h || { events: 0, by_severity: {}, tickets: 0 };
  const sub = [warn && `${warn} warning`, bad && `${bad} failing`].filter(Boolean).join(" · ") || "All connections reporting";
  $("#kpis").innerHTML = [
    ["Connected tools", `${healthy} / ${ints.length}`, `healthy · ${sub}`],
    ["Events (last 24h)", fmtN(d.events), `${fmtN(st.events.total)} stored in total`],
    ["Critical (last 24h)", fmtN(d.by_severity.critical || 0), `${fmtN(d.tickets)} ticket${d.tickets === 1 ? "" : "s"} opened`, "bad"],
    ["Records quarantined", fmtN(st.quarantined || 0), "Failed validation, kept for review"],
  ].map(([label, value, s, cls]) => `<div class="card kpi"><div class="label">${esc(label)}</div><div class="value ${cls && value !== "0" ? cls : ""}">${esc(value)}</div><div class="sub">${esc(s)}</div></div>`).join("");

  const max = Math.max(1, ...SEVERITIES.map((s) => d.by_severity[s] || 0));
  $("#sevBars").innerHTML = d.events ? `<div class="bars">${[...SEVERITIES].reverse().map((s) => {
    const n = d.by_severity[s] || 0;
    return `<a class="bar-row" href="#events" data-preset="${s}" style="text-decoration:none">${sevPill(s)}<div class="bar-track"><div class="bar-fill" style="width:${(n / max) * 100}%;background:var(--${s})"></div></div><span class="n">${fmtN(n)}</span></a>`;
  }).join("")}</div>` : '<div class="empty"><b>No events in the last 24 hours</b>Run a connection to pull fresh data.</div>';

  $("#connList").innerHTML = ints.map((i) => {
    const h = i.health, lr = h.last_run || {}, c = h.counts || {};
    const total = (c.users || 0) + (c.devices || 0) + (c.events || 0) + (c.repositories || 0);
    return `<a class="conn" href="#integrations" data-open-int="${esc(i.name)}"><span class="dot ${statusOf(h)[1]}" title="${esc(statusOf(h)[0])}"></span>
      <div style="min-width:0"><div class="conn-name">${esc(i.display_name)}</div><div class="conn-sub">${h.status === "not_configured" ? "Not configured" : `Last run ${esc(relTime(lr.finished_at))}`}</div></div>
      <span class="n">${fmtN(total)} records</span></a>`;
  }).join("") || '<div class="empty"><b>No connections yet</b></div>';

  state.lastCritical = crit.items;
  $("#criticalTable tbody").innerHTML = crit.items.length ? crit.items.map((e, i) => `<tr data-i="${i}">
      <td>${timeHtml(e.timestamp)}</td><td>${sevPill(e.severity)}</td><td>${cell(e.description)}</td><td>${sourceTag(e.source)}</td><td>${mono(e.host || e.src_ip)}</td></tr>`).join("")
    : emptyRow(5, "No critical events", ": nothing critical has been reported.");
}

/* ------------------------------------------------------------------ events */
const ev = { q: "", source: "", severity: "", range: "all", offset: 0, limit: 50, items: [] };
const RANGES = [["24h", "24h"], ["7d", "7d"], ["all", "All"]];

function sinceFor(range) {
  const hours = { "24h": 24, "7d": 168 }[range];
  return hours ? new Date(Date.now() - hours * 3600e3).toISOString().replace(/\.\d+Z$/, "Z") : "";
}

function renderEventFilters() {
  $("#evSeverity").innerHTML = [["", "All"], ...["critical", "high", "medium", "low"].map((s) => [s, cap(s)])]
    .map(([v, l]) => `<button class="chip ${ev.severity === v ? "active" : ""}" data-sev="${v}" aria-pressed="${ev.severity === v}">${v ? `<span class="dot" style="background:var(--${v})"></span>` : ""}${l}</button>`).join("");
  $("#evRange").innerHTML = RANGES.map(([v, l]) => `<button class="${ev.range === v ? "active" : ""}" data-range="${v}" aria-pressed="${ev.range === v}">${l}</button>`).join("");
}

async function renderEvents() {
  const q = new URLSearchParams({ limit: ev.limit, offset: ev.offset });
  if (ev.q) q.set("q", ev.q);
  if (ev.source) q.set("source", ev.source);
  if (ev.severity) q.set("severity", ev.severity);
  const since = sinceFor(ev.range);
  if (since) q.set("since", since);
  const data = await api(`/api/events?${q}`);
  ev.items = data.items;
  $("#evMeta").textContent = rangeText(ev.offset, data.items.length, data.total);
  $("#evPrev").disabled = ev.offset === 0;
  $("#evNext").disabled = ev.offset + ev.limit >= data.total;
  const filtered = ev.q || ev.source || ev.severity || ev.range !== "all";
  $("#eventsTable tbody").innerHTML = data.items.length ? data.items.map((e, i) => `<tr data-i="${i}">
      <td>${timeHtml(e.timestamp)}</td><td>${sevPill(e.severity)}</td>
      <td><div class="cell-main" title="${esc(e.description)}">${esc(e.description || "-")}</div><div class="cell-sub mono" title="${esc(e.type)}">${esc(e.type || "")}</div></td>
      <td>${sourceTag(e.source)}</td><td>${mono(e.host || e.src_ip)}</td><td>${ticketLink(e.ticket_key)}</td></tr>`).join("")
    : emptyRow(6, filtered ? "No matching events" : "No events yet", filtered ? ": try a wider time range or clear the filters." : ": run a connection to pull data.");
}

function eventDrawer(e) {
  const { raw, ...norm } = e;
  const fields = ["id", "type", "severity", "timestamp", "description", "host", "src_ip", "dst_ip", "user"];
  openDrawer(`${sevPill(e.severity)} ${sourceTag(e.source)}`, e.description || e.id, `
    ${kvList(fields.map((f) => [f, f === "severity" ? sevPill(norm[f]) : f === "timestamp" ? `${esc(fullTime(norm[f]))} <span class="muted">(${esc(relTime(norm[f]))})</span>`
      : norm[f] ? `<span class="${["id", "host", "src_ip", "dst_ip", "user"].includes(f) ? "mono" : ""}">${esc(norm[f])}</span>` : '<span class="muted">-</span>']))}
    <div><div class="section-title">Source</div>${kvList([["source", esc(srcName(e.source))], ["stream", `<span class="mono">${esc(e.stream || "-")}</span>`],
      ["fetched_at", `${esc(fullTime(e.fetched_at))}`], ["ticket", ticketLink(e.ticket_key)]])}</div>
    ${rawBlock(raw)}`);
}

/* ------------------------------------------------------------------ users / devices */
const us = { q: "", source: "", offset: 0, limit: 50, items: [] };
const dv = { q: "", source: "", offset: 0, limit: 50, items: [] };
const USER_STATUS = { active: "ok", enabled: "ok", member: "idle", admin: "idle", suspended: "bad", locked_out: "bad", locked: "bad", deprovisioned: "bad", inactive: "bad",
  disabled: "bad", provisioned: "idle", staged: "idle", pending: "idle", recovery: "warn", password_expired: "warn" };
const userStatusPill = (s) => (s ? `<span class="pill ${USER_STATUS[String(s).toLowerCase()] || "idle"}"><i></i>${esc(cap(String(s).toLowerCase().replace(/_/g, " ")))}</span>` : '<span class="muted">-</span>');

async function renderUsers() {
  const q = new URLSearchParams({ limit: us.limit, offset: us.offset });
  if (us.q) q.set("q", us.q);
  if (us.source) q.set("source", us.source);
  const [data, st] = await Promise.all([api(`/api/users?${q}`), api("/api/stats")]);
  us.items = data.items;
  const bySrc = st.users.by_source || {};
  $("#usSources").innerHTML = [["", "All", st.users.total], ...Object.entries(bySrc).sort((a, b) => b[1] - a[1]).map(([s, n]) => [s, srcName(s), n])]
    .map(([s, l, n]) => `<button class="chip ${us.source === s ? "active" : ""}" data-src="${esc(s)}" aria-pressed="${us.source === s}">${esc(l)} <span class="n">${fmtN(n)}</span></button>`).join("");
  $("#usMeta").textContent = rangeText(us.offset, data.items.length, data.total);
  $("#usPrev").disabled = us.offset === 0;
  $("#usNext").disabled = us.offset + us.limit >= data.total;
  $("#usersTable tbody").innerHTML = data.items.length ? data.items.map((u, i) => `<tr data-i="${i}">
      <td><div class="who"><span class="avatar">${esc(initials(u.name || u.email || u.id))}</span><span class="cell-main" title="${esc(u.name)}">${esc(u.name || "-")}</span></div></td>
      <td>${cell(u.email)}</td><td>${userStatusPill(u.status)}</td><td>${timeHtml(u.last_login)}</td><td>${sourceTag(u.source)}</td></tr>`).join("")
    : emptyRow(5, us.q || us.source ? "No matching users" : "No users yet", us.q || us.source ? ": clear the search or pick another source." : ": run a connection with a users stream.");
}

const ONLINE_MS = 5 * 60e3;  // seen in the last 5 minutes = online (Tailscale polls every minute)
function onlineCell(lastSeen) {
  if (!lastSeen) return '<span class="presence"><i class="dot"></i><span class="muted">Never seen</span></span>';
  const age = Date.now() - new Date(lastSeen).getTime();
  const online = age <= ONLINE_MS;
  return `<span class="presence" title="Last seen ${esc(fullTime(lastSeen))}"><i class="dot ${online ? "ok" : ""}"></i>${online ? "Online" : `<span class="muted">Offline · ${esc(relTime(lastSeen))}</span>`}</span>`;
}
/** Device sources for the filter: integrations with a device stream (or stored devices), real sources first. */
function renderDeviceSources() {
  const sel = $("#dvSource");
  const sources = state.integrations.filter((i) => !isMock(i) && ((i.streams || []).some((s) => s.entity === "device") || (i.health.counts || {}).devices))
    .sort((a, b) => a.display_name.localeCompare(b.display_name));
  const html = ['<option value="">All sources</option>', ...sources.map((i) => `<option value="${esc(i.name)}">${esc(i.display_name)}</option>`)].join("");
  if (sel.dataset.sig !== html) { sel.innerHTML = html; sel.dataset.sig = html; }
  sel.value = dv.source;
}

async function renderDevices() {
  renderDeviceSources();
  const q = new URLSearchParams({ limit: dv.limit, offset: dv.offset });
  if (dv.q) q.set("q", dv.q);
  if (dv.source) q.set("source", dv.source);
  const data = await api(`/api/devices?${q}`);
  dv.items = data.items;
  $("#dvMeta").textContent = rangeText(dv.offset, data.items.length, data.total);
  $("#dvPrev").disabled = dv.offset === 0;
  $("#dvNext").disabled = dv.offset + dv.limit >= data.total;
  $("#devicesTable tbody").innerHTML = data.items.length ? data.items.map((d, i) => `<tr data-i="${i}">
      <td><span class="cell-main" title="${esc(d.hostname)}" style="font-weight:500">${esc(d.hostname || "-")}</span></td><td>${mono(d.ip)}</td><td>${cell(d.os)}</td>
      <td>${cell(d.owner)}</td><td>${onlineCell(d.last_seen)}</td><td>${sourceTag(d.source)}</td></tr>`).join("")
    : emptyRow(6, dv.q || dv.source ? "No matching devices" : "No devices yet",
      dv.q || dv.source ? ": clear the search or pick another source." : ": none of the connected tools reports a device inventory. Add one with a devices stream.");
}

function recordDrawer(entity, r) {
  const { raw, ...norm } = r;
  const title = entity === "user" ? r.name || r.email || r.id : r.hostname || r.ip || r.id;
  const timeField = TIME_FIELD[entity];
  openDrawer(`${cap(entity)} · ${sourceTag(r.source)}`, title, `
    ${kvList(ENTITY_FIELDS[entity].map((f) => [f, f === "status" ? userStatusPill(norm[f]) : f === timeField ? (norm[f] ? `${esc(fullTime(norm[f]))} <span class="muted">(${esc(relTime(norm[f]))})</span>` : '<span class="muted">-</span>')
      : norm[f] ? `<span class="${["id", "ip", "email"].includes(f) ? "mono" : ""}">${esc(norm[f])}</span>` : '<span class="muted">-</span>']))}
    <div><div class="section-title">Source</div>${kvList([["source", esc(srcName(r.source))], ["stream", `<span class="mono">${esc(r.stream || "-")}</span>`], ["fetched_at", esc(fullTime(r.fetched_at))]])}</div>
    ${rawBlock(raw)}`);
}

/* ------------------------------------------------------------------ repositories */
const rp = { q: "", language: "", topic: "", visibility: "", critical: false, items: [], data: null };
const ALERT_SEVS = ["critical", "high", "medium", "low"];
/** A small stable colour per language for the language bar (no external palette needed). */
function langColour(name) {
  let h = 0;
  for (const ch of String(name)) h = (h * 31 + ch.charCodeAt(0)) % 360;
  return `hsl(${h} 55% 55%)`;
}
function langBar(languages, thin = true) {
  const entries = Object.entries(languages || {});
  if (!entries.length) return "";
  return `<div class="lang-bar ${thin ? "" : "tall"}" role="img" aria-label="${esc(entries.map(([k, v]) => `${k} ${v.percent}%`).join(", "))}">${entries.map(([k, v]) =>
    `<span style="width:${Math.max(v.percent, 0.5)}%;background:${langColour(k)}" title="${esc(`${k} ${v.percent}%`)}"></span>`).join("")}</div>`;
}
function alertPills(r) {
  if (r.dependabot_status === "disabled") return '<span class="pill idle" title="Dependabot alerts are disabled for this repository"><i></i>Dependabot off</span>';
  if (r.dependabot_status === "no access") return '<span class="pill idle" title="The token cannot read this repository\'s Dependabot alerts"><i></i>No alert access</span>';
  const pills = ALERT_SEVS.filter((s) => r[`alerts_${s}`]).map((s) => `<span class="pill ${s}"><i></i>${fmtN(r[`alerts_${s}`])} ${s}</span>`).join("");
  return pills || (r.dependabot_status === "enabled" ? '<span class="pill ok"><i></i>No open alerts</span>' : '<span class="muted sm">Dependabot not checked yet</span>');
}
function repoSummary(r) {
  if (r.description) return `<p class="repo-desc">${esc(r.description)}</p>`;
  if (r.summary) return `<p class="repo-desc">${esc(r.summary)} <span class="src-label">${r.summary_source === "AI" ? "AI summary" : "from README"}</span></p>`;
  return '<p class="repo-desc muted">No description</p>';
}
const plural = (n, word) => `${fmtN(n)} ${word}${n === 1 ? "" : "s"}`;

async function renderRepositories() {
  const params = new URLSearchParams();
  for (const k of ["q", "language", "topic", "visibility"]) if (rp[k]) params.set(k, rp[k]);
  if (rp.critical) params.set("critical", "true");
  const d = await api(`/api/repositories?${params}`);
  rp.data = d;
  rp.items = d.items;
  const k = d.kpis;
  $("#repoKpis").innerHTML = [
    ["Repositories", fmtN(k.repositories), `${plural(k.alerts.critical + k.alerts.high + k.alerts.medium + k.alerts.low, "open Dependabot alert")}`],
    ["With critical alerts", fmtN(k.with_critical), `${plural(k.alerts.critical, "critical alert")} · ${fmtN(k.alerts.high)} high`, "bad"],
    ["Languages", fmtN(k.languages), "Across all repositories"],
    ["Last updated", k.last_updated ? relTime(k.last_updated) : "-", k.last_updated ? fullTime(k.last_updated) : "Run the GitHub connection"],
  ].map(([label, value, s, cls]) => `<div class="card kpi"><div class="label">${esc(label)}</div><div class="value ${cls && value !== "0" ? cls : ""}">${esc(value)}</div><div class="sub">${esc(s)}</div></div>`).join("");
  const opts = (list, current, all) => [`<option value="">${all}</option>`, ...list.map((v) => `<option value="${esc(v)}" ${v === current ? "selected" : ""}>${esc(v)}</option>`)].join("");
  $("#rpLanguage").innerHTML = opts(d.facets.languages, rp.language, "All languages");
  $("#rpTopic").innerHTML = opts(d.facets.topics, rp.topic, "All topics");
  $("#rpVisibility").innerHTML = opts(d.facets.visibility, rp.visibility, "Any visibility");
  $("#rpCritical").classList.toggle("active", rp.critical);
  $("#rpCritical").setAttribute("aria-pressed", String(rp.critical));
  $("#rpMeta").textContent = d.total ? `Showing ${fmtN(d.shown)} of ${plural(d.total, "repository").replace("repositorys", "repositories")}` : "";
  $("#repoGrid").innerHTML = d.items.map((r, i) => `<article class="card repo-card" data-i="${i}" tabindex="0" aria-label="${esc(r.full_name)}">
      <div class="repo-head"><a class="repo-name" href="${esc(r.url)}" target="_blank" rel="noopener noreferrer" title="Open on GitHub">${esc(r.full_name)}</a>
        ${r.visibility ? `<span class="chip-sm vis-${esc(r.visibility)}">${esc(cap(r.visibility))}</span>` : ""}${r.is_fork ? '<span class="chip-sm">Fork</span>' : ""}${r.is_archived ? '<span class="chip-sm">Archived</span>' : ""}</div>
      ${repoSummary(r)}
      ${r.topics.length ? `<div class="repo-topics">${r.topics.slice(0, 6).map((t) => `<span class="topic">${esc(t)}</span>`).join("")}${r.topics.length > 6 ? `<span class="muted sm">+${r.topics.length - 6}</span>` : ""}</div>` : ""}
      ${langBar(r.languages)}
      <div class="repo-meta">${r.primary_language ? `<span><i class="lang-dot" style="background:${langColour(r.primary_language)}"></i>${esc(r.primary_language)}</span>` : ""}
        <span title="Stars">★ ${fmtN(r.stars)}</span><span title="Forks">${fmtN(r.forks)} fork${r.forks === 1 ? "" : "s"}</span><span title="Open issues">${fmtN(r.open_issues)} open issue${r.open_issues === 1 ? "" : "s"}</span>
        ${r.last_pushed_at ? `<span>Pushed ${timeHtml(r.last_pushed_at)}</span>` : ""}</div>
      <div class="repo-alerts">${alertPills(r)}</div>
    </article>`).join("")
    || `<div class="card"><div class="empty"><b>${d.total ? "No matching repositories" : "No repositories yet"}</b>${d.total ? "Clear the search or a filter." : "Run the GitHub connection to list every repository the token can see."}</div></div>`;
}

async function repoDrawer(r) {
  const alerts = await api(`/api/events?resource=${encodeURIComponent(r.full_name)}&limit=20`).catch(() => ({ items: [], total: 0 }));
  const langs = Object.entries(r.languages || {});
  openDrawer(`${sourceTag(r.source)} <span class="muted">Repository</span>`, r.full_name, `
    ${repoSummary(r)}
    <div style="display:flex;gap:8px;flex-wrap:wrap"><a class="btn secondary sm" href="${esc(r.url)}" target="_blank" rel="noopener noreferrer">${icon("external")}Open on GitHub</a></div>
    ${kvList([["Visibility", esc(cap(r.visibility || "-"))], ["Default branch", `<span class="mono">${esc(r.default_branch || "-")}</span>`],
      ["Stars · forks · issues", `★ ${fmtN(r.stars)} · ${fmtN(r.forks)} · ${fmtN(r.open_issues)}`], ["Fork / archived", `${r.is_fork ? "Fork" : "Not a fork"} · ${r.is_archived ? "Archived" : "Active"}`],
      ["Created", r.created_at ? esc(fullTime(r.created_at)) : "-"], ["Last push", r.last_pushed_at ? timeHtml(r.last_pushed_at) : "-"],
      ["Topics", r.topics.map((t) => `<span class="topic">${esc(t)}</span>`).join(" ") || '<span class="muted">none</span>'],
      ["Summary source", esc(r.description ? "Description" : r.summary ? (r.summary_source === "AI" ? "AI summary" : "README") : "-")],
      ["Dependabot", esc(cap(r.dependabot_status || "not checked"))], ["Fetched", esc(fullTime(r.fetched_at))]])}
    <div><div class="section-title">Languages</div>${langs.length ? `${langBar(r.languages, false)}<ul class="lang-list">${langs.map(([k, v]) =>
      `<li><i class="lang-dot" style="background:${langColour(k)}"></i><span>${esc(k)}</span><span class="muted">${v.percent}%</span></li>`).join("")}</ul>` : '<div class="muted">No language data</div>'}</div>
    <div><div class="section-title">Open Dependabot alerts ${alerts.total ? `<span class="muted">${fmtN(alerts.total)}</span>` : ""}</div>
      <div class="repo-alerts" style="margin-bottom:8px">${alertPills(r)}</div>
      ${alerts.items.length ? `<div class="alert-list">${alerts.items.map((e) => `<div class="alert-row">${sevPill(e.severity)}<span>${esc(e.description)}</span><span class="muted sm">${timeHtml(e.timestamp)}</span></div>`).join("")}</div>` : ""}</div>`);
}

/* ------------------------------------------------------------------ integrations */
function warningLine(i) {
  const h = i.health, lr = h.last_run || {};
  if (h.status === "suspicious") return ["bad", `Exfiltration guard: ${h.state.detail.records} records vs baseline ${h.state.detail.baseline}. Review it.`];
  if (h.status === "revoked") return ["bad", "Secrets revoked: store a new secret to reconnect"];
  if (h.status === "auth_failed") return ["bad", "Authentication failed: check the key in .env"];
  if (h.status === "error" && h.last_error) return ["bad", `Last run failed: ${h.last_error.error}`];
  if (h.status === "not_configured") return ["warn", `Set ${h.missing.join(", ")} in .env`];
  if (h.failure_streak) return ["bad", `${h.failure_streak} failed runs in a row${h.failure_alerted ? " · alert sent" : ""}`];
  if (h.quarantined_total) return ["warn", `${fmtN(h.quarantined_total)} record${h.quarantined_total === 1 ? "" : "s"} quarantined`, "quarantine"];
  const w = (h.warnings || [])[0];
  if (w) return [w.kind === "scope" ? "bad" : "warn", w.text];
  if (h.status === "partial" && lr.detail) return ["warn", "A stream failed in the last run"];
  return null;
}

async function renderIntegrations() {
  const ints = state.integrations;
  const count = (cls) => ints.filter((i) => statusOf(i.health)[1] === cls).length;
  const parts = [`${ints.length} connection${ints.length === 1 ? "" : "s"}`, `${ints.filter((i) => i.health.colour === "green").length} healthy`];
  if (count("warn")) parts.push(`${count("warn")} warning`);
  if (count("bad")) parts.push(`${count("bad")} failing`);
  const idle = ints.filter((i) => ["disabled", "not_configured", "pending"].includes(i.health.status)).length;
  if (idle) parts.push(`${idle} paused or not configured`);
  $("#intSummary").textContent = parts.join(" · ");
  const errs = Object.entries(state.loadErrors || {});
  $("#loadErrors").innerHTML = errs.map(([file, list]) => `<div class="notice warn"><b>${esc(file)}</b> could not be loaded: ${list.map(esc).join("; ")}</div>`).join("");

  $("#intGrid").innerHTML = ints.map((i) => {
    const h = i.health, lr = h.last_run || {}, c = h.counts || {};
    const stats = ["repositories", "users", "devices", "events"].filter((k) => c[k]).map((k) => `<div><b>${fmtN(c[k])}</b><span>${cap(k)}</span></div>`).join("");
    const nEp = (i.streams || []).length;
    const reach = c.repositories ? `${plural(c.repositories, "repository").replace("repositorys", "repositories")} · ${plural(c.events || 0, "alert")} · ${plural(nEp, "endpoint")}` : plural(nEp, "endpoint");
    const skipped = (i.streams || []).reduce((n, s) => n + (s.skipped || 0), 0);
    const pagings = [...new Set((i.streams || []).map((s) => s.pagination))];
    const paging = (pagings.length > 1 ? pagings.filter((p) => p !== "none") : pagings).map((p) => PAGING_LABEL[p] || p).join(" + ");
    const w = warningLine(i);
    const line = h.status === "not_configured" ? "Waiting for settings"
      : `Last run ${relTime(lr.finished_at)}${h.next_run && i.enabled ? ` · next ${relTime(h.next_run)}` : ""}`;
    const runnable = i.enabled && !["not_configured", "revoked", "suspicious"].includes(h.status);
    return `<article class="card int-card" data-int="${esc(i.name)}" tabindex="0" aria-label="${esc(i.display_name)}">
      <div class="int-head"><span class="avatar">${esc(initials(i.display_name).slice(0, 2))}</span><span class="int-name">${esc(i.display_name)}</span>${statusPill(h)}</div>
      <div class="int-line">${esc(line)}</div>
      <div class="int-line"><b>${esc(reach)}</b>${skipped ? ` · <span title="${esc((i.streams || []).filter((s) => s.skipped).map((s) => `${s.name}: ${Object.entries(s.skipped_reasons || {}).map(([k, n]) => `${n} × ${k}`).join("; ")}`).join("\n"))}">${plural(skipped, "item")} skipped</span>` : ""}</div>
      ${stats ? `<div class="int-stats">${stats}</div>` : ""}
      <div class="int-chips"><span class="chip-sm">${esc(AUTH_LABEL[i.auth_type] || i.auth_type)}</span><span class="chip-sm">${esc(paging || "No paging")}</span>${i.seeded ? "" : '<span class="chip-sm">Added live</span>'}</div>
      ${w ? `<div class="int-warn ${w[0]}">${icon("alert")}<span class="cell-main" title="${esc(w[1])}">${esc(w[1])}</span>${w[2] ? `<button class="link sm" data-act="quarantine" data-name="${esc(i.name)}">View</button>` : ""}</div>` : ""}
      <div class="int-foot">
        ${h.status === "suspicious" ? gatedBtn("admin", "Review", `data-act="review" data-name="${esc(i.name)}"`, "btn primary sm")
          : gatedBtn("analyst", `${icon("play")}Run now`, `data-act="run" data-name="${esc(i.name)}" ${runnable ? "" : "disabled"}`, "btn primary sm")}
        <button class="icon-btn" data-menu="${esc(i.name)}" aria-label="More actions for ${esc(i.display_name)}" aria-haspopup="menu">${icon("more")}</button>
      </div></article>`;
  }).join("") || '<div class="card"><div class="empty"><b>No integrations yet</b>Add one to start pulling data.</div></div>';
}

function integrationMenu(btn, name) {
  const i = state.integrations.find((x) => x.name === name);
  if (!i) return;
  const h = i.health;
  const items = [{ label: "View details", act: "view" }];
  if (h.quarantined_total) items.push({ label: `View quarantine (${fmtN(h.quarantined_total)})`, act: "quarantine" });
  items.push({ sep: true });
  if (h.status === "suspicious") items.push({ label: "Resume (false positive)", act: "resume", role: "admin" });
  else if (h.status !== "revoked") items.push({ label: i.enabled ? "Disable" : "Enable", act: i.enabled ? "disable" : "enable", role: "admin" });
  items.push({ label: "Revoke secret", act: "revoke", role: "admin", danger: true, disabled: h.status === "revoked" || !(h.secrets || []).length });
  if (!i.seeded) items.push({ label: "Delete integration", act: "delete", role: "admin", danger: true });
  openMenu(btn, items, (act) => integrationAction(act, name));
}

async function integrationAction(act, name) {
  const label = srcName(name);
  try {
    if (act === "run") {
      toast(`Run started: ${label}`);
      const r = await api(`/api/integrations/${name}/run`, { method: "POST" });
      if (r.status === "success" || r.status === "partial") {
        const waits = (r.retry_log || []).filter((l) => l.includes("waited")).join("; ");
        toast(`${label}: ${fmtN(r.records_fetched)} records (${fmtN(r.records_new)} new)${r.quarantined ? `, ${r.quarantined} quarantined` : ""}${r.retries ? `, ${r.retries} retr${r.retries === 1 ? "y" : "ies"}` : ""}${waits ? ` (${waits})` : ""}`, r.status === "success" ? "ok" : "err");
      } else toast(`${label}: ${r.error || r.status}`, "err");
    } else if (act === "enable" || act === "disable") {
      await api(`/api/integrations/${name}/${act}`, { method: "POST" });
      toast(`${label} ${act}d`, "ok");
    } else if (act === "delete") {
      if (!confirm(`Delete the integration "${label}"? Its stored records stay.`)) return;
      await api(`/api/integrations/${name}`, { method: "DELETE" });
      toast("Integration deleted", "ok");
    } else if (act === "resume") {
      await api(`/api/integrations/${name}/resume`, { method: "POST" });
      closeDrawer();
      toast(`${label} resumed; the volume baseline is re-learnt from now`, "ok");
    } else if (act === "revoke") {
      if (!confirm(`Revoke ${label}? This disables the connection and wipes its stored secret(s) from the vault.`)) return;
      const r = await api(`/api/integrations/${name}/revoke`, { method: "POST" });
      closeDrawer();
      toast(`${label} revoked: wiped ${r.wiped_secrets.join(", ")}`, "ok");
    } else if (act === "quarantine") {
      const q = await api(`/api/integrations/${name}/quarantine`);
      openDrawer(`${sourceTag(name)}`, `${fmtN(q.total)} quarantined record${q.total === 1 ? "" : "s"}`,
        `<p class="muted" style="margin:0">Records that failed validation are kept here with the reason. The run continued and the good records were stored.</p>
        ${q.items.map((r) => `<div class="card" style="padding:12px 16px"><div class="int-warn bad">${icon("alert")}<span>${esc(r.reason)}</span></div>
          <div class="muted sm" style="margin:6px 0">${timeHtml(r.created_at)} · stream <span class="mono">${esc(r.stream || "-")}</span></div>${rawBlock(r.raw, "Raw record")}</div>`).join("") || '<div class="empty"><b>Nothing quarantined</b></div>'}`);
      return;
    } else if (act === "view" || act === "review") {
      return integrationDrawer(name);
    }
  } catch (e) {
    toast(errorList(e).join("; "), "err");
  }
  await loadIntegrations();
  if (state.page === "integrations") renderIntegrations();
}

async function integrationDrawer(name) {
  const d = await api(`/api/integrations/${name}`);
  const h = d.health, g = h.state && h.state.detail;
  const guard = h.status === "suspicious" ? `<div class="notice warn"><b>Flagged by the exfiltration guard.</b> One run pulled ${fmtN(g.records)} records: ${g.ratio}x the rolling baseline of ${g.baseline}
      (threshold ${g.threshold}). That is the pattern of a stolen token used for a bulk export. If the jump is expected (for example a first full scan), resume it.
      <div style="display:flex;gap:8px;margin-top:10px">${gatedBtn("admin", "Resume (false positive)", `data-act="resume" data-name="${esc(name)}"`)}${gatedBtn("admin", "Revoke token", `data-act="revoke" data-name="${esc(name)}"`, "btn danger sm")}</div></div>` : "";
  const runs = d.recent_runs.map((r) => {
    const cls = r.status === "success" ? "ok" : r.status === "running" ? "idle" : r.status === "partial" ? "warn" : "bad";
    return `<div class="run"><span>${timeHtml(r.started_at)}</span><span class="pill ${cls}"><i></i>${esc(cap(r.status))}</span>
      <span class="muted sm">${fmtN(r.records_fetched)} records · ${fmtN(r.records_new)} new${r.retries ? ` · ${r.retries} retr${r.retries === 1 ? "y" : "ies"}` : ""}${r.pages ? ` · ${r.pages} page${r.pages === 1 ? "" : "s"}` : ""}</span>
      ${r.error ? `<span class="err">${esc(r.error)}</span>` : ""}</div>`;
  }).join("");
  const epCls = (st) => (!st ? "idle" : st === "ok" ? "ok" : st === "error" ? "bad" : "idle");
  const endpoints = (d.streams || []).map((s) => `<tr><td><span class="mono">${esc(s.name)}</span><div class="muted sm mono" title="${esc(s.endpoint)}">${esc(s.endpoint)}</div>
      ${s.for_each ? `<div class="muted sm">for each ${esc(s.for_each)} record${s.merge_into_parent ? " · merged" : ""}</div>` : ""}</td>
      <td>${esc(entityLabel(s.entity))}</td>
      <td><span class="pill ${epCls(s.last_status)}" title="${esc(s.last_status || "")}"><i></i>${esc(s.last_status === "ok" ? "OK" : s.last_status ? cap(String(s.last_status).split(":")[0]) : "Not run")}</span></td>
      <td>${s.fetched == null ? '<span class="muted">-</span>' : `${fmtN(s.fetched)}<div class="muted sm">${fmtN(s.new)} new · ${fmtN(s.updated)} upd.</div>`}</td>
      <td>${s.skipped ? `<span title="${esc(Object.entries(s.skipped_reasons || {}).map(([k, n]) => `${n} × ${k}`).join("\n"))}">${fmtN(s.skipped)} skipped</span>` : '<span class="muted">-</span>'}
        ${s.error ? `<div class="err sm" title="${esc(s.error)}">${esc(s.error)}</div>` : ""}</td></tr>`).join("");
  openDrawer(`${statusPill(h)} <span>${esc(h.summary)}</span>`, d.display_name, `${guard}
    ${kvList([["Base URL", `<span class="mono">${esc(d.base_url)}</span>`], ["Schedule", `every ${d.schedule_seconds >= 60 ? `${d.schedule_seconds / 60} min` : `${d.schedule_seconds}s`}`],
      ["Auth", esc(AUTH_LABEL[d.auth_type] || d.auth_type)], ["Scopes", (d.scopes || []).map((s) => `<span class="chip-sm" style="margin:0 4px 4px 0;${(d.risky_scopes || []).includes(s) ? "color:var(--bad)" : ""}">${esc(s)}</span>`).join("") || '<span class="muted">-</span>'],
      ["Retries", `${fmtN(h.totals.retries)} in ${fmtN(h.totals.runs)} runs · ${fmtN(h.totals.errors)} failed`],
      ["Secrets", (h.secrets || []).map((s) => `<span class="mono">${esc(s.name)}</span> <span class="muted sm">${s.revoked ? "revoked" : s.in_vault ? `in vault · ${s.age_days} d old` : "from .env"}</span>`).join("<br>") || '<span class="muted">none</span>']])}
    <div><div class="section-title">Endpoints <span class="muted">${(d.streams || []).length}</span></div>
      <div class="table-wrap"><table class="table ep-table"><thead><tr><th>Endpoint</th><th>Fills</th><th>Last status</th><th>Records</th><th>Skipped / error</th></tr></thead><tbody>${endpoints}</tbody></table></div></div>
    <div><div class="section-title">Recent runs</div><div class="runs">${runs || '<div class="muted">No runs yet</div>'}</div></div>
    <details class="raw" open><summary>Config<button class="btn ghost sm" data-copy="${esc(d.yaml)}">${icon("copy")}Copy</button></summary><pre class="code">${esc(d.yaml)}</pre></details>`);
}

/* ------------------------------------------------------------------ catalog */
const cat = { data: null, q: "", category: "", status: "", at: 0 };
const CAT_STATUS = {
  connected: ["Connected", "ok"], template_ready: ["Template ready", "role"], needs_verification: ["Needs verification", "warn"],
  needs_capability: ["Needs capability", "idle"], no_public_api: ["No public API", "idle"],
};
const VERIFICATION = { verified: "Verified in vendor docs", partial: "Partly verified (some facts from third-party docs)", unverified: "Not verifiable from public docs" };
const capTitle = (key) => ((cat.data.capabilities[key] || {}).title || key).toLowerCase();

async function renderCatalog(force) {
  if (!cat.data || (force && Date.now() - cat.at > 60e3)) { cat.data = await api("/api/catalog"); cat.at = Date.now(); }
  const d = cat.data;
  $("#catCategories").innerHTML = [["", "All"], ...d.categories.map((c) => [c, c])]
    .map(([v, l]) => `<button class="chip ${cat.category === v ? "active" : ""}" data-cat="${esc(v)}" aria-pressed="${cat.category === v}">${esc(l)}</button>`).join("");
  $("#catStatuses").innerHTML = [["", "All", d.entries.length], ...Object.entries(CAT_STATUS).map(([k, [l]]) => [k, l, d.counts[k] || 0])]
    .map(([v, l, n]) => `<button class="chip ${cat.status === v ? "active" : ""}" data-status="${esc(v)}" aria-pressed="${cat.status === v}">${esc(l)} <span class="n">${n}</span></button>`).join("");
  const q = cat.q.toLowerCase();
  const shown = d.entries.filter((e) => (!cat.category || e.catalog.category === cat.category) && (!cat.status || e.status === cat.status)
    && (!q || [e.catalog.name, e.catalog.category, e.catalog.auth, e.catalog.paging, e.catalog.api_style, e.label, e.catalog.notes, e.catalog.docs].join(" ").toLowerCase().includes(q)));
  const groups = d.categories.map((c) => [c, shown.filter((e) => e.catalog.category === c)]).filter(([, list]) => list.length);
  $("#catGroups").innerHTML = groups.map(([c, list]) => `<h2 class="cat-title">${esc(c)} <span class="muted sm">${list.length}</span></h2>
    <div class="int-grid">${list.map(catalogCard).join("")}</div>`).join("")
    || '<div class="card"><div class="empty"><b>No matching tools</b>Clear the search or pick another filter.</div></div>';
}

function catalogCard(e) {
  const m = e.catalog;
  const [label, cls] = CAT_STATUS[e.status];
  const text = e.status === "needs_capability" ? e.label.replace("Needs capability: ", "Needs: ") : label;
  const pill = `<span class="pill ${cls}" title="${esc(e.label)}"><i></i>${esc(text)}</span>`;
  const usable = e.template && ["template_ready", "connected"].includes(e.status);
  const why = e.status === "needs_capability" ? e.label : e.status === "no_public_api" ? "No public API to connect to" : "The events endpoint is not confirmed in public docs yet";
  const use = usable ? gatedBtn("admin", "Use template", `data-template="${esc(e.id)}"`, "btn primary sm")
    : `<button class="btn secondary sm" disabled title="${esc(why)}">Use template</button>`;
  return `<article class="card int-card cat-card">
    <div class="int-head"><span class="avatar">${esc(initials(m.name).slice(0, 2))}</span><span class="int-name" title="${esc(m.name)}">${esc(m.name)}</span>${pill}</div>
    <div class="int-chips"><span class="chip-sm" title="Auth">${esc(m.auth)}</span><span class="chip-sm" title="Paging">${esc(m.paging)}</span></div>
    <div class="int-line"><span class="mono">${esc(m.endpoint)}</span></div>
    <div class="muted sm">${esc(m.notes || "")}</div>
    <div class="int-line">${esc(VERIFICATION[m.verification] || m.verification)}${e.uses.length ? ` · uses ${esc(e.uses.map(capTitle).join(", "))}` : ""}</div>
    <div class="int-foot">${use}${m.docs ? `<a class="btn ghost sm" href="${esc(m.docs)}" target="_blank" rel="noopener noreferrer" style="margin-left:auto">${icon("external")}Docs</a>` : ""}</div>
  </article>`;
}

function useTemplate(id) {
  const e = cat.data.entries.find((x) => x.id === id);
  if (!e || !e.template || !can("admin")) return;
  const draft = ensureShape(copy(e.template));
  Object.assign(wiz, { step: 0, maxStep: 0, active: 0, ep: draft.streams.map(newEndpointState), draft, test: null, saved: null, fieldErrors: {}, tabErrors: new Set() });
  saveWizard();
  state.wizardNotice = `Template loaded: <b>${esc(e.catalog.name)}</b>. Fill in the .env names, then test it. <button class="link" data-draft="fresh">Start fresh</button>`;
  location.hash = "wizard";
  const n = draft.streams.length;
  toast(`${e.catalog.name} template loaded${n > 1 ? ` with ${n} endpoints (${draft.streams.map((x) => x.name).join(", ")})` : ""}: fill in the .env names, then test it`, "ok");
}

/* ------------------------------------------------------------------ actions & tickets */
const acts = { all: false };
function ruleSummary(a) {
  if (a.trigger.includes("connector_failure")) return "When a connection fails several runs in a row, and again when it recovers";
  const w = a.when || {};
  const sev = w.severity_in ? `severity is ${w.severity_in.join(" or ")}` : "any event arrives";
  const src = w.source_in ? ` from ${w.source_in.map(srcName).join(", ")}` : "";
  return `When ${sev}${src}`;
}

async function renderActions() {
  const [list, res] = await Promise.all([api("/api/actions"), api(`/api/actions/results?limit=${acts.all ? 200 : 20}`)]);
  state.actions = list.items;
  $("#actionCards").innerHTML = list.items.map((a) => {
    const ref = (a.target.match(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/) || [])[1];
    let host = ref ? `the URL in ${ref}` : a.target;
    if (ref === "JIRA_DOMAIN" && state.meta.jira_base_url) host = new URL(state.meta.jira_base_url).host;
    else if (!ref) { try { host = new URL(a.target).host; } catch { /* keep as is */ } }
    return `<div class="card" style="display:flex;flex-direction:column;gap:12px">
      <div class="int-head"><span class="avatar">${icon(a.trigger.includes("connector_failure") ? "alert" : "actions")}</span><span class="int-name">${esc(a.display_name)}</span>
        <span class="pill ${a.enabled ? "ok" : "idle"}"><i></i>${a.enabled ? "On" : "Off"}</span></div>
      <div>${esc(ruleSummary(a))}</div>
      <div class="int-stats"><div><b>${fmtN(a.stats.success)}</b><span>Succeeded</span></div><div><b style="${a.stats.failed ? "color:var(--bad)" : ""}">${fmtN(a.stats.failed)}</b><span>Failed</span></div></div>
      <div class="int-foot"><span class="muted sm cell-main" title="${esc(a.target)}">Sends to ${esc(host)}</span>
        <button class="btn ghost sm" data-yaml="${esc(a.name)}" style="margin-left:auto">View config</button></div></div>`;
  }).join("") || '<div class="card"><div class="empty"><b>No actions configured</b></div></div>';
  $("#resultsAll").textContent = acts.all ? "Show latest 20" : "View all";
  $("#resultsTable tbody").innerHTML = res.items.length ? res.items.map((r) => `<tr>
      <td>${timeHtml(r.created_at)}</td><td>${cell((list.items.find((a) => a.name === r.action) || {}).display_name || r.action)}</td>
      <td><span class="cell-main mono" title="${esc(r.event_id)}">${esc(srcName(r.event_source))} · ${esc(r.event_id)}</span>${r.error ? `<div class="cell-sub" title="${esc(r.error)}" style="color:var(--bad)">${esc(r.error)}</div>` : ""}</td>
      <td><span class="pill ${r.status === "success" ? "ok" : "bad"}"><i></i>${esc(cap(r.status))}</span></td><td>${ticketLink(r.ticket_key)}</td><td>${r.attempts}</td></tr>`).join("")
    : emptyRow(6, "No results yet", ": tickets appear here when a high or critical alert arrives from Okta or GitHub.");
}

/* ------------------------------------------------------------------ audit */
async function renderAudit() {
  const data = await api("/api/audit?limit=300");
  $("#auditTable tbody").innerHTML = data.items.length ? data.items.map((a) => `<tr>
      <td>${timeHtml(a.at.replace(" ", "T"))}</td><td><div class="who"><span class="avatar sm">${esc(initials(a.user))}</span>${cell(a.user)}</div></td>
      <td>${a.role ? `<span class="pill role">${esc(cap(a.role))}</span>` : '<span class="muted">-</span>'}</td><td>${cell(a.action)}</td><td>${mono(a.target)}</td>
      <td><span class="pill ${a.outcome === "ok" ? "ok" : "bad"}"><i></i>${esc(cap(a.outcome))}</span></td></tr>`).join("")
    : emptyRow(6, "No activity yet");
}

/* ================================================================== WIZARD */
/** Server messages start with a field path; each step owns some of them. Mapping messages: mapping/records path/transforms. */
const isMappingMsg = (m) => /^streams(\.\d+)?(\.(mapping|records_path|transforms)\b|\s.*\b(mapping|mapped)\b)/.test(m);
const STEPS = [
  { id: "basics", title: "Basics", owns: (m) => /^(name|display_name|base_url|schedule_seconds|enabled)\b/.test(m) },
  { id: "auth", title: "Auth", owns: (m) => /^(auth|scopes)\b/.test(m) },
  { id: "endpoints", title: "Endpoints", owns: (m) => /^streams\b/.test(m) && !isMappingMsg(m) },
  { id: "mapping", title: "Mapping", owns: isMappingMsg },
  { id: "test", title: "Test", owns: null },
  { id: "save", title: "Save", owns: null },
];

const AUTH_DEFAULTS = {
  none: { type: "none" },
  bearer: { type: "bearer", token: "" },
  api_key: { type: "api_key", header: "X-API-Key", api_key: "" },
  basic: { type: "basic", username: "", password: "" },
  oauth2_client_credentials: { type: "oauth2_client_credentials", token_url: "/oauth2/v1/token", client_id: "", client_secret: "" },
  session_login: { type: "session_login", login_url: "/login", body: {}, headers: {}, token_path: "token", header: "Authorization", prefix: "Bearer ", ttl_seconds: 600 },
};
const PAGINATION_DEFAULTS = {
  none: { type: "none" },
  page: { type: "page", page_param: "page", size_param: "page_size", page_size: 10, total_pages_path: "", max_pages: 10 },
  offset: { type: "offset", limit_param: "limit", offset_param: "offset", limit: 10, max_pages: 10 },
  cursor: { type: "cursor", cursor_path: "", cursor_param: "cursor", max_pages: 10 },
  link: { type: "link", next_path: "", max_pages: 10 },
};
const ENTITY_STREAM_NAME = { user: "users", device: "devices", event: "events", repository: "repositories" };
const ENTITY_OPTIONS = [["event", "Events"], ["user", "Users"], ["device", "Devices"], ["repository", "Repositories"]];
const entityLabel = (e) => (ENTITY_OPTIONS.find(([v]) => v === e) || [e, e])[1];
/** Fields an endpoint must map (the server's defaults: a missing id would otherwise become a content hash). */
const REQUIRED_FIELDS = { user: ["id"], device: ["id"], event: ["id", "timestamp"], repository: ["id", "full_name"] };
const newStream = (entity = "event", name = ENTITY_STREAM_NAME[entity]) => ({
  name, entity, endpoint: "", method: "GET", params: {},
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
const newEndpointState = () => ({ sample: "", suggestion: null, linkHeader: false, check: null });

const savedWiz = storeGet("wizard", null);
const wiz = (savedWiz && savedWiz.draft && Array.isArray(savedWiz.draft.streams) ? savedWiz : null)
  || { step: 0, maxStep: 0, active: 0, ep: [], draft: newDraft(), test: null, saved: null };
if (!Array.isArray(wiz.ep)) {  // a draft saved by the single-endpoint wizard (7 steps): keep its sample and step
  wiz.ep = [{ ...newEndpointState(), sample: wiz.sample || "", suggestion: wiz.suggestion || null, linkHeader: !!wiz.linkHeader }];
  const OLD_TO_NEW = [0, 1, 2, 2, 3, 4, 5];
  wiz.step = OLD_TO_NEW[wiz.step] ?? 0;
  wiz.maxStep = OLD_TO_NEW[wiz.maxStep] ?? 0;
  wiz.active = 0;
  delete wiz.sample; delete wiz.suggestion; delete wiz.linkHeader;
}
wiz.fieldErrors = {};
wiz.tabErrors = new Set();

/** The endpoint (stream) the wizard is editing, its field-path prefix and its sample / suggestion. */
const S = () => wiz.draft.streams[wiz.active] || wiz.draft.streams[0];
const P = () => `streams.${wiz.active}`;
const EP = () => wiz.ep[wiz.active] || (wiz.ep[wiz.active] = newEndpointState());

/** Keep the per-endpoint state in step with the streams (YAML edits can add or remove some). */
function syncEndpointState() {
  const n = wiz.draft.streams.length;
  while (wiz.ep.length < n) wiz.ep.push(newEndpointState());
  wiz.ep.length = n;
  wiz.active = Math.min(Math.max(0, Number(wiz.active) || 0), n - 1);
}

/** Guarantee the nested objects the form binds to exist (YAML edits may remove them). */
function ensureShape(d) {
  const base = newDraft();
  for (const k of ["auth", "retry"]) if (typeof d[k] !== "object" || d[k] === null || Array.isArray(d[k])) d[k] = base[k];
  if (!Array.isArray(d.streams) || !d.streams.length) d.streams = [newStream()];
  d.streams = d.streams.map((st) => (st && typeof st === "object" && !Array.isArray(st) ? st : newStream()));
  for (const st of d.streams) {
    if (st.path && !st.endpoint) st.endpoint = st.path;
    delete st.path;
    const fresh = newStream(ENTITY_FIELDS[st.entity] ? st.entity : "event");
    for (const k of ["params", "pagination", "mapping", "transforms"]) if (typeof st[k] !== "object" || st[k] === null || Array.isArray(st[k])) st[k] = fresh[k];
    if (typeof st.transforms.severity_map !== "object" || st.transforms.severity_map === null) st.transforms.severity_map = {};
    for (const k of ["name", "entity", "method"]) if (!st[k]) st[k] = fresh[k];
    if (typeof st.endpoint !== "string") st.endpoint = "";
    if (!st.pagination.type) st.pagination.type = "none";
  }
  if (!d.auth.type) d.auth.type = "none";
  return d;
}

/** A stream name not used yet in this draft: events, events_2, ... */
function uniqueName(base) {
  const taken = new Set(wiz.draft.streams.map((s) => s.name));
  if (!taken.has(base)) return base;
  let n = 2;
  while (taken.has(`${base}_${n}`)) n += 1;
  return `${base}_${n}`;
}

/** Records of a sample response (records path, else the first list of objects) and their field paths. */
function sampleRecords(text, recordsPath) {
  let data;
  try { data = JSON.parse(text); } catch { return []; }
  if (recordsPath) for (const k of String(recordsPath).split(".")) data = data == null ? null : data[k];
  else if (data && !Array.isArray(data) && typeof data === "object") {
    const list = Object.values(data).find((v) => Array.isArray(v) && v.length && typeof v[0] === "object");
    data = list || [data];
  }
  if (data && !Array.isArray(data) && typeof data === "object") data = [data];
  return Array.isArray(data) ? data.filter((r) => r && typeof r === "object" && !Array.isArray(r)) : [];
}
function leafPaths(obj, prefix = "", out = []) {
  for (const [k, v] of Object.entries(obj)) {
    const path = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v) && !prefix) leafPaths(v, path, out); else out.push(path);
  }
  return out;
}
/** Fields of a parent endpoint's records, for the "insert a parent field" picker. */
function parentFields(name) {
  const i = wiz.draft.streams.findIndex((s) => s.name === name);
  if (i < 0) return [];
  const rec = sampleRecords((wiz.ep[i] || {}).sample || "", wiz.draft.streams[i].records_path)[0];
  if (rec) return leafPaths(rec);
  return Object.values(wiz.draft.streams[i].mapping || {}).filter((v) => /^[A-Za-z_][\w.]*$/.test(v));
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

function saveWizard() { const { fieldErrors, tabErrors, ...rest } = wiz; storeSet("wizard", rest); }

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

/* ---------- field renderers: label above, helper text below, the error under the field ---------- */
const SECRET_MSG = "Use an environment variable reference like ${OKTA_TOKEN}. Never paste the secret itself.";
const eg = (ph) => (ph && !/^e\.g\./.test(ph) ? `e.g. ${ph}` : ph);

function input(path, label, { type = "text", placeholder = "", hint = "", secret = false } = {}) {
  let v = getPath(wiz.draft, path);
  if (Array.isArray(v)) v = v.join(", ");
  const err = (secret && v && !ENV_REF.test(v) ? SECRET_MSG : "") || wiz.fieldErrors[path] || "";
  return `<div class="field"><label class="label" for="f_${path}">${esc(label)}</label>
    <input id="f_${path}" data-path="${path}" data-type="${type}" type="${type === "number" ? "number" : "text"}" value="${esc(v ?? "")}" placeholder="${esc(eg(placeholder))}"
      ${secret ? 'data-secret="1" autocomplete="off" spellcheck="false"' : ""} class="${err ? "invalid" : ""}" aria-describedby="e_${path}">
    ${hint ? `<span class="help">${hint}</span>` : ""}<span class="field-error" id="e_${path}" data-err-for="${path}">${esc(err)}</span>
    ${secret ? `<button class="link sm" type="button" data-store-secret="${path}" style="align-self:flex-start">Store a value in the vault…</button>` : ""}</div>`;
}

function select(path, label, options, { switchKind = "", hint = "" } = {}) {
  const v = getPath(wiz.draft, path);
  return `<div class="field"><label class="label" for="f_${path}">${esc(label)}</label>
    <select id="f_${path}" data-path="${path}" ${switchKind ? `data-switch="${switchKind}"` : ""}>
      ${options.map((o) => { const [val, text] = Array.isArray(o) ? o : [o, o]; return `<option value="${esc(val)}" ${String(val) === String(v ?? "") ? "selected" : ""}>${esc(text)}</option>`; }).join("")}
    </select>${hint ? `<span class="help">${hint}</span>` : ""}<span class="field-error" data-err-for="${path}">${esc(wiz.fieldErrors[path] || "")}</span></div>`;
}

function kvEditor(path, label, { keyPh = "key", valPh = "value", valueOptions = null, hint = "" } = {}) {
  const obj = getPath(wiz.draft, path) || {};
  const rows = Object.entries(obj).concat([["", ""]]);
  return `<div class="field"><span class="label">${esc(label)}</span><div class="kv" data-kv="${path}">
    ${rows.map(([k, v]) => `<div class="kv-row">
      <input data-kv-key value="${esc(k)}" placeholder="${esc(eg(keyPh))}" aria-label="Key">
      ${valueOptions
        ? `<select data-kv-val aria-label="Value"><option value=""></option>${valueOptions.map((o) => `<option ${o === v ? "selected" : ""}>${o}</option>`).join("")}</select>`
        : `<input data-kv-val value="${esc(v)}" placeholder="${esc(eg(valPh))}" aria-label="Value">`}
      <button class="icon-btn" data-kv-del title="Remove" aria-label="Remove row">${icon("x")}</button></div>`).join("")}
  </div>${hint ? `<span class="help">${hint}</span>` : ""}<span class="field-error" data-err-for="${path}">${esc(wiz.fieldErrors[path] || "")}</span></div>`;
}
const row2 = (...fields) => `<div class="form-row">${fields.join("")}</div>`;

/* ---------- steps ---------- */
function stepBasics() {
  return `<h2>Basics</h2><p class="lead">Name the tool and point at its API.</p>
    ${row2(input("display_name", "Display name", { placeholder: "Okta" }), input("name", "Integration ID", { placeholder: "okta", hint: "Lowercase letters, digits and underscores. Used as the event source." }))}
    ${input("base_url", "Base URL", { placeholder: "https://www.cisa.gov", hint: "Scheme and host only, e.g. https://api.github.com. May reference a setting from .env, e.g. https://${OKTA_DOMAIN}" })}
    <div id="baseUrlHint">${baseUrlHint(wiz.draft.base_url)}</div>
    ${row2(input("schedule_seconds", "Run every (seconds)", { type: "number", placeholder: "900", hint: "900 = every 15 minutes" }), select("enabled", "Start enabled", [["true", "Yes"], ["false", "No"]]))}`;
}

/** Warn (not block) when the base URL carries a path or a trailing slash: URLs are joined with exactly one "/". */
function baseUrlHint(url) {
  const m = /^(https?:\/\/[^/?#\s]+)(\/[^?#\s]*)?$/i.exec(String(url || "").trim());
  if (!m || !m[2] || m[2] === "") return "";
  if (m[2] === "/") return `<div class="notice">The trailing slash is removed when saving: requests go to <code>${esc(m[1])}/&lt;path&gt;</code>.</div>`;
  const path = m[2].replace(/\/+$/, "");
  return `<div class="notice warn">The base URL has a path (<code>${esc(path)}</code>). Every endpoint path is added after it, so don't repeat it: <code>${esc(m[1] + path)}/users</code>, not <code>${esc(m[1] + path + path)}/users</code>.${m[2].endsWith("/") ? " The trailing slash is removed when saving." : ""}</div>`;
}

function stepAuth() {
  const t = wiz.draft.auth.type;
  const fields = {
    none: `<div class="notice">No credentials: for public feeds.</div>`,
    bearer: input("auth.token", "Token", { secret: true, placeholder: "${MY_TOOL_TOKEN}", hint: "Sent as <code>Authorization: Bearer …</code>" }),
    api_key: row2(input("auth.header", "Header name", { placeholder: "X-API-Key" }), input("auth.api_key", "API key", { secret: true, placeholder: "${MY_TOOL_API_KEY}" })),
    basic: row2(input("auth.username", "Username", { placeholder: "${MY_TOOL_USER}", hint: "Plain value or ${VAR}" }), input("auth.password", "Password", { secret: true, placeholder: "${MY_TOOL_PASSWORD}" })),
    oauth2_client_credentials: input("auth.token_url", "Token URL", { placeholder: "/oauth2/v1/token", hint: "Full URL or a path on the base URL" })
      + row2(input("auth.client_id", "Client ID", { placeholder: "${OKTA_CLIENT_ID}" }), input("auth.client_secret", "Client secret", { secret: true, placeholder: "${OKTA_CLIENT_SECRET}" })),
    session_login: input("auth.login_url", "Login URL", { placeholder: "/api/v2/access/tokens", hint: "Called once; the token it returns is reused until it expires" })
      + row2(input("auth.token_path", "Token path in the response", { placeholder: "token", hint: "JMESPath in the JSON response" }),
        input("auth.token_response_header", "Or: token response header", { placeholder: "X-auth-access-token", hint: "When the token comes back in a header" }))
      + row2(input("auth.header", "Send the token in header", { placeholder: "Authorization" }), input("auth.prefix", "Prefix", { placeholder: "Bearer " }))
      + `<div class="notice">Login body, login headers and Basic credentials: edit them in the YAML panel (secrets as <code>\${NAME}</code>).</div>`,
  }[t] || "";
  return `<h2>Authentication</h2><p class="lead">Secrets never go in the config. Reference a value from <code>.env</code> by name, e.g. <code>\${OKTA_TOKEN}</code>.</p>
    ${select("auth.type", "Auth type", [["none", "None (public)"], ["bearer", "Bearer token"], ["api_key", "API key header"], ["basic", "Basic auth"], ["oauth2_client_credentials", "OAuth2 client credentials"], ["session_login", "Session login (token from a login call)"]], { switchKind: "auth" })}
    ${fields}
    ${input("scopes", "Scopes (comma-separated)", { type: "list", placeholder: "okta.logs.read", hint: "Permissions this credential holds. Prefer read-only scopes." })}
    <div id="scopeBadge">${scopeBadge()}</div>`;
}

const RISKY_SCOPE = /write|admin|manage|delete|owner|root|modify|put|create|update|full|\*|^api$/i;
function scopeBadge() {
  const risky = (wiz.draft.scopes || []).filter((s) => RISKY_SCOPE.test(s));
  return risky.length ? `<div class="notice warn">Write or admin scope: ${esc(risky.join(", "))}. A log connector should be read-only.</div>` : "";
}

function endpointCard(st, i) {
  const fe = st.for_each;
  const only = wiz.draft.streams.length === 1;
  return `<div class="ep-card ${i === wiz.active ? "active" : ""} ${wiz.tabErrors.has(i) ? "has-error" : ""}" data-ep="${i}" role="button" tabindex="0" aria-pressed="${i === wiz.active}" aria-label="Edit endpoint ${esc(st.name)}">
    <div class="ep-top"><span class="ep-num">${i + 1}</span><b class="mono ep-name">${esc(st.name || "(unnamed)")}</b><span class="chip-sm">${esc(entityLabel(st.entity))}</span>
      <span class="ep-actions"><button class="icon-btn" type="button" data-ep-dup="${i}" title="Duplicate" aria-label="Duplicate endpoint ${esc(st.name)}">${icon("copy")}</button>
      <button class="icon-btn" type="button" data-ep-del="${i}" title="${only ? "An integration needs at least one endpoint" : "Remove"}" aria-label="Remove endpoint ${esc(st.name)}" ${only ? "disabled" : ""}>${icon("x")}</button></span></div>
    <div class="ep-path mono" title="${esc(st.endpoint)}">${esc(st.method || "GET")} ${esc(st.endpoint || "(no path yet)")}</div>
    ${fe ? `<div class="muted sm">For each record of <span class="mono">${esc(fe.stream)}</span>${st.merge_into_parent ? " · merged into it" : ""}</div>` : ""}
  </div>`;
}

function stepEndpoints() {
  const st = S(), p = P(), fe = st.for_each;
  const as = (fe && fe.as) || "item";
  return `<h2>Endpoints</h2><p class="lead">One integration can pull several endpoints with the same login. Each endpoint has its own path, paging and mapping, and fills one table.</p>
    <div class="ep-grid">${wiz.draft.streams.map(endpointCard).join("")}
      <button class="ep-add" type="button" id="epAdd">${icon("plus")}Add endpoint</button></div>
    <div class="ep-editor">
      <h3>Endpoint ${wiz.active + 1}: <span class="mono">${esc(st.name)}</span></h3>
      ${row2(input(`${p}.name`, "Endpoint name", { placeholder: "events", hint: "Unique within this integration" }),
        select(`${p}.entity`, "Fills", ENTITY_OPTIONS, { switchKind: "entity", hint: `Fields: ${ENTITY_FIELDS[st.entity].join(", ")}` }))}
      ${row2(select(`${p}.method`, "Method", ["GET", "POST"]),
        input(`${p}.endpoint`, "Path", { placeholder: fe ? `/repos/{{ ${as}.full_name }}/languages` : "/api/v1/logs",
          hint: fe ? `<code>{{ ${esc(as)}.&lt;field&gt; }}</code> is a field of the ${esc(fe.stream)} record` : "Add <code>{{ last_sync }}</code> to a parameter to fetch only new data" }))}
      ${kvEditor(`${p}.params`, "Query parameters (optional)", { keyPh: "since", valPh: "{{ last_sync }}" })}
      ${forEachFields(st, p)}
      <h3>Pagination</h3>
      ${paginationFields(st, p)}
    </div>`;
}

function forEachFields(st, p) {
  const fe = st.for_each;
  const parents = wiz.draft.streams.filter((s, i) => i !== wiz.active && !(s.for_each && s.for_each.stream === st.name));
  const options = [["", "Once per run"], ...parents.map((s) => [s.name, `For each record of ${s.name}`])];
  let html = `<div class="field"><label class="label" for="f_foreach">Run</label>
    <select id="f_foreach" data-foreach>${options.map(([v, t]) => `<option value="${esc(v)}" ${((fe && fe.stream) || "") === v ? "selected" : ""}>${esc(t)}</option>`).join("")}</select>
    <span class="help">"For each record" calls this endpoint once per record of another endpoint (e.g. once per repository). That endpoint runs first.</span>
    <span class="field-error" data-err-for="${p}.for_each">${esc(wiz.fieldErrors[`${p}.for_each`] || "")}</span></div>`;
  if (!fe) return html;
  const parent = wiz.draft.streams.find((s) => s.name === fe.stream);
  const fields = parentFields(fe.stream);
  html += row2(input(`${p}.for_each.as`, "Name of the parent record", { placeholder: "repo", hint: "Used in the path, e.g. {{ repo.full_name }}" }),
    input(`${p}.for_each.where`, "Only records where (optional)", { placeholder: "!description", hint: "JMESPath condition on the parent record" }));
  html += `<div class="field"><span class="label">Insert a parent field into the path</span><div class="chips">${fields.length
    ? fields.slice(0, 40).map((f) => `<button class="chip" type="button" data-insert-field="${esc(f)}">${esc(f)}</button>`).join("")
    : `<span class="muted sm">Fetch a sample of ${esc(fe.stream)} on the Mapping step to list its fields</span>`}</div></div>`;
  const canMerge = parent && parent.entity === st.entity && st.entity !== "event";
  html += row2(input(`${p}.for_each.concurrency`, "Parallel requests", { type: "number", placeholder: "4", hint: "1-16. Rate limits, Retry-After and retries still apply" }),
    canMerge ? select(`${p}.merge_into_parent`, "Store the result", [["false", "As new records"], ["true", `Merged into the ${parent.name} record`]],
      { hint: "Merged: adds fields (e.g. languages) to the parent record" }) : "<div></div>");
  return html;
}

function paginationFields(st, p) {
  const t = st.pagination.type;
  const pp = `${p}.pagination.`;
  const fields = {
    none: `<div class="notice">One request per run${st.for_each ? " (per parent record)" : ""}.</div>`,
    page: row2(input(`${pp}page_param`, "Page parameter", { placeholder: "page" }), input(`${pp}size_param`, "Page-size parameter", { placeholder: "page_size" }))
      + row2(input(`${pp}page_size`, "Page size", { type: "number", placeholder: "100" }), input(`${pp}total_pages_path`, "Total pages path (optional)", { placeholder: "total_pages", hint: "JMESPath in the response" })),
    offset: row2(input(`${pp}limit_param`, "Limit parameter", { placeholder: "limit" }), input(`${pp}offset_param`, "Offset parameter", { placeholder: "offset" }))
      + row2(input(`${pp}limit`, "Page size", { type: "number", placeholder: "100" }), input(`${pp}total_path`, "Total count path (optional)", { placeholder: "totalResults" })),
    cursor: row2(input(`${pp}cursor_path`, "Cursor path in the response", { placeholder: "meta.next_cursor", hint: "JMESPath; stops when empty" }), input(`${pp}cursor_param`, "Cursor parameter", { placeholder: "cursor" })),
    link: input(`${pp}next_path`, "Next URL path in the body (optional)", { placeholder: "links.next", hint: 'Leave empty to follow the <code>Link: &lt;…&gt;; rel="next"</code> header (Okta, GitHub). Links to other hosts are refused.' }),
  }[t] || "";
  return `${row2(select(`${pp}type`, "Pagination type", [["none", "None"], ["page", "Page number"], ["offset", "Limit / offset"], ["cursor", "Cursor / token"], ["link", "Next link (Link header)"]], { switchKind: "pagination" }),
      t === "none" ? "<div></div>" : input(`${pp}max_pages`, "Max pages per run", { type: "number", placeholder: "10" }))}
    ${fields}`;
}

function confBar(c) {
  const pct = Math.round((c || 0) * 100);
  const colour = c >= 0.8 ? "var(--ok)" : c >= 0.5 ? "var(--warn)" : "var(--bad)";
  return `<div class="conf"><div class="conf-bar"><span style="width:${pct}%;background:${colour}"></span></div>${pct}%</div>`;
}
const engineLabel = (e) => (e && e.startsWith("AI") ? `AI · ${e.replace(/^AI \(|\)$/g, "")}` : "Rule-based");

/** One tab per endpoint (Mapping and Test steps); on Test each tab carries the endpoint's pass/fail badge. */
function endpointTabs(withBadges = false) {
  return `<div class="ep-tabs" role="tablist" aria-label="Endpoints">${wiz.draft.streams.map((s, i) => {
    const r = withBadges ? testResult(s.name) : null;
    const badge = r ? `<span class="pill ${r.cls}"><i></i>${esc(r.label)}</span>` : "";
    return `<button class="ep-tab ${i === wiz.active ? "active" : ""} ${wiz.tabErrors.has(i) ? "has-error" : ""}" type="button" role="tab" aria-selected="${i === wiz.active}" data-ep="${i}">
      <span class="mono">${esc(s.name)}</span><span class="muted sm">${esc(entityLabel(s.entity))}</span>${badge}</button>`;
  }).join("")}</div>`;
}

function checkMark(field) {
  const c = (EP().check || {}).fields || {};
  const r = c[field];
  if (!r) return "";
  if (!r.ok) return `<span class="map-check bad">${r.error ? esc(r.error) : "Not found in the sample"}</span>`;
  if (r.note) return `<span class="map-check muted">${esc(r.note)}</span>`;
  const ex = typeof r.example === "object" ? JSON.stringify(r.example) : String(r.example);
  return `<span class="map-check ok" title="${esc(ex)}">✓ ${esc(ex.length > 40 ? `${ex.slice(0, 40)}…` : ex)}${r.found_in < r.of ? ` <span class="muted">(${r.found_in}/${r.of})</span>` : ""}</span>`;
}

const checkInfo = (c) => (c ? `Path check against the sample: ${c.error ? esc(c.error) : `${fmtN(c.records)} record${c.records === 1 ? "" : "s"}`}` : "");

function stepMapping() {
  const e = EP();
  const s = e.suggestion;
  const paths = s ? s.available_paths.map((x) => x.path) : [];
  const datalist = `<datalist id="pathOptions">${paths.map((x) => `<option value="${esc(x)}">`).join("")}</datalist>`;
  const st = S(), p = P(), fe = st.for_each;
  const entity = st.entity;
  const required = st.merge_into_parent ? [] : REQUIRED_FIELDS[entity] || ["id"];
  let ai = "";
  if (s) {
    const isAi = s.engine.startsWith("AI");
    const hint = s.pagination_hint || {};
    const showHint = hint.type && hint.type !== st.pagination.type;
    ai = `<div class="card" style="display:flex;flex-direction:column;gap:12px">
      <div class="card-head" style="margin:0;flex-wrap:wrap"><h3>Suggested mapping</h3><span class="engine ${isAi ? "ai" : ""}" title="${esc(s.fallback_reason || s.engine)}">${esc(engineLabel(s.engine))}</span>
        <span class="muted sm" style="margin-left:auto">${fmtN(s.record_count)} records · records path <code>${esc(s.records_path || "(root list)")}</code></span></div>
      ${s.fallback_reason ? `<div class="muted sm">${esc(s.fallback_reason)}</div>` : ""}
      ${showHint ? `<div class="notice">Pagination looks like <b>${esc(PAGING_LABEL[hint.type] || hint.type)}</b>: ${esc((hint.evidence || []).join(" "))} <button class="link" id="applyPagination">Use it</button></div>` : ""}
      <div class="table-wrap"><table class="table map-table"><thead><tr><th>Tool field</th><th></th><th>Common field</th><th>Example</th><th>Confidence</th></tr></thead><tbody>
      ${s.fields.map((f, i) => {
        const note = f.status === "needs_manual" ? `<div class="field-error">${esc(f.note || "Needs a manual path")}</div>`
          : f.status === "low_confidence" ? `<div class="muted sm" style="color:var(--warn)">${esc(f.note || "Check this one")}</div>` : "";
        return `<tr><td style="min-width:150px"><input list="pathOptions" data-sugg="${i}" value="${esc(f.path)}" placeholder="not mapped" aria-label="Tool field for ${esc(f.field)}">${note}</td>
          <td class="muted">→</td><td><span class="mono">${esc(f.field)}</span> <span class="muted sm">${f.source === "ai" ? "AI" : "rules"}</span></td>
          <td><div class="map-example" title="${esc(f.example == null ? "" : JSON.stringify(f.example))}">${esc(f.example == null ? "" : JSON.stringify(f.example))}</div></td><td>${confBar(f.confidence)}</td></tr>`;
      }).join("")}</tbody></table></div>
      ${s.entity === "event" ? `<div class="muted sm">Severity map <code>${esc(JSON.stringify(s.severity_map))}</code>${s.default_severity ? ` · default severity <b>${esc(s.default_severity)}</b>` : ""}</div>` : ""}
      ${(s.notes || []).map((n) => `<div class="muted sm">${esc(n)}</div>`).join("")}
      <div style="display:flex;align-items:center;gap:12px"><button class="btn primary" id="applySuggestion">Apply to ${esc(st.name)}</button><span class="muted sm">AI suggests, code checks every path against the sample, you approve.</span></div>
    </div>`;
  }
  const notes = [];
  if (fe) notes.push(`Runs once per record of <span class="mono">${esc(fe.stream)}</span>: the sample is fetched for its first record. Use <code>parent().field</code> for fields of that record.`);
  if (st.merge_into_parent) notes.push(`Merged into the <span class="mono">${esc(fe.stream)}</span> record: map only the fields this endpoint adds (the id comes from the parent).`);
  const check = e.check;
  return `<h2>Field mapping</h2><p class="lead">Each endpoint has its own mapping. Fetch or paste one sample response, let the assistant suggest the mapping, then review it.</p>
    ${endpointTabs()}
    ${datalist}
    <div class="muted sm">Endpoint <span class="mono">${esc(st.method || "GET")} ${esc(st.endpoint)}</span> fills <b>${esc(entityLabel(entity))}</b> · fields: ${esc(ENTITY_FIELDS[entity].join(", "))} (source and fetched_at are added automatically)</div>
    ${notes.map((n) => `<div class="notice">${n}</div>`).join("")}
    <div class="field"><label class="label" for="sampleInput">Sample API response for ${esc(st.name)} (JSON)</label>
      <textarea id="sampleInput" class="mono" rows="8" spellcheck="false" placeholder='e.g. {"data": [ ... ]}'>${esc(e.sample)}</textarea></div>
    <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn secondary" id="fetchSample">Fetch sample from API</button>${gatedBtn("admin", "Suggest mapping", 'id="suggestBtn"', "btn primary")}</div>
    ${ai}
    <h2 style="margin-top:8px">Mapping saved for ${esc(st.name)}</h2>
    <div class="muted sm" id="checkInfo">${checkInfo(check)}</div>
    ${row2(input(`${p}.records_path`, "Records path", { placeholder: "data.alerts", hint: "JMESPath to the list of records; empty = the response is the list" }),
      select(`${p}.transforms.time_format`, `Time format (${TIME_FIELD[entity]})`, [["iso8601", "ISO 8601"], ["epoch_s", "Epoch seconds"], ["epoch_ms", "Epoch milliseconds"]]))}
    <div class="form-row">${ENTITY_FIELDS[entity].map((f) => `<div class="field"><label class="label" for="m_${f}">${f}${required.includes(f) ? ' <span class="req" title="Required">*</span>' : ""}</label>
      <input id="m_${f}" class="mono ${wiz.fieldErrors[`${p}.mapping.${f}`] ? "invalid" : ""}" list="pathOptions" data-path="${p}.mapping.${f}" value="${esc(st.mapping[f] || "")}" placeholder="not mapped">
      <span class="field-error" data-err-for="${p}.mapping.${f}">${esc(wiz.fieldErrors[`${p}.mapping.${f}`] || "")}</span>${checkMark(f)}</div>`).join("")}</div>
    <span class="field-error" data-err-for="${p}.mapping">${esc(wiz.fieldErrors[`${p}.mapping`] || "")}</span>
    ${entity === "event" ? select(`${p}.transforms.default_severity`, "Default severity (when the value is missing or unknown)", ["", ...SEVERITIES].map((x) => [x, x ? cap(x) : "None"])) : ""}
    ${entity === "event" ? kvEditor(`${p}.transforms.severity_map`, "Severity map (tool value → common severity)", { keyPh: "alert", valueOptions: SEVERITIES }) : ""}`;
}

/** Pass / fail of one endpoint in the last test run. */
function testResult(name) {
  const r = ((wiz.test || {}).streams || []).find((x) => x.name === name);
  if (!r) return null;
  const status = String(r.status || "");
  if (status === "ok") {
    const failed = (!(r.normalised || []).length && (r.quarantined || []).length) || (r.item_errors || []).length;
    return { ...r, pass: !failed, cls: failed ? "bad" : "ok", label: failed ? "Fail" : "Pass" };
  }
  if (status.startsWith("skipped") || status.startsWith("not available")) return { ...r, skipped: true, cls: "idle", label: "Skipped" };
  return { ...r, pass: false, cls: "bad", label: "Fail" };
}

function stepTest() {
  const t = wiz.test;
  let out = "";
  if (t) {
    const results = wiz.draft.streams.map((s) => testResult(s.name)).filter(Boolean);
    const ran = results.filter((r) => !r.skipped);
    const failed = ran.filter((r) => !r.pass);
    const overall = !t.ok ? ["bad", `Test failed${t.stage === "validation" ? ": the config is not valid" : ""}`]
      : failed.length ? ["bad", `${failed.length} of ${ran.length} endpoint${ran.length === 1 ? "" : "s"} failed`]
      : ["ok", `All ${ran.length} endpoint${ran.length === 1 ? "" : "s"} passed`];
    out = `<div class="test-overall ${overall[0]}"><span class="pill ${overall[0]}"><i></i>${overall[0] === "ok" ? "Pass" : "Fail"}</span><b>${esc(overall[1])}</b><span class="muted sm">Nothing was saved.</span></div>
      ${(t.errors || []).length ? `<div class="form-alert" style="margin:0"><ul>${t.errors.map((e) => `<li>${esc(humanizeMsg(e))}</li>`).join("")}</ul></div>` : ""}
      ${results.length ? endpointTabs(true) + testPanel(testResult(S().name)) : ""}`;
  }
  return `<h2>Test</h2><p class="lead">Runs every endpoint once against the real API <b>without saving</b> and shows the first 5 records of each, raw and normalised.</p>
    <div>${gatedBtn("admin", `${icon("play")}Run test`, 'id="runTest"', "btn primary")}</div>${out}`;
}

function testPanel(r) {
  if (!r) return `<div class="muted">This endpoint was not part of the last test run. Run the test again.</div>`;
  if (r.status !== "ok") return `<div class="notice ${r.skipped ? "" : "warn"}"><b>${esc(r.name)}:</b> ${esc(r.error || r.status)}</div>`;
  const view = wiz.testView === "raw" ? "raw" : "normalised";
  const rows = view === "raw" ? (r.raw || []) : (r.normalised || []);
  const fan = r.for_each ? `<div class="muted sm">Ran for ${fmtN(r.items)} of ${fmtN(r.eligible)} ${esc(r.for_each)} record${r.eligible === 1 ? "" : "s"} (a test uses the first 3)${r.skipped ? ` · ${fmtN(r.skipped)} skipped: ${esc(Object.entries(r.skipped_reasons || {}).map(([k, n]) => `${n} × ${k}`).join("; "))}` : ""}</div>` : "";
  return `<div class="notice ${r.pass ? "ok" : "warn"}">${esc(r.name)}: normalised ${fmtN((r.normalised || []).length)} sample record${(r.normalised || []).length === 1 ? "" : "s"} from ${fmtN(r.pages)} page${r.pages === 1 ? "" : "s"}${r.retries ? `, ${r.retries} retr${r.retries === 1 ? "y" : "ies"} (${esc((r.retry_log || []).join("; "))})` : ""}.</div>
    ${fan}
    <div class="seg" role="tablist" aria-label="Sample view"><button class="chip ${view === "normalised" ? "active" : ""}" data-test-view="normalised" aria-pressed="${view === "normalised"}">Normalised · common schema</button>
      <button class="chip ${view === "raw" ? "active" : ""}" data-test-view="raw" aria-pressed="${view === "raw"}">Raw · from the tool</button></div>
    <pre class="code">${esc(JSON.stringify(rows.slice(0, 5), null, 2))}</pre>
    ${(r.quarantined || []).length ? `<div class="notice warn"><b>${r.quarantined.length} record(s) would be quarantined:</b><ul style="margin:4px 0 0">${r.quarantined.map((q) => `<li>${esc(q.reason)}</li>`).join("")}</ul></div>` : ""}
    ${(r.item_errors || []).length ? `<div class="notice warn"><b>Failed items:</b><ul style="margin:4px 0 0">${r.item_errors.map((m) => `<li>${esc(m)}</li>`).join("")}</ul></div>` : ""}`;
}

function stepSave() {
  const d = clean(wiz.draft);
  const streams = d.streams || [];
  const tables = [...new Set(streams.map((s) => ENTITY_STREAM_NAME[s.entity] || "events"))];
  const saved = wiz.saved
    ? `<div class="notice ok">${esc(wiz.saved)} <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap">
        ${tables.map((t) => `<a class="btn secondary sm" href="#${t === "repositories" ? "repositories" : t}">See ${esc(t)}</a>`).join("")}<a class="btn secondary sm" href="#integrations">View health</a></div></div>` : "";
  return `<h2>Save and go live</h2><p class="lead">Saving writes <code>configs/integrations/${esc(d.name || "…")}.yaml</code> and schedules it right away. No restart, no code.</p>
    <dl class="summary">
      <dt>Integration</dt><dd>${esc(d.display_name || "-")} <span class="muted mono">${esc(d.name || "")}</span></dd>
      <dt>Base URL</dt><dd class="mono">${esc(d.base_url || "")}</dd>
      <dt>Auth</dt><dd>${esc(AUTH_LABEL[d.auth?.type] || d.auth?.type)}</dd>
      <dt>Schedule</dt><dd>every ${esc(d.schedule_seconds)} s</dd>
      <dt>Endpoints</dt><dd>${streams.length}</dd>
    </dl>
    <div class="table-wrap"><table class="table"><thead><tr><th>Endpoint</th><th>Request</th><th>Fills</th><th>Paging</th><th>Mapping</th></tr></thead><tbody>
      ${streams.map((s) => `<tr><td class="mono">${esc(s.name)}</td><td><span class="mono">${esc(s.method || "GET")} ${esc(s.endpoint || "")}</span>${s.for_each ? `<div class="muted sm">for each ${esc(s.for_each.stream)} record${s.merge_into_parent ? " · merged" : ""}</div>` : ""}</td>
        <td>${esc(entityLabel(s.entity || "event"))}</td><td>${esc(PAGING_LABEL[(s.pagination || {}).type || "none"])}</td>
        <td><span class="mono sm" title="${esc(Object.entries(s.mapping || {}).map(([k, v]) => `${k} ← ${v}`).join(", "))}">${Object.keys(s.mapping || {}).length} field${Object.keys(s.mapping || {}).length === 1 ? "" : "s"}</span></td></tr>`).join("")}
    </tbody></table></div>
    <div style="display:flex;gap:8px">${gatedBtn("admin", "Save and go live", 'id="saveBtn"', "btn primary")}<button class="btn danger hidden" id="overwriteBtn">Overwrite existing</button></div>${saved}`;
}

const STEP_RENDER = { basics: stepBasics, auth: stepAuth, endpoints: stepEndpoints, mapping: stepMapping, test: stepTest, save: stepSave };

function renderStepper() {
  $("#stepper").innerHTML = STEPS.map((s, i) => {
    const done = i < wiz.step || (i < wiz.maxStep && i !== wiz.step);
    const reachable = i <= wiz.maxStep || i === wiz.step + 1;
    return `${i ? '<span class="sep"></span>' : ""}<li data-step="${i}" class="${i === wiz.step ? "active" : done ? "done" : ""} ${reachable ? "reachable" : ""}" ${i === wiz.step ? 'aria-current="step"' : ""}>
      <span class="num">${done ? svg("check") : i + 1}</span>${s.title}</li>`;
  }).join("");
}

function renderStep() {
  syncEndpointState();
  const step = STEPS[wiz.step];
  $("#stepBody").innerHTML = STEP_RENDER[step.id]();
  $("#stepBody").classList.toggle("wide", ["endpoints", "mapping", "test"].includes(step.id));
  const enabledSel = $('select[data-path="enabled"]');
  if (enabledSel) enabledSel.value = String(wiz.draft.enabled !== false);
  $("#wizBack").disabled = wiz.step === 0;
  $("#wizNext").classList.toggle("hidden", wiz.step === STEPS.length - 1);
  $("#wizNext").textContent = wiz.step === STEPS.length - 2 ? "Continue to save" : "Next";
  renderStepper();
}

function renderWizard() {
  if (!$("#stepBody")) return;
  wiz.draft = ensureShape(wiz.draft);
  renderStep();
  syncYaml(true);
}

/** "streams.2 a repository needs ..." -> "Endpoint repo_languages: a repository needs ..." */
function humanizeMsg(msg) {
  return String(msg).replace(/^streams\.(\d+)(\.[\w.]+)?[:\s]*/, (all, i, rest) => {
    const s = wiz.draft.streams[Number(i)];
    return s ? `Endpoint ${s.name}${rest ? ` (${rest.slice(1)})` : ""}: ` : all;
  });
}

/** Server messages start with the field path ("streams.0.endpoint: ..."): show each under its field, the rest in one alert.
 *  Messages about another endpoint mark its card / tab in red. */
function showStepErrors(list) {
  wiz.fieldErrors = {};
  wiz.tabErrors = new Set(list.map((m) => (String(m).match(/^streams\.(\d+)/) || [])[1]).filter((i) => i !== undefined).map(Number));
  const loose = [];
  const fields = $$("#stepBody [data-err-for]").map((el) => el.dataset.errFor).sort((a, b) => b.length - a.length);
  for (const msg of list) {
    const path = fields.find((p) => msg === p || msg.startsWith(`${p}:`) || msg.startsWith(`${p} `) || msg.startsWith(`${p}.`));
    if (!path) { loose.push(humanizeMsg(msg)); continue; }
    let text = msg.slice(path.length).replace(/^[:.\s]+/, "") || msg;
    if (/^(is|are|must|should|cannot|can't) /.test(text)) {  // "is required" -> "Display name is required"
      const label = $(`#stepBody [data-err-for="${CSS.escape(path)}"]`).closest(".field")?.querySelector(".label");
      text = `${label ? label.textContent.replace("*", "").trim() : path} ${text}`;
    }
    wiz.fieldErrors[path] = (wiz.fieldErrors[path] ? `${wiz.fieldErrors[path]} ` : "") + cap(text);
  }
  $$("#stepBody [data-err-for]").forEach((el) => {
    const m = wiz.fieldErrors[el.dataset.errFor];
    const field = el.closest(".field");
    if (m !== undefined || !field || !field.querySelector("[data-secret]")) el.textContent = m || "";
    const ctl = field && field.querySelector("input, select");
    if (ctl && !ctl.dataset.secret) ctl.classList.toggle("invalid", !!m);
  });
  $$("#stepBody [data-ep]").forEach((el) => el.classList.toggle("has-error", wiz.tabErrors.has(Number(el.dataset.ep))));
  const box = $("#stepErrors");
  box.classList.toggle("hidden", !loose.length);
  box.innerHTML = loose.length ? `<b>Please fix:</b><ul>${loose.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>` : "";
  const first = $("#stepBody .invalid");
  if (first) first.focus();
}

/** Validate the current step: client checks + server validation filtered to this step's fields. */
async function validateStep() {
  const step = STEPS[wiz.step];
  const errs = [];
  $$("#stepBody [data-secret]").forEach((el) => {
    if (el.value && !ENV_REF.test(el.value)) errs.push(`${el.dataset.path}: ${SECRET_MSG}`);
  });
  if (step.id === "endpoints") {
    const seen = new Map();
    wiz.draft.streams.forEach((s, i) => {
      const name = String(s.name || "").trim();
      if (name && seen.has(name)) errs.push(`streams.${i}.name: Another endpoint is already called "${name}"`);
      seen.set(name, i);
    });
  }
  if (step.id === "mapping") {
    wiz.draft.streams.forEach((s, i) => {
      const mapped = Object.entries(s.mapping || {}).filter(([, v]) => v);
      if (s.merge_into_parent) {
        if (!mapped.length) errs.push(`streams.${i}.mapping: Map at least one field to merge into the parent record`);
        return;
      }
      for (const f of REQUIRED_FIELDS[s.entity] || ["id"]) {
        if (!(s.mapping || {})[f]) errs.push(`streams.${i}.mapping.${f}: Required for ${entityLabel(s.entity).toLowerCase()}`);
      }
    });
  }
  if (!step.owns) return errs;
  try {
    await api("/api/integrations/validate", { method: "POST", body: { config: clean(wiz.draft) } });
  } catch (e) {
    for (const msg of errorList(e)) {
      if (e.status !== 422 || step.owns(msg)) errs.push(msg);
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
  wiz.fieldErrors = {};
  renderStep();
  saveWizard();
  $("#content").scrollIntoView({ block: "start" });
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
  if (el.dataset.foreach !== undefined) {
    if (ev.type !== "change") return;
    const st = S();
    if (!el.value) { delete st.for_each; delete st.merge_into_parent; delete st.parent_status; }
    else st.for_each = { stream: el.value, as: (st.for_each && st.for_each.as) || el.value.replace(/ies$/, "y").replace(/s$/, ""), ...(st.for_each && st.for_each.where ? { where: st.for_each.where } : {}) };
    renderStep(); syncYaml(); return;
  }
  if (el.dataset.path) {
    const path = el.dataset.path;
    let value = el.value;
    if (el.dataset.switch === "auth") { wiz.draft.auth = copy(AUTH_DEFAULTS[value]); renderStep(); syncYaml(); return; }
    if (el.dataset.switch === "pagination") { S().pagination = copy(PAGINATION_DEFAULTS[value]); renderStep(); syncYaml(); return; }
    if (el.dataset.switch === "entity") {
      const st = S();
      const defaultName = !st.name || /^(users|devices|events|repositories)(_\d+)?$/.test(st.name);
      Object.assign(st, { entity: value, mapping: {} });
      if (defaultName) { st.name = ""; st.name = uniqueName(ENTITY_STREAM_NAME[value]); }
      st.transforms = value === "event" ? { severity_map: {}, time_format: st.transforms.time_format || "iso8601" } : { time_format: st.transforms.time_format || "iso8601" };
      if (value === "event" || !wiz.draft.streams.some((s) => s.name === (st.for_each || {}).stream && s.entity === value)) delete st.merge_into_parent;
      Object.assign(EP(), { suggestion: null, check: null });
      renderStep(); syncYaml(); return;
    }
    if (path === "enabled") value = value === "true";
    else if (path.endsWith(".merge_into_parent")) value = value === "true" ? true : undefined;
    else if (el.dataset.type === "number") value = value === "" ? undefined : Number(value);
    else if (el.dataset.type === "list") { value = value.split(/[,\s]+/).filter(Boolean); if (!value.length) value = undefined; }
    else if ((path.includes(".mapping.") || path.endsWith("default_severity") || path.includes(".for_each.")) && value.trim() === "") value = undefined;
    setPath(wiz.draft, path, value);
    if (wiz.fieldErrors[path]) { delete wiz.fieldErrors[path]; const m = $(`[data-err-for="${CSS.escape(path)}"]`); if (m) m.textContent = ""; el.classList.remove("invalid"); }
    if (el.dataset.secret) {
      const bad = el.value && !ENV_REF.test(el.value);
      el.classList.toggle("invalid", bad);
      const msg = $(`[data-err-for="${CSS.escape(path)}"]`);
      if (msg) msg.textContent = bad ? SECRET_MSG : "";
    }
    if (path === "scopes" && $("#scopeBadge")) $("#scopeBadge").innerHTML = scopeBadge();
    if (path === "base_url" && $("#baseUrlHint")) $("#baseUrlHint").innerHTML = baseUrlHint(value);
    // keep the endpoint card in step without re-rendering (the field keeps focus)
    const card = $(`.ep-card[data-ep="${wiz.active}"]`);
    if (card && path === `${P()}.name`) $(".ep-name", card).textContent = value || "(unnamed)";
    if (card && (path === `${P()}.endpoint` || path === `${P()}.method`)) $(".ep-path", card).textContent = `${S().method || "GET"} ${S().endpoint || "/"}`;
    if (path.startsWith(`${P()}.mapping.`) || path === `${P()}.records_path`) scheduleCheck();
    syncYaml();
    return;
  }
  const kv = el.closest("[data-kv]");
  if (kv) {
    setPath(wiz.draft, kv.dataset.kv, readKv(kv));
    const rows = $$(".kv-row", kv);
    const last = rows[rows.length - 1];
    if ($("[data-kv-key]", last).value.trim() && ev.type === "change") renderStep();  // keep one empty row at the bottom
    syncYaml();
    return;
  }
  if (el.dataset.sugg !== undefined && EP().suggestion) {
    EP().suggestion.fields[Number(el.dataset.sugg)].path = el.value.trim();
    saveWizard();
  }
  if (el.id === "sampleInput") { EP().sample = el.value; saveWizard(); scheduleCheck(); }
}

/** Per-endpoint path verification: check every mapped path against this endpoint's sample (server-side JMESPath). */
let checkTimer = null;
function scheduleCheck() { clearTimeout(checkTimer); checkTimer = setTimeout(checkPaths, 400); }
async function checkPaths() {
  const e = EP(), st = S(), idx = wiz.active;
  if (!e.sample.trim() || STEPS[wiz.step].id !== "mapping") return;
  try {
    const r = await api("/api/mapping/check", { method: "POST", body: { sample: e.sample, records_path: st.records_path || null, mapping: st.mapping } });
    wiz.ep[idx].check = r;
  } catch { wiz.ep[idx].check = null; }
  if (idx !== wiz.active || STEPS[wiz.step].id !== "mapping") return;
  if ($("#checkInfo")) $("#checkInfo").innerHTML = checkInfo(wiz.ep[idx].check);
  for (const f of ENTITY_FIELDS[st.entity]) {
    const input = $(`#m_${f}`);
    if (!input) continue;
    const old = input.parentElement.querySelector(".map-check");
    if (old) old.remove();
    input.parentElement.insertAdjacentHTML("beforeend", checkMark(f));
  }
}

function selectEndpoint(i) {
  if (i === wiz.active || i < 0 || i >= wiz.draft.streams.length) return;
  wiz.active = i;
  wiz.fieldErrors = {};
  renderStep();
  saveWizard();
  if (STEPS[wiz.step].id === "mapping" && EP().sample && !EP().check) scheduleCheck();
}

function addEndpoint(from = null) {
  const src = from === null ? null : wiz.draft.streams[from];
  const st = src ? copy(src) : newStream("event", uniqueName("events"));
  st.name = uniqueName(src ? `${src.name}_copy`.slice(0, 44) : st.name);
  const at = from === null ? wiz.draft.streams.length : from + 1;
  wiz.draft.streams.splice(at, 0, st);
  wiz.ep.splice(at, 0, src ? copy(wiz.ep[from] || newEndpointState()) : newEndpointState());
  wiz.active = at;
  wiz.test = null;
  renderStep(); syncYaml();
  const name = $(`[data-path="${P()}.name"]`);
  if (name) { name.focus(); name.select(); }
}

function removeEndpoint(i) {
  const st = wiz.draft.streams[i];
  if (!st || wiz.draft.streams.length === 1) return;
  const children = wiz.draft.streams.filter((s) => s.for_each && s.for_each.stream === st.name).map((s) => s.name);
  if (!confirm(`Remove the endpoint "${st.name}"?${children.length ? ` ${children.join(", ")} run${children.length === 1 ? "s" : ""} for each of its records and will run once per run instead.` : ""}`)) return;
  for (const s of wiz.draft.streams) if (s.for_each && s.for_each.stream === st.name) { delete s.for_each; delete s.merge_into_parent; delete s.parent_status; }
  wiz.draft.streams.splice(i, 1);
  wiz.ep.splice(i, 1);
  wiz.active = Math.min(wiz.active >= i && wiz.active > 0 ? wiz.active - 1 : wiz.active, wiz.draft.streams.length - 1);
  wiz.test = null;
  renderStep(); syncYaml();
}

function insertParentField(field) {
  const st = S();
  const as = (st.for_each && st.for_each.as) || "item";
  const token = `{{ ${as}.${field} }}`;
  const el = $(`[data-path="${P()}.endpoint"]`);
  const text = st.endpoint || "/";
  const at = el && document.activeElement === el ? el.selectionStart : text.length;
  st.endpoint = text.slice(0, at) + token + text.slice(at);
  renderStep(); syncYaml();
  const again = $(`[data-path="${P()}.endpoint"]`);
  if (again) { again.focus(); again.setSelectionRange(at + token.length, at + token.length); }
}

async function onWizardClick(ev) {
  const el = ev.target.closest("button, li[data-step], [data-ep]");
  if (!el || el.disabled) return;
  if (el.matches("li[data-step]")) {
    const target = Number(el.dataset.step);
    if (target <= wiz.maxStep || target === wiz.step + 1) goStep(target);
    return;
  }
  if (el.hasAttribute("data-ep-dup")) return addEndpoint(Number(el.dataset.epDup));
  if (el.hasAttribute("data-ep-del")) return removeEndpoint(Number(el.dataset.epDel));
  if (el.hasAttribute("data-ep")) return selectEndpoint(Number(el.dataset.ep));
  if (el.hasAttribute("data-insert-field")) return insertParentField(el.dataset.insertField);
  if (el.hasAttribute("data-test-view")) { wiz.testView = el.dataset.testView; renderStep(); return; }
  if (el.hasAttribute("data-store-secret")) {
    const path = el.dataset.storeSecret;
    const name = prompt("Secret name (it becomes a ${NAME} reference in the config):", (getPath(wiz.draft, path) || "").replace(/^\$\{|\}$/g, "") || "MY_TOOL_SECRET");
    if (!name) return;
    const value = prompt(`Value for ${name} (stored encrypted; it is never shown again):`);
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
    case "epAdd": return addEndpoint();
    case "fetchSample": return fetchSample(el);
    case "suggestBtn": return suggest(el);
    case "applySuggestion": return applySuggestion();
    case "applyPagination": {
      const { evidence, ...hint } = EP().suggestion.pagination_hint;
      S().pagination = Object.assign(copy(PAGINATION_DEFAULTS[hint.type]), hint);
      toast(`Pagination set to ${PAGING_LABEL[hint.type] || hint.type}`, "ok");
      renderStep(); syncYaml();
      return;
    }
    case "runTest": return runTest(el);
    case "saveBtn": return save(false);
    case "overwriteBtn": return save(true);
  }
}

function onWizardKey(ev) {
  const card = ev.target.closest(".ep-card[data-ep]");
  if (card && ev.target === card && (ev.key === "Enter" || ev.key === " ")) { ev.preventDefault(); selectEndpoint(Number(card.dataset.ep)); }
}

async function withBusy(btn, label, fn) {
  const original = btn.innerHTML;
  btn.disabled = true;
  btn.textContent = label;
  try { await fn(); } finally { btn.disabled = false; btn.innerHTML = original; }
}

async function fetchSample(btn) {
  const idx = wiz.active;
  await withBusy(btn, "Fetching…", async () => {
    try {
      const r = await api("/api/integrations/sample", { method: "POST", body: { config: clean(wiz.draft), stream: idx } });
      if (!r.ok) { showStepErrors(r.errors); return; }
      Object.assign(wiz.ep[idx], { sample: JSON.stringify(r.sample, null, 2), linkHeader: !!r.link_next });
      if (idx === wiz.active) $("#sampleInput").value = wiz.ep[idx].sample;
      showStepErrors([]);
      toast(r.trimmed ? `Sample fetched for ${wiz.draft.streams[idx].name}: showing 20 of ${fmtN(r.record_count)} records`
        : `Sample fetched for ${wiz.draft.streams[idx].name}: ${fmtN(r.record_count)} records`, "ok");
    } catch (e) { showStepErrors(errorList(e)); }
  });
  if (idx === wiz.active && EP().sample && can("admin")) await suggest($("#suggestBtn"));
  else scheduleCheck();
}

async function suggest(btn) {
  const text = $("#sampleInput").value.trim();
  if (!text) { showStepErrors(["Paste a sample API response first, or fetch one from the API"]); return; }
  const idx = wiz.active, e = EP();
  await withBusy(btn, "Analysing…", async () => {
    try {
      if (text !== e.sample) e.linkHeader = false; // pasted by hand: no response headers available
      e.sample = text;
      e.suggestion = await api("/api/ai/suggest-mapping", { method: "POST", body: { sample: text, entity: wiz.draft.streams[idx].entity, link_header: !!e.linkHeader } });
      showStepErrors([]);
      saveWizard();
    } catch (err) { showStepErrors(errorList(err)); }
  });
  renderStep();
  scheduleCheck();
}

function applySuggestion() {
  const s = EP().suggestion;
  const st = S();
  const keep = st.merge_into_parent ? ["id"] : [];
  st.mapping = Object.fromEntries(s.fields.filter((f) => f.path && !keep.includes(f.field)).map((f) => [f.field, f.path]));
  st.records_path = s.records_path || "";
  st.transforms.time_format = s.time_format;
  if (st.entity === "event") {
    st.transforms.severity_map = { ...s.severity_map };
    if (s.default_severity) st.transforms.default_severity = s.default_severity;
  }
  toast(`Mapping applied to ${st.name}: review it below`, "ok");
  renderStep();
  syncYaml();
  scheduleCheck();
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
    toast("Saved", "ok");
    await loadIntegrations();
  } catch (e) {
    const errs = errorList(e);
    renderStep();
    showStepErrors(errs);
    if (errs.some((m) => m.includes("already exists"))) $("#overwriteBtn").classList.remove("hidden");
    return;
  }
  renderStep();
  saveWizard();
}

/** Does the draft hold anything the user typed (so restoring or discarding it matters)? */
function draftHasContent(d) {
  return !!(d && (d.name || d.display_name || (d.base_url && d.base_url !== "https://")
    || (d.streams || []).some((s) => (s.endpoint && s.endpoint !== "/") || Object.keys(s.mapping || {}).length)));
}
const draftLabel = (d) => d.display_name || d.name || d.base_url || "untitled";

function showDraftNotice(html) {
  const box = $("#draftNotice");
  box.innerHTML = html;
  box.classList.toggle("hidden", !html);
}

/** "Add integration": always a clean draft. An unsaved draft is set aside (one slot) and can be brought back. */
function startFreshWizard() {
  if (draftHasContent(wiz.draft) && !wiz.saved) {
    storeSet("wizardPrev", (({ fieldErrors, tabErrors, ...rest }) => rest)(wiz));
    showDraftNotice(`New integration: clean draft. <span class="muted">Your unsaved draft "${esc(draftLabel(wiz.draft))}" was set aside.</span>
      <button class="link" data-draft="restore">Restore it</button>`);
  } else showDraftNotice("");
  resetWizard();
}

/** Opening the wizard by reload / back button: keep the draft, and say so. */
function noteRestoredDraft() {
  if (draftHasContent(wiz.draft) && !wiz.saved) {
    showDraftNotice(`<b>Draft restored:</b> "${esc(draftLabel(wiz.draft))}" (step ${wiz.step + 1} of ${STEPS.length}). <button class="link" data-draft="fresh">Start fresh</button>`);
  } else showDraftNotice("");
}

function onDraftNotice(ev) {
  const b = ev.target.closest("[data-draft]");
  if (!b) return;
  if (b.dataset.draft === "fresh") { showDraftNotice(""); resetWizard(); return; }
  const prev = storeGet("wizardPrev", null);
  if (!prev || !prev.draft) { showDraftNotice(""); return; }
  Object.assign(wiz, prev, { fieldErrors: {}, tabErrors: new Set() });
  if (!Array.isArray(wiz.ep)) wiz.ep = [];
  storeSet("wizardPrev", null);
  showDraftNotice(`<b>Draft restored:</b> "${esc(draftLabel(wiz.draft))}". <button class="link" data-draft="fresh">Start fresh</button>`);
  renderWizard();
}

function resetWizard() {
  Object.assign(wiz, { step: 0, maxStep: 0, active: 0, ep: [], draft: newDraft(), test: null, saved: null, fieldErrors: {}, tabErrors: new Set() });
  showStepErrors([]);
  renderWizard();
}

function setYamlOpen(open) {
  $("#wizLayout").classList.toggle("yaml-closed", !open);
  $("#yamlToggle").textContent = open ? "Hide YAML" : "Show YAML";
  $("#yamlToggle").setAttribute("aria-expanded", String(open));
  storeSet("yamlOpen", open);
}

/* ------------------------------------------------------------------ demo controls (admin) */
function demoDrawer() {
  openDrawer("Admin", "Demo controls", `<p class="muted" style="margin:0">Triggers for a live demo. Each runs against the real connectors.</p>
    <div class="demo-list">
      <div class="demo-item"><b>Wrong key</b><span class="muted sm">Calls the real GitHub API with an invalid token: a real HTTP 401, shown as "Authentication failed", with no retries.</span>
        <button class="btn secondary sm" data-demo="wrong-key">Call GitHub with a wrong key</button></div>
      <div class="demo-item"><b>Network off</b><span class="muted sm">One GitHub run against a dead address: retries after 1 s, 2 s and 4 s, then the run fails.</span>
        <button class="btn secondary sm" data-demo="network-off">Network off mid-run</button></div>
      <div class="demo-item"><b>Rate limit (Mock)</b><span class="muted sm">The Demo source (Mock) answers HTTP 429 with Retry-After: 5. The run waits 5 s, then succeeds.</span>
        <button class="btn secondary sm" data-demo="retry-after">429 with Retry-After: 5</button></div>
      <div class="demo-item"><b>Bad record (Mock)</b><span class="muted sm">One record from the Demo source (Mock) has an unreadable time. It is quarantined; the rest of the run is stored.</span>
        <button class="btn secondary sm" data-demo="malformed">Send a malformed record</button></div>
      <div class="demo-item"><b>Stolen token (Mock)</b><span class="muted sm">The Demo source (Mock) returns ~20x its normal volume, like a bulk export with a stolen token. The connection is paused, a critical alert is raised and a Jira ticket opens.</span>
        <button class="btn danger sm" data-demo="bulk-export">Simulate a bulk export</button></div>
      <div class="demo-item"><b>Repeated failure</b><span class="muted sm">Three failed GitHub runs in a row send one alert; the next good run sends "recovered".</span>
        <button class="btn secondary sm" data-demo="repeated-failure">Fail 3 times, then recover</button></div>
      <div class="demo-item"><b>Slack test</b><span class="muted sm">Posts "PlugSec: Slack alerts connected" to the Slack webhook in .env (SLACK_WEBHOOK_URL).</span>
        <button class="btn secondary sm" id="slackTestBtn">Send a test message</button></div>
      <div class="demo-item"><b>Reset demo</b><span class="muted sm">Clears stored records, run history and alerts, and removes integrations added during the demo. Jira tickets are never duplicated.</span>
        <button class="btn danger sm" id="resetBtn">Reset demo</button></div>
    </div><div id="demoResult" class="notice hidden"></div>`);
}

async function runDemo(btn) {
  const kind = btn.dataset.demo;
  await withBusy(btn, "Running…", async () => {
    try {
      const { result: r } = await api(`/api/demo/${kind}`, { method: "POST", body: {} });
      const msg = r.status === "done" ? `${r.failed_runs} failed runs, ${r.alerts.length} alert sent${r.alerts[0] ? ` (${r.alerts[0].channels.join(", ")})` : ""}; then ${r.recovery_run}${r.recovery ? `: ${r.recovery.message}` : ""}`
        : r.status === "auth_failed" ? `${r.error} (retries: ${r.retries})`
        : r.status === "suspicious" ? `Suspicious: ${r.suspicious.records} records vs a baseline of ${r.suspicious.baseline}. Paused, critical alert raised.`
        : r.status === "error" ? `Run failed: ${r.error}`
        : `Run ${r.status}: ${r.records_fetched} records, ${r.retries} retr${r.retries === 1 ? "y" : "ies"}${r.quarantined ? `, ${r.quarantined} quarantined` : ""}${(r.retry_log || []).some((l) => l.includes("waited")) ? ` (${r.retry_log.filter((l) => l.includes("waited")).join("; ")})` : ""}`;
      const box = $("#demoResult");
      box.textContent = msg;
      box.className = `notice ${(r.status === "success" && !r.quarantined) || r.status === "done" ? "ok" : "warn"}`;
      await loadIntegrations();
    } catch (e) { toast(errorList(e).join("; "), "err"); }
  });
}

async function sendSlackTest(btn) {
  await withBusy(btn, "Sending…", async () => {
    try {
      const r = await api("/api/alerts/test", { method: "POST" });
      const box = $("#demoResult");
      box.className = `notice ${r.sent.length ? "ok" : "warn"}`;
      box.textContent = r.sent.length ? "Test message sent to Slack." : r.failed.length ? `Slack did not accept it: ${r.failed.join("; ")}`
        : "Slack is not configured: set SLACK_WEBHOOK_URL in .env and restart.";
    } catch (e) { toast(errorList(e).join("; "), "err"); }
  });
}

async function resetDemo() {
  if (!confirm("Reset the demo? This clears stored records, run history and alerts, and removes integrations added during the demo.")) return;
  try {
    const r = await api("/api/demo/reset", { method: "POST" });
    resetWizard();
    closeDrawer();
    toast(`Demo reset${r.removed_integrations.length ? `: removed ${r.removed_integrations.join(", ")}` : ""}`, "ok");
    refresh(true);
  } catch (e) { toast(errorList(e).join("; "), "err"); }
}

/* ------------------------------------------------------------------ theme, sidebar, session */
function setTheme(theme, remember = true) {
  document.documentElement.dataset.theme = theme;
  if (remember) storeSet("theme", theme);  // only an explicit toggle saves; otherwise the system setting keeps applying
  const next = theme === "dark" ? "light" : "dark";
  $("#themeBtn").innerHTML = `${icon(next === "light" ? "sun" : "moon")}<span class="nav-label">${cap(next)} theme</span>`;
  $("#themeBtn").title = `Switch to the ${next} theme`;
}

function setCollapsed(collapsed) {
  $("#appView").classList.toggle("collapsed", collapsed);
  $("#collapseBtn").innerHTML = `<span class="ico" style="transform:rotate(${collapsed ? 180 : 0}deg)">${svg("chevrons")}</span>`;
  $("#collapseBtn").title = collapsed ? "Expand sidebar" : "Collapse sidebar";
  storeSet("sidebarCollapsed", collapsed);
}

/** No (or an expired) session: back to the public home page with the sign-in card open. */
function showLogin() {
  state.me = null;
  location.replace("/#signin");
}

async function startApp(me) {
  state.me = me;
  $("#appView").classList.remove("hidden");
  $("#userName").textContent = me.user;
  $("#userAvatar").textContent = initials(me.user);
  $("#userRole").textContent = cap(me.role);
  renderNav();
  try {
    state.meta = await api("/api/meta");
    Object.assign(ENTITY_FIELDS, state.meta.entity_fields || {});
  } catch { /* shown via the Live indicator */ }
  showPage(location.hash.slice(1) || storeGet("page", "overview"));
}

/* ------------------------------------------------------------------ boot */
function rowFrom(ev, tableSel) {
  const row = ev.target.closest(`${tableSel} tbody tr[data-i]`);
  if (!row || ev.target.closest("a, button")) return null;
  $$(".table tr.selected").forEach((r) => r.classList.remove("selected"));
  row.classList.add("selected");
  return Number(row.dataset.i);
}

function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }

function boot() {
  hydrateIcons();
  setTheme(document.documentElement.dataset.theme || "dark", false);
  setCollapsed(storeGet("sidebarCollapsed", false));
  setYamlOpen(storeGet("yamlOpen", true));

  $("#logoutBtn").addEventListener("click", async () => { try { await api("/api/auth/logout", { method: "POST" }); } catch { /* ignore */ } location.replace("/"); });
  $("#themeBtn").addEventListener("click", () => setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));
  $("#collapseBtn").addEventListener("click", () => setCollapsed(!$("#appView").classList.contains("collapsed")));
  $("#demoBtn").addEventListener("click", () => { if (can("admin")) demoDrawer(); });
  window.addEventListener("hashchange", () => { if (state.me) { storeSet("page", location.hash.slice(1)); showPage(location.hash.slice(1)); } });

  // drawer, menu and global keys
  $("#drawerClose").addEventListener("click", closeDrawer);
  $("#scrim").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") { if (!$("#menu").classList.contains("hidden")) closeMenu(); else closeDrawer(); }
  });
  document.addEventListener("click", (ev) => {
    if (!ev.target.closest("#menu, [data-menu]")) closeMenu();
    if (ev.target.closest('a[href="#wizard"]') && can("admin")) {  // "Add integration" (sidebar or button): a clean draft
      state.freshWizard = true;
      if (state.page === "wizard") { state.freshWizard = false; startFreshWizard(); }
    }
    const cp = ev.target.closest("[data-copy]");
    if (cp) { ev.preventDefault(); copyText(cp.dataset.copy); return; }
    const preset = ev.target.closest("[data-preset]");
    if (preset) evPreset(preset.dataset.preset);
    const openInt = ev.target.closest("[data-open-int]");
    if (openInt) { ev.preventDefault(); location.hash = "integrations"; setTimeout(() => integrationDrawer(openInt.dataset.openInt).catch(() => {}), 50); }
  });
  $("#drawerBody").addEventListener("click", (ev) => {
    const b = ev.target.closest("button[data-act]");
    if (b && !b.disabled) integrationAction(b.dataset.act, b.dataset.name);
    const d = ev.target.closest("button[data-demo]");
    if (d) runDemo(d);
    if (ev.target.closest("#resetBtn")) resetDemo();
    const st = ev.target.closest("#slackTestBtn");
    if (st) sendSlackTest(st);
  });

  // overview + events
  $("#criticalTable tbody").addEventListener("click", (e) => { const i = rowFrom(e, "#criticalTable"); if (i !== null) eventDrawer(state.lastCritical[i]); });
  $("#eventsTable tbody").addEventListener("click", (e) => { const i = rowFrom(e, "#eventsTable"); if (i !== null) eventDrawer(ev.items[i]); });
  $("#evSearch").addEventListener("input", debounce((e) => { ev.q = e.target.value.trim(); ev.offset = 0; refresh(true); }, 300));
  $("#evSource").addEventListener("change", (e) => { ev.source = e.target.value; ev.offset = 0; refresh(true); });
  $("#evSeverity").addEventListener("click", (e) => { const b = e.target.closest("[data-sev]"); if (!b) return; ev.severity = b.dataset.sev; ev.offset = 0; renderEventFilters(); refresh(true); });
  $("#evRange").addEventListener("click", (e) => { const b = e.target.closest("[data-range]"); if (!b) return; ev.range = b.dataset.range; ev.offset = 0; renderEventFilters(); refresh(true); });
  $("#evPrev").addEventListener("click", () => { ev.offset = Math.max(0, ev.offset - ev.limit); refresh(true); });
  $("#evNext").addEventListener("click", () => { ev.offset += ev.limit; refresh(true); });
  renderEventFilters();

  // users + devices
  $("#usersTable tbody").addEventListener("click", (e) => { const i = rowFrom(e, "#usersTable"); if (i !== null) recordDrawer("user", us.items[i]); });
  $("#devicesTable tbody").addEventListener("click", (e) => { const i = rowFrom(e, "#devicesTable"); if (i !== null) recordDrawer("device", dv.items[i]); });
  $("#usSearch").addEventListener("input", debounce((e) => { us.q = e.target.value.trim(); us.offset = 0; refresh(true); }, 300));
  $("#usSources").addEventListener("click", (e) => { const b = e.target.closest("[data-src]"); if (!b) return; us.source = b.dataset.src; us.offset = 0; refresh(true); });
  $("#usPrev").addEventListener("click", () => { us.offset = Math.max(0, us.offset - us.limit); refresh(true); });
  $("#usNext").addEventListener("click", () => { us.offset += us.limit; refresh(true); });
  $("#dvSearch").addEventListener("input", debounce((e) => { dv.q = e.target.value.trim(); dv.offset = 0; refresh(true); }, 300));
  $("#dvSource").addEventListener("change", (e) => { dv.source = e.target.value; dv.offset = 0; refresh(true); });
  $("#dvPrev").addEventListener("click", () => { dv.offset = Math.max(0, dv.offset - dv.limit); refresh(true); });
  $("#dvNext").addEventListener("click", () => { dv.offset += dv.limit; refresh(true); });

  // repositories
  const rpRefresh = () => refresh(true);
  $("#rpSearch").addEventListener("input", debounce((e) => { rp.q = e.target.value.trim(); rpRefresh(); }, 250));
  $("#rpLanguage").addEventListener("change", (e) => { rp.language = e.target.value; rpRefresh(); });
  $("#rpTopic").addEventListener("change", (e) => { rp.topic = e.target.value; rpRefresh(); });
  $("#rpVisibility").addEventListener("change", (e) => { rp.visibility = e.target.value; rpRefresh(); });
  $("#rpCritical").addEventListener("click", () => { rp.critical = !rp.critical; rpRefresh(); });
  $("#repoGrid").addEventListener("click", (e) => {
    if (e.target.closest("a, button")) return;
    const card = e.target.closest(".repo-card[data-i]");
    if (card) repoDrawer(rp.items[Number(card.dataset.i)]);
  });
  $("#repoGrid").addEventListener("keydown", (e) => {
    const card = e.target.closest(".repo-card[data-i]");
    if (card && e.target === card && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); repoDrawer(rp.items[Number(card.dataset.i)]); }
  });

  // integrations
  $("#intGrid").addEventListener("click", (e) => {
    const menuBtn = e.target.closest("[data-menu]");
    if (menuBtn) { e.stopPropagation(); integrationMenu(menuBtn, menuBtn.dataset.menu); return; }
    const b = e.target.closest("button[data-act]");
    if (b) { if (!b.disabled) integrationAction(b.dataset.act, b.dataset.name); return; }
    if (e.target.closest("a, button")) return;
    const card = e.target.closest("[data-int]");
    if (card) integrationDrawer(card.dataset.int).catch((err) => toast(errorList(err).join("; "), "err"));
  });
  $("#intGrid").addEventListener("keydown", (e) => {
    const card = e.target.closest("[data-int]");
    if (card && e.target === card && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); integrationDrawer(card.dataset.int); }
  });

  // catalog
  $("#catSearch").addEventListener("input", debounce((e) => { cat.q = e.target.value.trim(); renderCatalog(false); }, 200));
  $("#catCategories").addEventListener("click", (e) => { const b = e.target.closest("[data-cat]"); if (b) { cat.category = b.dataset.cat; renderCatalog(false); } });
  $("#catStatuses").addEventListener("click", (e) => { const b = e.target.closest("[data-status]"); if (b) { cat.status = b.dataset.status; renderCatalog(false); } });
  $("#catGroups").addEventListener("click", (e) => { const b = e.target.closest("[data-template]"); if (b && !b.disabled) useTemplate(b.dataset.template); });

  // actions
  $("#actionCards").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-yaml]");
    const a = b && (state.actions || []).find((x) => x.name === b.dataset.yaml);
    if (a) openDrawer("Action", a.display_name, `<div>${esc(ruleSummary(a))}</div><details class="raw" open><summary>Config<button class="btn ghost sm" data-copy="${esc(a.yaml)}">${icon("copy")}Copy</button></summary><pre class="code">${esc(a.yaml)}</pre></details>`);
  });
  $("#resultsAll").addEventListener("click", () => { acts.all = !acts.all; refresh(true); });

  // wizard
  $("#stepBody").addEventListener("input", onWizardInput);
  $("#stepBody").addEventListener("change", onWizardInput);
  $("#stepBody").addEventListener("click", onWizardClick);
  $("#stepBody").addEventListener("keydown", onWizardKey);
  $("#stepper").addEventListener("click", onWizardClick);
  $("#wizNext").addEventListener("click", () => goStep(wiz.step + 1));
  $("#wizBack").addEventListener("click", () => goStep(wiz.step - 1));
  $("#wizNew").addEventListener("click", () => { if (confirm("Discard this draft and start a new integration?")) { showDraftNotice(""); resetWizard(); } });
  $("#draftNotice").addEventListener("click", onDraftNotice);
  $("#yamlToggle").addEventListener("click", () => setYamlOpen($("#wizLayout").classList.contains("yaml-closed")));
  $("#yamlEditor").addEventListener("input", onYamlInput);
  $("#yamlEditor").addEventListener("keydown", (e) => {
    if (e.key === "Tab") { // indent with spaces instead of leaving the editor
      e.preventDefault();
      const ed = e.target, s = ed.selectionStart;
      ed.setRangeText("  ", s, ed.selectionEnd, "end");
      onYamlInput();
    }
  });
  $("#yamlEditor").addEventListener("blur", () => { if (!$("#yamlStatus").classList.contains("err")) setTimeout(() => syncYaml(), 500); });

  setInterval(() => refresh(), REFRESH_MS);
  api("/api/auth/me").then(startApp).catch(() => showLogin());
}

/** Overview links ("View all", a severity bar) open Events with that severity. */
function evPreset(sev) {
  Object.assign(ev, { severity: sev === "critical" || SEVERITIES.includes(sev) ? sev : "", range: "all", offset: 0, q: "", source: "" });
  $("#evSearch").value = "";
  $("#evSource").value = "";
  renderEventFilters();
}

boot();
