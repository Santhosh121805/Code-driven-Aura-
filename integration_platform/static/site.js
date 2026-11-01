/* Public pages (home, docs, sign-in). Calls only public endpoints: /api/auth/options and /api/auth/login.
   Everything animated here is demo content; no live data is shown on public pages. */
"use strict";

const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const SVG = {
  eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="M3 3l18 18M10.6 5.1A10.6 10.6 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-3.1 3.9M6.6 6.6C3.9 8.4 2 12 2 12s3.6 7 10 7a9.7 9.7 0 0 0 4.4-1.1"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
  copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
  check: '<path d="m5 12 5 5 9-10"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z"/>',
};
const icon = (name) => `<span class="ico"><svg viewBox="0 0 24 24" aria-hidden="true">${SVG[name]}</svg></span>`;

function storeGet(key, fallback) {
  try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; } catch { return fallback; }
}
function storeSet(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* storage unavailable */ }
}
/** Run `fn` once, the first time `el` scrolls into view. */
function onceVisible(el, fn, threshold = 0.25) {
  if (!el) return;
  if (!("IntersectionObserver" in window)) { fn(); return; }
  const io = new IntersectionObserver((entries) => {
    if (entries.some((e) => e.isIntersecting)) { io.disconnect(); fn(); }
  }, { threshold });
  io.observe(el);
}

/* ------------------------------------------------------------------ theme (same "theme" key as the app) */
function initTheme() {
  const root = document.documentElement;
  const meta = $('meta[name="theme-color"]');
  const paint = (theme) => {
    root.dataset.theme = theme;
    if (meta) meta.content = theme === "light" ? "#FAFAFA" : "#000000";
    const next = theme === "dark" ? "light" : "dark";
    $$(".theme-toggle").forEach((b) => {
      b.innerHTML = icon(next === "light" ? "sun" : "moon");
      b.title = `Switch to the ${next} theme`;
      b.setAttribute("aria-label", b.title);
    });
  };
  paint(root.dataset.theme === "light" ? "light" : "dark");
  $$(".theme-toggle").forEach((b) => b.addEventListener("click", () => {
    const theme = root.dataset.theme === "light" ? "dark" : "light";
    root.classList.add("theme-anim");  // 200 ms colour transition only while switching
    paint(theme);
    storeSet("theme", theme);
    setTimeout(() => root.classList.remove("theme-anim"), 260);
  }));
  // No saved choice yet: keep following the system setting.
  const mq = window.matchMedia && matchMedia("(prefers-color-scheme: light)");
  if (mq && mq.addEventListener) mq.addEventListener("change", (e) => { if (!storeGet("theme", null)) paint(e.matches ? "light" : "dark"); });
}

/* ------------------------------------------------------------------ nav + reveal */
function initNav() {
  const nav = $("#siteNav");
  if (!nav || !$(".hero")) return;  // docs and /login keep the solid nav
  const update = () => nav.classList.toggle("scrolled", window.scrollY > 8);
  update();
  window.addEventListener("scroll", update, { passive: true });
}

function initReveal() {
  const items = $$(".reveal");
  if (REDUCED || !("IntersectionObserver" in window)) { items.forEach((el) => el.classList.add("shown")); return; }
  const io = new IntersectionObserver((entries) => {
    entries.forEach((e) => { if (e.isIntersecting) { e.target.classList.add("shown"); io.unobserve(e.target); } });
  }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
  items.forEach((el, i) => { el.style.transitionDelay = `${Math.min(i % 4, 3) * 70}ms`; io.observe(el); });
}

/* ------------------------------------------------------------------ code: line numbers, highlighting, copy */
function highlightYaml(line) {
  // split off a comment that starts outside quotes
  let quote = null, cut = -1;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) { if (c === quote) quote = null; continue; }
    if (c === '"' || c === "'") quote = c;
    else if (c === "#" && (i === 0 || /\s/.test(line[i - 1]))) { cut = i; break; }
  }
  const code = cut >= 0 ? line.slice(0, cut) : line;
  const comment = cut >= 0 ? line.slice(cut) : "";
  const refs = (s) => s.replace(/(\$\{[A-Za-z_][A-Za-z0-9_]*\}|\{\{[^}]*\}\})/g, '<span class="tk-r">$1</span>');
  const html = code.replace(/("(?:[^"\\]|\\.)*"|'[^']*')|([A-Za-z_][\w-]*)(?=\s*:(?:\s|$))|([{}[\],])|([^"'{}[\],A-Za-z_]+|[A-Za-z_][\w-]*)/g,
    (m, str, key, punct) => (str ? `<span class="tk-s">${refs(esc(str))}</span>` : key ? `<span class="tk-k">${esc(key)}</span>`
      : punct ? `<span class="tk-p">${esc(punct)}</span>` : refs(esc(m))));
  return html + (comment ? `<span class="tk-c">${esc(comment)}</span>` : "");
}
const highlightPlain = (line) => {
  const i = line.search(/(^|\s)#/);
  return i < 0 ? esc(line) : esc(line.slice(0, i)) + `<span class="tk-c">${esc(line.slice(i))}</span>`;
};

/** Turn a <pre> into numbered lines (keeping the raw text for copying). */
function numberLines(pre, yaml) {
  const raw = pre.textContent.replace(/\n$/, "");
  pre.dataset.raw = raw;
  pre.innerHTML = raw.split("\n").map((l) => `<span class="l">${(yaml ? highlightYaml : highlightPlain)(l) || " "}</span>`).join("");
}

async function copyText(text, btn) {
  try { await navigator.clipboard.writeText(text); } catch {
    const ta = Object.assign(document.createElement("textarea"), { value: text });
    document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove();
  }
  btn.innerHTML = `${icon("check")}Copied`;
  setTimeout(() => { btn.innerHTML = `${icon("copy")}Copy`; }, 1600);
}

function initCode() {
  // Home page: code windows already in the markup.
  $$("pre.code-body").forEach((pre) => numberLines(pre, pre.classList.contains("yaml")));
  // Docs: wrap each plain block in the same window.
  $$("pre[data-copyable]").forEach((pre) => {
    const name = pre.dataset.name || "snippet";
    const win = document.createElement("div");
    win.className = "window";
    win.innerHTML = `<div class="window-bar"><span class="dots"><i></i><i></i><i></i></span><span class="file-tab">${esc(name)}</span><span class="spacer"></span><button class="copy" type="button" data-copy-target>Copy</button></div>`;
    pre.replaceWith(win);
    pre.className = "code-body";
    win.appendChild(pre);
    numberLines(pre, name.endsWith(".yaml"));
  });
  $$("[data-copy-target]").forEach((btn) => {
    btn.innerHTML = `${icon("copy")}Copy`;
    btn.addEventListener("click", () => copyText($("pre", btn.closest(".window")).dataset.raw, btn));
  });
}

/* ------------------------------------------------------------------ tabs */
function initTabs(list, onSelect) {
  if (!list) return;
  const tabs = $$("[role=tab]", list);
  const select = (tab, focus = false) => {
    tabs.forEach((t) => { const on = t === tab; t.setAttribute("aria-selected", String(on)); t.tabIndex = on ? 0 : -1; });
    onSelect(tab);
    if (focus) tab.focus();
    tab.scrollIntoView({ block: "nearest", inline: "nearest" });
  };
  tabs.forEach((t, i) => { t.tabIndex = i === 0 ? 0 : -1; });
  list.addEventListener("click", (e) => { const t = e.target.closest("[role=tab]"); if (t) select(t); });
  list.addEventListener("keydown", (e) => {
    const i = tabs.indexOf(document.activeElement);
    if (i < 0 || !["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) return;
    e.preventDefault();
    const n = e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1 : (i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length;
    select(tabs[n], true);
  });
}

function initCodeTabs() {
  initTabs($("#codeTabs"), (tab) => $$(".code-panes .pane").forEach((p) => { p.hidden = p.id !== `pane-${tab.dataset.pane}`; }));
}

const SHOTS = { overview: "Overview page", integrations: "Integrations page", events: "Events page" };
function initShots() {
  const img = $("#shotImg");
  if (!img) return;
  Object.keys(SHOTS).forEach((k) => { const pre = new Image(); pre.src = `/static/shots/${k}.png`; });  // no flash on switch
  initTabs($("#shotTabs"), (tab) => { img.src = `/static/shots/${tab.dataset.shot}.png`; img.alt = `PlugSec dashboard: ${SHOTS[tab.dataset.shot]}`; });
}

/* ------------------------------------------------------------------ terminal demo (static sample lines) */
const TERM_LINES = [
  ["t-ok", "✓", "github   · 200 · link → next · 4 pages · 183 records"],
  ["t-ok", "✓", "okta     · 200 · link → next · 7 users · 267 events"],
  ["t-retry", "↻", "nvd      · 429 · Retry-After 0 → waiting the 30 s window"],
  ["t-ok", "✓", "nvd      · 200 · offset 0 → 2000 · 3,065 CVEs"],
  ["t-warn", "⚠", "cisa_kev · 1 record quarantined (missing cveID) · 1,765 stored"],
  ["t-ok", "✓", "jira     · 200 · cursor → next · 11 users · 6 issues"],
];
function initTerminal() {
  const body = $("#termBody"), btn = $("#termRun"), status = $("#termStatus");
  if (!body) return;
  let timers = [];
  function play() {
    timers.forEach(clearTimeout); timers = [];
    body.innerHTML = '<li class="term-line in prompt"><b>$</b> plugsec run --all</li>';
    btn.disabled = true;
    status.textContent = "running…";
    const lines = TERM_LINES.map(([cls, mark, text]) => `<li class="term-line"><span class="${cls}">${mark}</span> ${esc(text)}</li>`)
      .concat(['<li class="term-line t-dim">5 connectors · 1 wait · 1 quarantined · 0 failed</li>']);
    let at = 450;
    lines.forEach((html, i) => {
      timers.push(setTimeout(() => {
        body.insertAdjacentHTML("beforeend", html);
        const li = body.lastElementChild;
        requestAnimationFrame(() => li.classList.add("in"));
        if (i === lines.length - 1) { btn.disabled = false; btn.textContent = "Run again"; status.textContent = "done"; }
      }, REDUCED ? 0 : at));
      at += (TERM_LINES[i] || [])[0] === "t-retry" ? 1500 : 650;  // the 429 line "waits" a little longer
    });
  }
  btn.addEventListener("click", play);
  onceVisible($("#term"), play, 0.4);
}

/* ------------------------------------------------------------------ one-format feed (demo data, looping) */
const FEED = [
  ["critical", "GitHub", "dependabot_alert", "pillow · requirements.txt"],
  ["high", "Okta", "user.session.start", "j.rivera@example.com"],
  ["medium", "Jira", "Task", "SEC-142"],
  ["high", "NVD", "vulnerability", "CVSS 8.1"],
  ["critical", "CISA KEV", "vulnerability", "known exploited"],
  ["info", "Okta", "user.lifecycle.create", "a.chen@example.com"],
  ["medium", "Okta", "policy.evaluate_sign_on", "203.0.113.24"],
  ["low", "GitHub", "dependabot_alert", "urllib3 · requirements.txt"],
  ["high", "Jira", "Bug", "SEC-157"],
  ["critical", "GitHub", "token_abuse", "guard · 91× baseline"],
];
function feedRow([sev, src, type, who]) {
  const li = document.createElement("li");
  li.className = "feed-row";
  li.innerHTML = `<span class="pill ${sev}"><i></i>${sev[0].toUpperCase() + sev.slice(1)}</span>
    <span class="src"><b>${esc(src[0])}</b>${esc(src)}</span><span class="type">${esc(type)}</span><span class="who">${esc(who)}</span>`;
  return li;
}
function initFeed() {
  const list = $("#feedList");
  if (!list) return;
  FEED.slice(0, 6).forEach((r) => list.appendChild(feedRow(r)));
  if (REDUCED) return;
  let next = 6;
  const step = () => {
    const row = feedRow(FEED[next++ % FEED.length]);
    row.classList.add("enter");
    list.prepend(row);
    const shift = row.offsetHeight + 8;
    list.style.transition = "none";
    list.style.transform = `translateY(${-shift}px)`;
    void list.offsetHeight;  // commit the start position, then slide (transform only)
    list.style.transition = "transform .7s cubic-bezier(.2,.7,.2,1)";
    list.style.transform = "translateY(0)";
    row.classList.remove("enter");
    while (list.children.length > 8) list.lastElementChild.remove();
  };
  onceVisible($(".feed"), () => setInterval(() => { if (!document.hidden) step(); }, 2600), 0.2);
}

/* ------------------------------------------------------------------ sign-in (modal on the home page, full page at /login) */
const ROLE_TEXT = {
  admin: "Manage integrations, secrets, AI mapping",
  analyst: "View everything, run connections",
  viewer: "Read-only dashboards",
};

function initSignin() {
  const form = $("#signin");
  if (!form) return;
  const user = $("#username"), pass = $("#password"), btn = $("#signinBtn"), err = $("#signinError");
  const modal = $("#signinModal");
  let usernames = {}, cooldownTimer = null, opener = null, openSignin = false;

  // Demo mode pre-fills usernames per role. Passwords never come from the server.
  fetch("/api/auth/options", { credentials: "same-origin" }).then((r) => (r.ok ? r.json() : {})).then((o) => {
    usernames = o.usernames || {};
    openSignin = !!o.open;
    $("#demoHint").classList.toggle("hidden", !o.demo && !openSignin);
    if (openSignin) {  // demo: any credentials work; the tab picks the role
      $("#demoHint").textContent = "Demo sign-in: any username and password work. The tab above picks the role.";
      pass.placeholder = "anything";
    }
    if (!user.value) prefill(storeGet("signinRole", "admin"));
  }).catch(() => { /* the card still works without it */ });

  function prefill(role) {
    $$(".role-switch [data-role]", form).forEach((b) => b.setAttribute("aria-checked", String(b.dataset.role === role)));
    $("#roleDesc").textContent = ROLE_TEXT[role];
    if (usernames[role]) user.value = usernames[role];
    storeSet("signinRole", role);
  }
  $(".role-switch", form).addEventListener("click", (e) => {
    const b = e.target.closest("[data-role]");
    if (!b) return;
    prefill(b.dataset.role);
    pass.value = ""; err.textContent = "";
    pass.focus();
  });
  $(".role-switch", form).addEventListener("keydown", (e) => {
    if (!["ArrowLeft", "ArrowRight"].includes(e.key)) return;
    const opts = $$(".role-switch [data-role]", form);
    const i = opts.findIndex((b) => b.getAttribute("aria-checked") === "true");
    const nxt = opts[(i + (e.key === "ArrowRight" ? 1 : opts.length - 1)) % opts.length];
    prefill(nxt.dataset.role);
    nxt.focus();
  });

  const eye = $("#pwToggle");
  eye.innerHTML = icon("eye");
  eye.addEventListener("click", () => {
    const show = pass.type === "password";
    pass.type = show ? "text" : "password";
    eye.innerHTML = icon(show ? "eyeOff" : "eye");
    eye.setAttribute("aria-label", show ? "Hide password" : "Show password");
    eye.setAttribute("aria-pressed", String(show));
  });

  function setLoading(on) {
    btn.disabled = on;
    btn.classList.toggle("loading", on);
    $(".label-text", btn).textContent = on ? "Signing in…" : "Sign in";
  }
  function cooldown(seconds) {
    clearInterval(cooldownTimer);
    let left = seconds;
    btn.disabled = true;
    const tick = () => {
      err.textContent = `Too many attempts. Try again in ${left} s.`;
      $(".label-text", btn).textContent = `Wait ${left} s`;
      if (left-- <= 0) { clearInterval(cooldownTimer); btn.disabled = false; err.textContent = ""; $(".label-text", btn).textContent = "Sign in"; }
    };
    tick();
    cooldownTimer = setInterval(tick, 1000);
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    err.textContent = "";
    if (!openSignin && (!user.value.trim() || !pass.value)) { err.textContent = "Enter your username and password."; (user.value.trim() ? pass : user).focus(); return; }
    const role = ($('.role-switch [aria-checked="true"]', form) || {}).dataset?.role || "viewer";
    setLoading(true);
    try {
      // Normally only credentials are sent and the server decides the role; open demo sign-in also sends the picked tab.
      const res = await fetch("/api/auth/login", {
        method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: user.value.trim(), password: pass.value, ...(openSignin ? { role } : {}) }),
      });
      if (res.ok) { pass.value = ""; location.assign("/app#overview"); return; }
      setLoading(false);
      if (res.status === 429) { cooldown(Number(res.headers.get("Retry-After")) || 30); return; }
      err.textContent = "Invalid username or password";
      pass.select();
    } catch {
      setLoading(false);
      err.textContent = "The platform is not reachable. Is run_all.py running?";
    }
  });

  const focusFirst = () => (user.value ? pass : user).focus({ preventScroll: true });
  if (!modal) { setTimeout(focusFirst, 50); return; }  // full /login page

  function open(trigger) {
    opener = trigger || document.activeElement;
    modal.classList.add("open");
    modal.setAttribute("aria-hidden", "false");
    document.body.style.overflow = "hidden";
    setTimeout(focusFirst, 60);
  }
  function close() {
    if (!modal.classList.contains("open")) return;
    modal.classList.remove("open");
    modal.setAttribute("aria-hidden", "true");
    document.body.style.overflow = "";
    if (location.hash === "#signin") history.replaceState(null, "", location.pathname);
    if (opener && opener.focus) opener.focus({ preventScroll: true });
  }
  $$("[data-open-signin]").forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); open(a); }));
  $("#signinClose").addEventListener("click", close);
  modal.addEventListener("mousedown", (e) => { if (e.target === modal) close(); });
  document.addEventListener("keydown", (e) => {
    if (!modal.classList.contains("open")) return;
    if (e.key === "Escape") { e.preventDefault(); close(); }
    if (e.key === "Tab") {  // keep focus inside the dialog
      const f = $$("button:not([disabled]), input, [href]", form).filter((el) => el.offsetParent !== null);
      const first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  });
  if (location.hash === "#signin") open(null);  // e.g. redirected here from /app without a session
}

/* ------------------------------------------------------------------ docs */
function initDocs() {
  const nav = $("#docsNav");
  if (!nav) return;
  const links = $$("a", nav);
  const ids = links.map((a) => a.hash.slice(1));
  $("#docsPicker").innerHTML = links.map((a) => `<option value="${a.hash.slice(1)}">${a.textContent}</option>`).join("");
  function show(id) {
    if (!ids.includes(id)) id = ids[0];
    $$(".doc").forEach((d) => { d.hidden = d.id !== id; });
    links.forEach((a) => { const on = a.hash === `#${id}`; a.classList.toggle("active", on); if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current"); });
    $("#docsPicker").value = id;
    const i = ids.indexOf(id);
    const prev = i > 0 ? links[i - 1] : null, next = i < links.length - 1 ? links[i + 1] : null;
    $("#docPager").innerHTML = (prev ? `<a href="${prev.hash}"><span>Previous</span>${prev.textContent}</a>` : "")
      + (next ? `<a class="next" href="${next.hash}"><span>Next</span>${next.textContent}</a>` : "");
    document.title = `${links[i].textContent} · PlugSec docs`;
    window.scrollTo({ top: 0 });  // the browser's own anchor jump lands before the topic is visible
  }
  window.addEventListener("hashchange", () => show(location.hash.slice(1)));
  $("#docsPicker").addEventListener("change", (e) => { location.hash = e.target.value; });
  show(location.hash.slice(1));
  window.addEventListener("load", () => window.scrollTo({ top: 0 }));
}

initTheme();
initNav();
initCode();
initCodeTabs();
initShots();
initTerminal();
initFeed();
initSignin();
initDocs();
initReveal();
