/* Public pages (home + docs). Calls only public endpoints: /api/auth/options and /api/auth/login. */
"use strict";

const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];
const SVG = {
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z"/>',
  eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="M3 3l18 18M10.6 5.1A10.6 10.6 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-3.1 3.9M6.6 6.6C3.9 8.4 2 12 2 12s3.6 7 10 7a9.7 9.7 0 0 0 4.4-1.1"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
  copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
};
const icon = (name) => `<span class="ico"><svg viewBox="0 0 24 24" aria-hidden="true">${SVG[name]}</svg></span>`;

function storeGet(key, fallback) {
  try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; } catch { return fallback; }
}
function storeSet(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* storage unavailable */ }
}

/* ------------------------------------------------------------------ theme (shared with the app) */
function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  storeSet("theme", theme);
  const next = theme === "dark" ? "light" : "dark";
  $$(".theme-toggle").forEach((b) => { b.innerHTML = icon(next === "light" ? "sun" : "moon"); b.title = `Switch to the ${next} theme`; b.setAttribute("aria-label", b.title); });
}

/* ------------------------------------------------------------------ sign-in card (home page) */
const ROLE_TEXT = {
  admin: "Manage integrations, secrets, AI mapping",
  analyst: "View everything, run connections",
  viewer: "Read-only dashboards",
};

function initSignin() {
  const form = $("#signin");
  if (!form) return;
  const user = $("#username"), pass = $("#password"), btn = $("#signinBtn"), err = $("#signinError");
  let usernames = {};
  let cooldownTimer = null;

  // Demo mode pre-fills usernames per role. Passwords never come from the server.
  fetch("/api/auth/options", { credentials: "same-origin" }).then((r) => (r.ok ? r.json() : {})).then((o) => {
    usernames = o.usernames || {};
    $("#demoHint").classList.toggle("hidden", !o.demo);
    if (!user.value) prefill(storeGet("signinRole", "admin"));
  }).catch(() => { /* the card still works without it */ });

  function prefill(role) {
    $$(".role-switch [data-role]").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.role === role)));
    $("#roleDesc").textContent = ROLE_TEXT[role];
    if (usernames[role]) user.value = usernames[role];
    storeSet("signinRole", role);
  }

  $(".role-switch").addEventListener("click", (e) => {
    const b = e.target.closest("[data-role]");
    if (!b) return;
    prefill(b.dataset.role);
    pass.value = "";
    err.textContent = "";
    pass.focus();
  });
  $(".role-switch").addEventListener("keydown", (e) => {  // arrow keys move between the three options
    if (!["ArrowLeft", "ArrowRight"].includes(e.key)) return;
    const opts = $$(".role-switch [data-role]");
    const i = opts.findIndex((b) => b.getAttribute("aria-checked") === "true");
    const next = opts[(i + (e.key === "ArrowRight" ? 1 : opts.length - 1)) % opts.length];
    prefill(next.dataset.role);
    next.focus();
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
    if (!user.value.trim() || !pass.value) { err.textContent = "Enter your username and password."; (user.value.trim() ? pass : user).focus(); return; }
    setLoading(true);
    try {
      // Only credentials are sent: the role is decided by the server from the account.
      const res = await fetch("/api/auth/login", {
        method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: user.value.trim(), password: pass.value }),
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

  function focusSignin(smooth = true) {
    form.scrollIntoView({ behavior: smooth ? "smooth" : "auto", block: "center" });
    form.classList.remove("flash"); void form.offsetWidth; form.classList.add("flash");
    setTimeout(() => (user.value ? pass : user).focus({ preventScroll: true }), smooth ? 350 : 0);
  }
  $$("[data-focus-signin]").forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); history.replaceState(null, "", "#signin"); focusSignin(); }));
  if (location.hash === "#signin") focusSignin(false);
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

/* ------------------------------------------------------------------ copy buttons on code blocks */
function initCopy() {
  $$("pre[data-copyable]").forEach((pre) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn ghost sm copy-btn";
    btn.innerHTML = `${icon("copy")}Copy`;
    btn.addEventListener("click", async () => {
      const text = pre.firstChild.textContent.replace(/\n$/, "");
      try { await navigator.clipboard.writeText(text); } catch {
        const ta = Object.assign(document.createElement("textarea"), { value: text });
        document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove();
      }
      btn.innerHTML = `${icon("copy")}Copied`;
      setTimeout(() => { btn.innerHTML = `${icon("copy")}Copy`; }, 1500);
    });
    pre.appendChild(btn);
  });
}

setTheme(document.documentElement.dataset.theme || "dark");
$$(".theme-toggle").forEach((b) => b.addEventListener("click", () => setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark")));
initSignin();
initDocs();
initCopy();
