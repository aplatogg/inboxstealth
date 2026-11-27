const $ = (id) => document.getElementById(id);
const on = (id, ev, fn) => { const el = $(id); if (el) el.addEventListener(ev, fn); };
const store = {
  get address(){ return localStorage.getItem("menyurat.address") || "" },
  set address(v){ v ? localStorage.setItem("menyurat.address", v) : localStorage.removeItem("menyurat.address") },
  get expires(){ return Number(localStorage.getItem("menyurat.expires") || 0) },
  set expires(v){ v ? localStorage.setItem("menyurat.expires", String(v)) : localStorage.removeItem("menyurat.expires") },
  get pinned(){ return localStorage.getItem("menyurat.pinned") === "1" },
  set pinned(v){ v ? localStorage.setItem("menyurat.pinned", "1") : localStorage.removeItem("menyurat.pinned") },
  get read(){ try { return new Set(JSON.parse(localStorage.getItem("menyurat.read") || "[]")) } catch { return new Set() } },
  set read(s){ localStorage.setItem("menyurat.read", JSON.stringify([...s])) },
  get domain(){ return localStorage.getItem("menyurat.domain") || "" },
  set domain(v){ v ? localStorage.setItem("menyurat.domain", v) : localStorage.removeItem("menyurat.domain") }
};

const state = {
  me: null, domains: [], messages: [], selected: null,
  filter: "all", query: "", address: store.address, expires: store.expires, pinned: store.pinned,
  read: store.read, view: "inbox", pending: 0, userFilter: "all", users: [], resetRequests: [], lastReset: null, keys: [], audit: [], addressList: [], adminDomains: [], pendingTicket: null,
  stats: null, announcements: [], addrQuery: "", sel: new Set(),
  matrixList: [], mxQuery: "", mxStatus: "all",
  allMessages: [], allSelected: null, allSelectedAddr: "", allFilter: "all", allAddrFilter: "", allQuery: "", allSeen: null, allSeenReady: false
};

function api(path, opts){
  return fetch(path, Object.assign({ credentials: "same-origin" }, opts)).then(async (r) => {
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { const e = new Error(j.error || ("HTTP " + r.status)); e.code = j.error; e.status = r.status; throw e; }
    return j;
  });
}
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const escAttr = (s) => String(s ?? "").replace(/&/g,"&amp;").replace(/"/g,"&quot;");
/* ---------- role badge ---------- */
const ROLE_ICONS = {
  owner: '<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M1.4 12h13.2l1-8.2-4.3 3.1L8 2.4 4.7 6.9 1.4 3.8z"/></svg>',
  admin: '<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 1.3 14 3.6v4.6c0 3.9-2.7 5.9-6 6.9-3.3-1-6-3-6-6.9V3.6z"/></svg>',
  vip: '<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 1.6l2 4 4.4.6-3.2 3.1.8 4.4L8 11.6l-4 2.1.8-4.4L1.6 6.2 6 5.6z"/></svg>',
  member: '<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 8.2a3.1 3.1 0 1 0 0-6.2 3.1 3.1 0 0 0 0 6.2zm-6.2 7c0-3.1 2.8-5.2 6.2-5.2s6.2 2.1 6.2 5.2z"/></svg>'
};
const ROLE_LABEL = { owner: "Owner", admin: "Admin", vip: "VIP", member: "Member" };

function roleBadge(role) {
  const r = ROLE_LABEL[role] ? role : "member";
  return '<span class="rbadge r-' + r + '">' + ROLE_ICONS[r] + ROLE_LABEL[r] + "</span>";
}
const isStaff = () => state.me && (state.me.role === "owner" || state.me.role === "admin");
const TTL_MAX_DAYS = { member: 7, vip: 90, admin: 90, owner: 365 };
const ALL_TTL_OPTS = [
  ["3600", "1 jam"],
  ["86400", "1 hari"],
  ["259200", "3 hari"],
  ["604800", "7 hari"],
  ["1209600", "14 hari"],
  ["2592000", "30 hari"],
  ["7776000", "90 hari"],
  ["31536000", "365 hari"],
];
const canPickTtl = () => !!state.me && state.me.role !== "member";
function syncTtlOptions(sel){
  if (!sel) return;
  const role = state.me ? state.me.role : "member";
  const max = TTL_MAX_DAYS[role] || 90;
  const prev = sel.value || "1209600";
  const allowed = ALL_TTL_OPTS.filter(([sec]) => Number(sec) / 86400 <= max);
  sel.innerHTML = allowed.map(([val, lbl]) => `<option value="${val}">${lbl}</option>`).join("");
  if (allowed.some(([val]) => val === prev)) {
    sel.value = prev;
  } else if (allowed.some(([val]) => val === "1209600")) {
    sel.value = "1209600";
  } else if (allowed.length) {
    sel.value = allowed[allowed.length - 1][0];
  }
}
const RANK_OF = { owner: 4, admin: 3, vip: 2, member: 1 };

function fmtTime(ts){
  const d = new Date(ts), n = new Date();
  const sameDay = d.toDateString() === n.toDateString();
  const hm = d.getHours().toString().padStart(2,"0") + ":" + d.getMinutes().toString().padStart(2,"0");
  return sameDay ? hm : d.getDate() + "/" + (d.getMonth()+1) + " " + hm;
}
function fmtLeft(ms){
  const s = Math.max(0, Math.floor(ms/1000));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return d + " hari " + h + " jam";
  if (h > 0) return h + " jam " + m + " menit";
  return m + " menit " + String(s % 60).padStart(2,"0") + " detik";
}
function fmtSize(bytes){
  if (bytes == null) return "—";
  if (bytes < 1024) return bytes + " B";
  return (bytes/1024).toFixed(1) + " KB";
}
function fmtDate(ts){ return new Date(ts).toLocaleDateString("id-ID",{day:"2-digit",month:"short",year:"numeric"}); }

/* ---------- auth screen ---------- */
function showMsg(el, text, kind){
  // BUG lama: elemen punya atribut `hidden` di markup, jadi pesan ditulis tapi tidak pernah tampil.
  el.textContent = text;
  el.className = "auth-msg " + (kind || "");
  el.hidden = !text;
}
/* ---------- Turnstile ---------- */
const TS_SITEKEY = (document.querySelector('meta[name="turnstile-sitekey"]') || {}).content || "";
const tsIds = {};
const TS_EL = { login: "tsLogin", register: "tsRegister", forgot: "tsForgot" };

function renderTs(which){
  const key = TS_EL[which];
  if (!key || !TS_SITEKEY || !window.turnstile || tsIds[which] !== undefined) return;
  const el = $(key);
  if (!el) return;
  try {
    tsIds[which] = window.turnstile.render(el, {
      sitekey: TS_SITEKEY,
      theme: "light",
      size: "flexible",
      language: "id",
      appearance: "always",
      "before-interactive-callback": () => { el.style.display = "block"; },
      "after-interactive-callback": () => { el.style.display = "block"; }
    });
  } catch {}
}

function tsToken(which){
  if (tsIds[which] === undefined || !window.turnstile) return "";
  try { return window.turnstile.getResponse(tsIds[which]) || ""; } catch { return ""; }
}

function tsReset(which){
  if (tsIds[which] === undefined || !window.turnstile) return;
  try { window.turnstile.reset(tsIds[which]); } catch {}
}

function initTurnstile(attempt = 0){
  if (!TS_SITEKEY) return;
  if (!window.turnstile) {
    if (attempt < 20) setTimeout(() => initTurnstile(attempt + 1), 300);
    return;
  }
  renderTs("login");
}

const AUTH_FORMS = { login: "loginForm", register: "registerForm", forgot: "forgotForm", reset: "resetForm", otp: "otpForm" };
function authTab(which){
  for (const id of Object.values(AUTH_FORMS)) $(id).hidden = AUTH_FORMS[which] !== id;
  const sub = which === "forgot" || which === "reset";
  $("authTabs").hidden = sub;
  if (TS_EL[which]) setTimeout(() => renderTs(which), 30);
  $("tabLogin").setAttribute("aria-selected", String(which === "login"));
  $("tabRegister").setAttribute("aria-selected", String(which === "register"));
}
$("forgotLink").addEventListener("click", () => authTab("forgot"));
document.querySelectorAll("[data-back]").forEach((b) =>
  b.addEventListener("click", () => { authTab("login"); history.replaceState(null, "", location.pathname); }));

$("otpForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msg = $("otpMsg"); msg.hidden = true;
  const btn = e.target.querySelector("button[type=submit]"); btn.disabled = true;
  try {
    const j = await api("/api/auth/2fa/verify", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ ticket: state.pendingTicket, code: $("otpCode").value })
    });
    state.pendingTicket = null;
    state.me = j.user;
    $("otpForm").reset();
    await enterApp();
  } catch (err){
    const map = {
      invalid_code: "Kode salah.",
      ticket_used: "Sesi kode sudah dipakai. Login ulang.",
      ticket_expired: "Kode kedaluwarsa. Login ulang.",
      too_many_requests: "Terlalu banyak percobaan. Coba lagi nanti."
    };
    showMsg(msg, map[err.code] || ("Gagal verifikasi: " + err.message), "err");
  } finally { btn.disabled = false; }
});

$("forgotForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msg = $("forgotMsg"); msg.hidden = true;
  const btn = e.target.querySelector("button[type=submit]"); btn.disabled = true;
  try {
    const j = await api("/api/auth/forgot", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: $("forgotEmail").value, captcha: tsToken("forgot") })
    });
    showMsg(msg, j.message || "Permintaan dikirim ke owner.", "ok");
    $("forgotForm").reset();
  } catch (err){
    const mapF = { captcha_required: "Verifikasi keamanan belum selesai. Tunggu widget Turnstile selesai, lalu coba lagi.", captcha_failed: "Verifikasi keamanan gagal. Muat ulang halaman.", too_many_requests: "Terlalu banyak percobaan. Coba lagi nanti." };
    showMsg(msg, mapF[err.code] || ("Gagal mengirim permintaan: " + err.message), "err");
    if (err.code === "captcha_required" || err.code === "captcha_failed") tsReset("forgot");
  } finally { btn.disabled = false; }
});

$("resetForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msg = $("resetMsg"); msg.hidden = true;
  const btn = e.target.querySelector("button[type=submit]"); btn.disabled = true;
  try {
    await api("/api/auth/reset", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: $("resetToken").value, next: $("resetPassword").value })
    });
    showMsg(msg, "Kata sandi tersimpan. Masuk dengan sandi baru.", "ok");
    $("resetForm").reset();
    setTimeout(() => { authTab("login"); history.replaceState(null, "", location.pathname); }, 1600);
  } catch (err){
    const map = {
      invalid_token: "Tautan tidak berlaku.",
      token_expired: "Tautan kedaluwarsa. Minta tautan baru ke owner.",
      token_used: "Tautan sudah dipakai.",
      password_too_short: "Kata sandi minimal 8 karakter."
    };
    showMsg(msg, map[err.code] || ("Gagal menyimpan: " + err.message), "err");
  } finally { btn.disabled = false; }
});
$("tabLogin").addEventListener("click", () => authTab("login"));
$("tabRegister").addEventListener("click", () => authTab("register"));

$("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msg = $("loginMsg");
  msg.hidden = true;
  const btn = e.submitter || e.target.querySelector("button[type=submit]");
  if (btn) btn.disabled = true;
  try {
    const j = await api("/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: $("loginEmail").value, password: $("loginPassword").value, captcha: tsToken("login") })
    });
    if (j.otp_required){
      state.pendingTicket = j.ticket;
      authTab("otp");
      setTimeout(() => { if ($("otpCode")) $("otpCode").focus(); }, 30);
      return;
    }
    state.me = j.user;
    await enterApp();
  } catch (err){
    const map = {
      invalid_credentials: "Email atau kata sandi salah.",
      pending_approval: "Akun masih menunggu persetujuan owner.",
      registration_rejected: "Pendaftaran ditolak owner.",
      account_suspended: "Akun ditangguhkan.",
      captcha_required: "Verifikasi keamanan belum selesai. Tunggu widget Turnstile selesai, lalu tekan Masuk lagi.",
      captcha_failed: "Verifikasi keamanan gagal. Muat ulang halaman lalu coba lagi.",
      too_many_requests: "Terlalu banyak percobaan. Coba lagi beberapa menit."
    };
    showMsg(msg, map[err.code] || ("Gagal masuk: " + err.message), "err");
    if (err.code === "captcha_required" || err.code === "captcha_failed") tsReset("login");
  } finally { if (btn) btn.disabled = false; }
});

$("registerForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msg = $("regMsg");
  msg.hidden = true;
  const btn = e.target.querySelector("button[type=submit]");
  btn.disabled = true;
  try {
    const j = await api("/api/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name: $("regName").value,
        email: $("regEmail").value,
        password: $("regPassword").value,
        captcha: tsToken("register")
      })
    });
    if (j.status === "approved" && j.user){
      state.me = j.user;
      await enterApp();
    } else {
      showMsg(msg, j.message || "Pendaftaran diterima. Tunggu persetujuan owner.", "ok");
      $("registerForm").reset();
    }
  } catch (err){
    const map = {
      email_taken: "Email sudah terdaftar.",
      invalid_email: "Format email tidak valid.",
      password_too_short: "Kata sandi minimal 8 karakter.",
      captcha_required: "Verifikasi keamanan belum selesai. Tunggu widget Turnstile selesai, lalu coba lagi.",
      captcha_failed: "Verifikasi keamanan gagal. Muat ulang halaman lalu coba lagi.",
      too_many_requests: "Terlalu banyak percobaan. Coba lagi nanti."
    };
    showMsg(msg, map[err.code] || ("Gagal mendaftar: " + err.message), "err");
    if (err.code === "captcha_required" || err.code === "captcha_failed") tsReset("register");
  } finally { btn.disabled = false; }
});

/* ---------- app boot ---------- */
async function enterApp(){
  if (!$("appShell")) {
    const r = await fetch("/api/app-shell", { credentials: "same-origin" });
    if (!r.ok) { authTab("login"); return; }
    const mount = $("appMount");
    if (mount) mount.innerHTML = await r.text();
    bindAppShellEvents();
    applyTheme(document.documentElement.dataset.theme === "dark" ? "dark" : "light");
  }
  $("authScreen").hidden = true;
  $("appShell").hidden = false;
  renderAccount();

  $("navUsers").hidden = !isStaff();
  $("navAudit").hidden = !isStaff();
  if ($("navDash")) $("navDash").hidden = !isStaff();
  await loadDomains();
  loadAddresses();
  const curHash = location.hash.replace(/^#\/?/, "");
  if (curHash !== "matrix") loadMatrix({ silent: true });
  if (curHash !== "all") loadAllInbox({ silent: true });
  loadBanner();
  if (isStaff()) await loadUsers();
  route();
  render();
  nsInit();
  nsEnsureCustomLoaded().catch(() => {});
  if (state.address) { loadInbox(); connectSSE(); }
  if (state.view === "all") connectAllSSE();
}

function closeAcct(){
  const m = $("acctMenu"), b = $("acctBtn");
  if (m) m.hidden = true;
  if (b) b.setAttribute("aria-expanded", "false");
}

document.addEventListener("click", (e) => {
  const peek = e.target.closest && e.target.closest("[data-peek]");
  if (peek) {
    const inp = $(peek.dataset.peek);
    if (inp) {
      const show = inp.type === "password";
      inp.type = show ? "text" : "password";
      peek.setAttribute("aria-label", show ? "Sembunyikan kata sandi" : "Tampilkan kata sandi");
    }
    return;
  }
}, true);

document.addEventListener("click", (e) => {
  const menu = $("acctMenu");
  if (!menu) return;
  const btn = e.target.closest && e.target.closest("#acctBtn");
  if (btn) {
    const open = menu.hidden;
    menu.hidden = !open;
    btn.setAttribute("aria-expanded", String(open));
    return;
  }
  if (e.target.closest && e.target.closest("#acctSettings")) {
    closeAcct();
    location.hash = "#/account";
    return;
  }
  if (!menu.hidden && !(e.target.closest && e.target.closest("#acctMenu"))) closeAcct();
});

document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeAcct(); });

function renderAccount(){
  if (!state.me) return;
  const mail = state.me.email || "";
  const initial = (mail[0] || "?").toUpperCase();
  const name = state.me.name || mail.split("@")[0] || "akun";
  for (const id of ["acctInitial", "acctInitial2"]) { const el = $(id); if (el) el.textContent = initial; }
  if ($("acctEmail")) $("acctEmail").textContent = mail;
  if ($("acctName")) $("acctName").textContent = name;
  if ($("acctMail")) $("acctMail").textContent = mail;
  if ($("acctRole")) $("acctRole").innerHTML = roleBadge(state.me.role);
}

/* ---------- domains ---------- */
async function loadDomains(){
  try {
    const j = await api("/api/domains");
    state.domains = j.domains || [];
  } catch { state.domains = []; }
  renderDomainControls();
}

function renderDomainControls(){
  const sel = $("domainSelect");
  sel.innerHTML = "";
  if (!state.domains.length){
    sel.innerHTML = '<option value="">tidak ada domain</option>';
    if ($("previewAddr")) $("previewAddr").textContent = "nama@domain";
    renderDomainRows(); renderDomainTable(); renderDomainCards();
    return;
  }
  const preferred = store.domain || (state.address && state.address.split("@")[1]) || "";
  let picked = "";
  const memberOnly = !state.me || state.me.role === "member";
  for (const d of state.domains){
    const locked = !!d.is_premium && memberOnly;
    const o = document.createElement("option");
    o.value = d.domain;
    o.textContent = d.domain + (locked ? " - premium (VIP)" : "");
    o.disabled = locked;
    sel.appendChild(o);
    if (!locked && d.domain === preferred) picked = d.domain;
    if (!picked && !locked && d.is_default) picked = d.domain;
  }
  sel.value = picked || state.domains[0].domain;
  const mxSel = $("mxDomain");
  if (mxSel) {
    mxSel.innerHTML = sel.innerHTML;
    mxSel.value = sel.value;
  }
  $("navDomains").textContent = String(state.domains.length);
  if ($("premHint")) $("premHint").hidden = !(memberOnly && state.domains.some((d) => d.is_premium));
  if ($("previewAddr")) $("previewAddr").textContent = "nama@" + sel.value;

  const nav = $("domainNav");
  if (nav) {
  nav.innerHTML = "";
  for (const d of state.domains){
    const b = document.createElement("button");
    b.type = "button"; b.className = "domain-item";
    b.setAttribute("aria-pressed", String(sel.value === d.domain));
    b.innerHTML = '<span class="dot"></span><span>' + esc(d.domain) + "</span>";
    b.addEventListener("click", () => {
      sel.value = d.domain; store.domain = d.domain; renderDomainControls();
    });
    nav.appendChild(b);
  }
  }
  renderDomainRows(); renderDomainTable(); renderDomainCards();
}

function renderDomainRows(){
  const wrap = $("domainRows");
  if (!wrap) return;
  if (!state.domains.length){ wrap.innerHTML = '<div class="hint">Belum ada domain terdaftar.</div>'; return; }
  wrap.innerHTML = state.domains.map((d) => `
    <button type="button" data-pick="${escAttr(d.domain)}">
      <span class="dot" style="width:6px;height:6px;border-radius:50%;background:var(--accent);display:inline-block"></span>
      <span class="mono">@${esc(d.domain)}</span>
      ${d.is_default ? '<span class="chip">default</span>' : ""}
    </button>`).join("");
  wrap.querySelectorAll("[data-pick]").forEach((b) =>
    b.addEventListener("click", () => {
      $("domainSelect").value = b.dataset.pick;
      store.domain = b.dataset.pick;
      if ($("exampleAddr")) $("exampleAddr").textContent = "nama@" + b.dataset.pick;
      $("previewAddr").textContent = "nama@" + b.dataset.pick;
      renderDomainControls();
    })
  );
}

function renderDomainTable(){
  const wrap = $("domainTable");
  if (!wrap) return;
  if (!state.domains.length){
    wrap.innerHTML = '<div class="empty-box" style="margin-top:4px">Belum ada domain terdaftar.</div>';
    return;
  }
  const memberOnly = !state.me || state.me.role === "member";
  wrap.innerHTML = state.domains.map((d) => {
    const locked = !!d.is_premium && memberOnly;
    return `<div class="drow">
      <span class="name">@${esc(d.domain)}</span>
      <span class="status">${esc(d.label || "tanpa label")}</span>
      <span class="def">${d.is_default ? '<span class="chip">default</span>' : ""}${d.is_premium ? '<span class="chip wait">premium</span>' : ""}${!d.is_default && !d.is_premium ? "-" : ""}</span>
      <button class="btn act" data-use="${escAttr(d.domain)}"${locked ? ' disabled title="Khusus VIP ke atas"' : ""}>Buat alamat</button>
    </div>`;
  }).join("");
  wrap.querySelectorAll("[data-use]").forEach((b) =>
    b.addEventListener("click", () => {
      $("domainSelect").value = b.dataset.use;
      store.domain = b.dataset.use;
      renderDomainControls();
      createInbox("");
    })
  );
}

function renderDomainCards(){
  const wrap = $("domainCards");
  if (!wrap) return;
  if (!state.domains.length){
    wrap.innerHTML = '<div class="empty-box" style="grid-column:1/-1">Belum ada domain terdaftar.</div>';
    return;
  }
  const memberOnly = !state.me || state.me.role === "member";
  wrap.innerHTML = state.domains.map((d) => {
    const locked = !!d.is_premium && memberOnly;
    return `<div class="card">
      <div style="display:flex;align-items:center;gap:8px;justify-content:space-between">
        <h3>${esc(d.label || d.domain)}</h3>
        ${d.is_premium ? '<span class="chip wait">premium</span>' : ""}
      </div>
      <div class="dom">${esc(d.domain)}</div>
      <div class="acts"><button class="btn" data-new-domain="${escAttr(d.domain)}"${locked ? ' disabled title="Khusus VIP ke atas"' : ""}>Buat alamat</button></div>
    </div>`;
  }).join("");
  wrap.querySelectorAll("[data-new-domain]").forEach((b) =>
    b.addEventListener("click", () => {
      store.domain = b.dataset.newDomain;
      location.hash = "#/inbox";
      createInbox("");
    })
  );
}

/* ---------- dialog alamat baru ---------- */
function dlgDomainValue(){
  const sel = $("dlgDomain");
  return sel && sel.value ? sel.value : (store.domain || "");
}
function dlgPreviewText(){
  const local = ($("dlgLocal").value || "").trim().toLowerCase().replace(/[^a-z0-9._-]/g, "").replace(/^\.+|\.+$/g, "").replace(/\.{2,}/g, ".");
  const dom = dlgDomainValue() || "domain";
  $("dlgPreview").textContent = (local || "nama.acak") + "@" + dom;
}
function openNewDialog(){
  const dlg = $("newAddrDlg");
  if (!dlg) { createInbox(""); return; }
  const sel = $("dlgDomain");
  sel.innerHTML = "";
  const memberOnly = !state.me || state.me.role === "member";
  for (const d of state.domains) {
    const locked = !!d.is_premium && memberOnly;
    const o = document.createElement("option");
    o.value = d.domain;
    o.textContent = d.domain + (locked ? " - premium (VIP)" : "");
    o.disabled = locked;
    sel.appendChild(o);
  }
  const preferred = (state.address && state.address.split("@")[1]) || store.domain || "";
  if (preferred && [...sel.options].some((o) => o.value === preferred && !o.disabled)) sel.value = preferred;
  $("dlgLocal").value = "";
  if ($("dlgNote")) $("dlgNote").value = "";
  if ($("dlgTtlWrap")) $("dlgTtlWrap").hidden = !canPickTtl();
  syncTtlOptions($("dlgTtl"));
  $("dlgMsg").hidden = true;
  dlgPreviewText();
  dlg.showModal();
  setTimeout(() => $("dlgLocal").focus(), 30);
}

/* ---------- smart OTP & verification link extractor ---------- */
function stripHtmlToText(s){
  if (!s) return "";
  return String(s)
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
    .replace(/\s+/g, " ")
    .trim();
}

function extractOtp(subject, textBody, htmlBody){
  const subj = String(subject || "").trim();
  const body = stripHtmlToText(textBody || htmlBody || "").slice(0, 2400);
  const combined = (subj + " \n " + body).replace(/#[0-9a-fA-F]{3,8}\b/g, " ");
  const hasCtx = /\b(otp|kode|code|pin|verifikasi|verification|verify|passcode|token|authenticat|masuk|login|sign[\s-]?in|confirm|konfirmasi|sandi|password|security|aktivasi|activate)\b/i.test(combined);
  if (!hasCtx) return null;

  // 1. Explicit pattern right after keyword (e.g. "Kode OTP Anda: 482910", "verification code is G-582910")
  const explicitRe = /\b(?:kode\s*(?:otp|verifikasi|keamanan|akses)?|verification\s*code|security\s*code|confirmation\s*code|login\s*code|passcode|one[-\s]?time\s*(?:password|code)|otp|pin|code|kode)\b[^0-9A-Za-z\n]{0,28}(?:G-)?\b(\d{4,8}|[A-Z0-9]{6,8})\b/gi;
  let m;
  while ((m = explicitRe.exec(combined)) !== null) {
    const cand = m[1];
    if (/^\d{4,8}$/.test(cand)) {
      const n = Number(cand);
      if (cand.length === 4 && n >= 1990 && n <= 2035) continue;
      return cand;
    }
    if (/^(?=.*\d)[A-Z0-9]{6,8}$/.test(cand)) return cand;
  }

  // 2. Pattern before keyword (e.g. "482910 adalah kode verifikasi", "482910 is your verification code")
  const beforeRe = /\b(\d{4,8})\b[^0-9A-Za-z\n]{0,20}\b(?:adalah\s+kode|is\s+your\s+(?:verification|security|login|confirmation|one-time)?\s*(?:code|otp|pin))\b/i.exec(combined);
  if (beforeRe) return beforeRe[1];

  // 3. Fallback: 6-digit number in subject or body when verification context is present
  const sixSubj = /\b(\d{6})\b/.exec(subj);
  if (sixSubj) return sixSubj[1];
  const sixBody = /\b(\d{6})\b/.exec(body);
  if (sixBody) return sixBody[1];
  return null;
}

function extractVerifyLink(textBody, htmlBody){
  const candidates = [];
  const skipRe = /\b(unsubscribe|berhenti[\s_-]?berlangganan|privacy|privasi|terms|ketentuan|help|support|bantuan|facebook\.com|twitter\.com|x\.com|instagram\.com|linkedin\.com|youtube\.com|tiktok\.com|fonts\.googleapis\.com|fonts\.gstatic\.com|w3\.org|schema\.org)\b/i;
  const assetRe = /\.(png|jpe?g|gif|webp|svg|ico|css|js|woff2?|ttf|eot)(\?|$)/i;
  const actionRe = /\b(verify|verifikasi|confirm|konfirmasi|activate|aktivasi|magic|login|signin|sign-in|auth|reset|token=|code=|key=|accept|approve|invitation|invite|validate|callback)\b/i;

  if (htmlBody) {
    const aRe = /<a\b[^>]*?\bhref\s*=\s*(?:"([^"]+)"|'([^']+)')[^>]*>([\s\S]*?)<\/a>/gi;
    let m;
    while ((m = aRe.exec(htmlBody)) !== null) {
      const rawUrl = (m[1] || m[2] || "").replace(/&amp;/g, "&").trim();
      const label = stripHtmlToText(m[3] || "");
      if (!/^https?:\/\//i.test(rawUrl)) continue;
      if (skipRe.test(rawUrl) || skipRe.test(label) || assetRe.test(rawUrl)) continue;
      let score = 1;
      if (actionRe.test(rawUrl)) score += 4;
      if (actionRe.test(label)) score += 5;
      if (rawUrl.length > 48) score += 1;
      candidates.push({ url: rawUrl, label: label.slice(0, 42) || "Buka link verifikasi", score });
    }
  }
  if (textBody) {
    const uRe = /https?:\/\/[^\s<>"')]+/gi;
    let m;
    while ((m = uRe.exec(textBody)) !== null) {
      const rawUrl = m[0].replace(/[.,;!?]+$/, "");
      if (skipRe.test(rawUrl) || assetRe.test(rawUrl)) continue;
      const score = actionRe.test(rawUrl) ? 5 : 1;
      candidates.push({ url: rawUrl, label: "Buka link verifikasi", score });
    }
  }
  if (!candidates.length) return null;
  candidates.sort((a, b) => b.score - a.score);
  return candidates[0].score >= 4 ? candidates[0] : null;
}

function hasExternalImages(html){
  if (!html) return false;
  return /<img\b[^>]*?\bsrc\s*=\s*["']https?:\/\//i.test(html);
}

function prepareEmailHtml(rawHtml, allowExternalImages){
  let html = String(rawHtml || "");
  if (!allowExternalImages) {
    html = html.replace(/(<img\b[^>]*?)\bsrc\s*=\s*(["']https?:\/\/[^"']+["'])/gi,
      '$1src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7" data-blocked-src=$2');
  }
  const headInject = '<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><base target="_blank" rel="noopener noreferrer">' +
    '<style>html,body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;line-height:1.5;margin:12px;color:#142126;max-width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch;box-sizing:border-box}a{word-break:break-word}img{max-width:100%!important;height:auto!important}table{max-width:100%!important}img[data-blocked-src]{opacity:0;pointer-events:none}</style>';
  if (/<head\b[^>]*>/i.test(html)) {
    return html.replace(/(<head\b[^>]*>)/i, "$1" + headInject);
  }
  return "<!doctype html><html><head>" + headInject + "</head><body>" + html + "</body></html>";
}

/* ---------- inbox ---------- */

async function createInbox(local, domain, ttlSec, note){
  domain = domain || ($("domainSelect") ? $("domainSelect").value : "") || store.domain;
  const qs = new URLSearchParams();
  if (domain) qs.set("domain", domain);
  if (ttlSec) qs.set("ttl", String(ttlSec));
  if (note && note.trim()) qs.set("note", note.trim());
  try {
    let j;
    if (local && local.trim()){
      qs.set("local", local.trim());
      j = await api("/api/custom?" + qs.toString(), { method: "POST" });
    } else {
      j = await api("/api/new?" + qs.toString(), { method: "POST" });
    }
    state.address = j.address; state.expires = j.expires_at; state.pinned = !!j.pinned; state.note = j.note || null;
    state.messages = []; state.selected = null; state.read = new Set(); state.seen = null; state.seenReady = false;
    store.address = j.address; store.expires = j.expires_at; store.pinned = state.pinned;
    store.domain = j.domain || domain; store.read = state.read;
    render(); loadInbox(); connectSSE(); loadAddresses(); loadMatrix({ silent: true });
    toast("Alamat dibuat: " + j.address);
  } catch (e){
    const map = {
      address_taken: "Alamat ini sedang digunakan pengguna lain. Pilih nama lain.",
      local_reserved: "Nama alamat ini dicadangkan sistem.",
      local_invalid: "Format nama alamat tidak valid (3-64 karakter, huruf/angka/titik).",
      domain_premium: "Domain ini khusus untuk pengguna VIP ke atas.",
      inbox_quota_reached: "Kuota 10 alamat aktif per domain sudah penuh."
    };
    toast(map[e.code] || ("Gagal membuat alamat: " + e.message), true);
  }
  $("localInput").value = "";
}

async function loadInbox(){
  if (!state.address) return;
  try {
    const j = await api("/api/inbox/" + encodeURIComponent(state.address));
    const next = j.messages || [];
    // beep & desktop notification hanya untuk pesan yang benar-benar baru
    if (!state.seen) { state.seen = new Set(); state.seenReady = false; }
    const fresh = next.filter((m) => !state.seen.has(m.id));
    state.seen = new Set(next.map((m) => m.id));
    const hadInitial = state.seenReady;
    state.seenReady = true;
    if (hadInitial && fresh.length) {
      nsPlay();
      fireDesktopNotify(fresh[0]);
      if (nsPrefs().autoOtp) {
        const autoCode = extractOtp(fresh[0].subject, fresh[0].snippet || "", "");
        if (autoCode && navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(autoCode).then(() => {
            toast("OTP otomatis disalin: " + autoCode);
          }).catch(() => {});
        }
      }
    }
    state.messages = next;
    state.note = j.note || null;
    state.pinned = !!j.pinned; store.pinned = state.pinned;
    if (j.expires_at){ state.expires = j.expires_at; store.expires = j.expires_at; }
    renderList(); renderTitle(); renderEmptyRead(); tick();
    if ($("addrNoteChip")) {
      $("addrNoteChip").textContent = state.note || "";
      $("addrNoteChip").hidden = !state.note;
    }
  } catch (e){
    if (e.status === 404 || e.status === 403 || e.code === "inbox_not_found" || e.code === "forbidden"){
      state.address = ""; store.address = ""; state.note = null; state.pinned = false; store.pinned = false;
      state.expires = 0; store.expires = 0;
      state.messages = []; state.selected = null; state.read = new Set(); state.seen = null; state.seenReady = false;
      store.read = state.read;
      if (evtSource) { try { evtSource.close(); } catch {} evtSource = null; }
      render();
    }
  }
}

function visibleMessages(){
  let rows = state.messages;
  if (state.filter === "unread") rows = rows.filter((m) => !state.read.has(m.id));
  const q = state.query.trim().toLowerCase();
  if (q) rows = rows.filter((m) =>
    (m.from_addr || "").toLowerCase().includes(q) ||
    (m.from_name || "").toLowerCase().includes(q) ||
    (m.subject || "").toLowerCase().includes(q));
  return rows;
}

function renderList(){
  const rows = visibleMessages();
  const list = $("msgList");
  if (!list) return;
  $("listCount").textContent = rows.length + " pesan";
  const unread = state.messages.filter((m) => !state.read.has(m.id)).length;
  $("navCount").textContent = String(state.messages.length);
  $("tabUnread").textContent = unread ? "Belum dibaca " + unread : "Belum dibaca";
  if ($("markAllReadBtn")) $("markAllReadBtn").hidden = unread === 0;
  if ($("clearMsgsBtn")) $("clearMsgsBtn").hidden = state.messages.length === 0;

  if (!rows.length){
    list.innerHTML = '<li><div class="empty-box" style="margin:12px 0">' +
      (state.messages.length ? "Tidak ada pesan yang cocok." : "Belum ada email masuk. Kirim ke alamat di atas.") +
      "</div></li>";
    return;
  }
  list.innerHTML = rows.map((m) => {
    const isUnread = !state.read.has(m.id);
    const who = m.from_name || m.from_addr || "Pengirim tidak dikenal";
    const otp = extractOtp(m.subject, m.snippet || "", "");
    const otpBadge = otp
      ? `<span class="otp-chip" role="button" tabindex="0" data-copy-otp="${escAttr(otp)}" title="Klik untuk salin kode OTP ${escAttr(otp)}">OTP ${esc(otp)}</span>`
      : "";
    return `<li>
      <button class="msg-row${isUnread ? " unread" : ""}" data-id="${escAttr(m.id)}" aria-selected="${state.selected === m.id}">
        <span class="from-line">
          ${isUnread ? '<span class="unread-dot" aria-hidden="true"></span>' : ""}
          <span class="who">${esc(who)}</span>
        </span>
        <span class="when">${fmtTime(m.received_at)}</span>
        <span class="subj">${esc(m.subject || "(tanpa subjek)")}${otpBadge}</span>
      </button></li>`;
  }).join("");
  list.querySelectorAll("[data-copy-otp]").forEach((chip) => {
    chip.addEventListener("click", async (ev) => {
      ev.stopPropagation();
      ev.preventDefault();
      const code = chip.dataset.copyOtp;
      try {
        await navigator.clipboard.writeText(code);
        toast("Kode OTP disalin: " + code);
      } catch {
        toast("Kode OTP: " + code);
      }
    });
  });
  list.querySelectorAll(".msg-row").forEach((b) =>
    b.addEventListener("click", () => openMessage(b.dataset.id)));
}

function estimateIframeHeight(htmlBody, textBody){
  const rawHtml = String(htmlBody || "");
  const plain = stripHtmlToText(textBody || rawHtml);
  const blockCount = (rawHtml.match(/<(p|div|tr|li|br|h[1-6]|table|blockquote)\b/gi) || []).length;
  const imgCount = (rawHtml.match(/<img\b/gi) || []).length;
  const est = 160 + Math.min(plain.length * 0.22, 360) + blockCount * 16 + imgCount * 75;
  return Math.round(Math.max(280, Math.min(est, 680)));
}

async function renderMessageIntoColumn(col, listColId, targetAddress, id, opts = {}){
  if (!col) return;
  col.classList.remove("expanded");
  col.innerHTML = '<div class="read-empty">Memuat pesan.</div>';
  if (window.matchMedia && window.matchMedia("(max-width: 820px)").matches) {
    setTimeout(() => { try { col.scrollIntoView({ behavior: "smooth", block: "start" }); } catch {} }, 40);
  }
  try {
    const m = await api("/api/message/" + encodeURIComponent(targetAddress) + "/" + encodeURIComponent(id));
    const hasHtml = !!m.html_body;
    const extImgs = hasHtml && hasExternalImages(m.html_body);
    const otp = extractOtp(m.subject, m.text_body, m.html_body);
    const vLink = extractVerifyLink(m.text_body, m.html_body);
    const smartBar = (otp || vLink)
      ? `<div class="smart-extract-bar">
          ${otp ? `<button type="button" class="smart-otp-btn" data-role="smartOtpBtn" data-otp="${escAttr(otp)}" title="Klik untuk salin kode OTP">Salin OTP: <b>${esc(otp)}</b></button>` : ""}
          ${vLink ? `<a class="smart-link-btn" href="${escAttr(vLink.url)}" target="_blank" rel="noopener noreferrer" title="${escAttr(vLink.url)}">${esc(vLink.label)} &nearr;</a>
          <button type="button" class="smart-otp-btn" data-role="smartCopyLinkBtn" data-url="${escAttr(vLink.url)}" title="Salin tautan verifikasi ke clipboard">Salin Link</button>` : ""}
        </div>`
      : "";
    const jumpInboxBtn = opts.showOpenInbox
      ? `<button type="button" class="btn btn-sm" data-role="openInSingleInbox" title="Buka alamat ${escAttr(targetAddress)} di tab Inbox">Buka di Inbox</button>`
      : "";
    col.innerHTML = `
      <div class="read-head">
        <button type="button" class="btn btn-sm mobile-back-btn" data-role="mobileBackToList">&uarr; Daftar pesan</button>
        <h2 class="read-subject">${esc(m.subject || "(tanpa subjek)")}</h2>
        <div class="read-meta">dari <b>${esc(m.from_name || m.from_addr || "—")}</b>
          ${m.from_addr ? "&lt;" + esc(m.from_addr) + "&gt;" : ""}
          · ${new Date(m.received_at).toLocaleString("id-ID")}
          ${opts.showOpenInbox ? ` · ke <span class="mono">${esc(targetAddress)}</span>` : ""}</div>
        ${smartBar}
      </div>
      ${hasHtml ? `<div class="read-tabs">
        <button class="tab" data-role="rHtml" aria-selected="true">HTML</button>
        <button class="tab" data-role="rText" aria-selected="false">Teks</button>
        <span style="margin-left:auto;display:inline-flex;gap:6px;align-items:center">
          ${jumpInboxBtn}
          ${extImgs ? '<button class="btn btn-sm" data-role="rImgToggle" type="button">Sembunyikan gambar</button>' : ""}
          <button class="btn btn-sm" data-role="rExpandToggle" type="button" title="Perbesar area baca email">Perbesar</button>
        </span>
      </div>` : (jumpInboxBtn ? `<div class="read-tabs">${jumpInboxBtn}</div>` : "")}
      <div class="read-body" data-role="readBody"></div>
      <div class="read-foot">
        <button class="btn" data-role="delBtn">Hapus pesan</button>
        ${m.has_eml
          ? `<a class="btn" href="/api/message/${encodeURIComponent(targetAddress)}/${encodeURIComponent(id)}/eml" title="File email mentah (.eml): header, isi, dan lampiran ter-encode. Untuk arsip/forensik.">Email mentah (.eml)</a>`
          : `<span class="btn" aria-disabled="true" title="Pesan lebih dari 6 MB: arsip .eml tidak disimpan, tapi lampiran tetap bisa diunduh.">Email mentah tidak diarsipkan</span>`}
        <dl class="kv" style="margin-left:auto">
          <dt>ke</dt><dd class="mono">${esc(m.to_addr || targetAddress)}</dd>
          <dt>ukuran</dt><dd>${fmtSize(m.raw_size)}</dd>
        </dl>
      </div>`;

    const q = (role) => col.querySelector(`[data-role="${role}"]`);

    if (q("mobileBackToList")) {
      q("mobileBackToList").addEventListener("click", () => {
        const lc = $(listColId) || col.parentElement?.querySelector(".list-col");
        if (lc) { try { lc.scrollIntoView({ behavior: "smooth", block: "start" }); } catch {} }
      });
    }

    if (q("openInSingleInbox")) {
      q("openInSingleInbox").addEventListener("click", () => {
        const box = (state.addressList || []).find((a) => a.address === targetAddress);
        state.address = targetAddress;
        state.expires = box ? box.expires_at : (Date.now() + 86400_000);
        state.pinned = box ? !!box.pinned : false;
        state.note = box ? (box.note || null) : null;
        state.selected = id;
        store.address = targetAddress; store.expires = state.expires; store.pinned = state.pinned;
        location.hash = "#/inbox";
        render();
        loadInbox().then(() => openMessage(id));
        connectSSE();
      });
    }

    if (q("smartOtpBtn")) {
      q("smartOtpBtn").addEventListener("click", async () => {
        const code = q("smartOtpBtn").dataset.otp;
        try {
          await navigator.clipboard.writeText(code);
          toast("Kode OTP disalin: " + code);
        } catch {
          toast("Kode OTP: " + code);
        }
      });
    }
    if (q("smartCopyLinkBtn")) {
      q("smartCopyLinkBtn").addEventListener("click", async () => {
        const u = q("smartCopyLinkBtn").dataset.url;
        try {
          await navigator.clipboard.writeText(u);
          toast("Tautan verifikasi disalin");
        } catch {
          toast("Gagal menyalin tautan", true);
        }
      });
    }

    const atts = Array.isArray(m.attachments) ? m.attachments : [];
    if (atts.length){
      const box = document.createElement("div");
      box.className = "atts";
      const base = "/api/attachment/" + encodeURIComponent(targetAddress) + "/" + encodeURIComponent(id) + "/";
      box.innerHTML = atts.map((a) => {
        const url = base + encodeURIComponent(a.id);
        const name = esc(a.filename || "lampiran");
        const size = fmtSize(a.size);
        if (/^image\/(png|jpe?g|gif|webp|avif|bmp)$/i.test(a.mime || "") && a.size <= 4 * 1024 * 1024) {
          return '<figure class="att" style="margin:0">' +
            '<a href="' + url + '" target="_blank" rel="noopener">' +
              '<img src="' + url + '" alt="' + escAttr(a.filename || "lampiran") + '" loading="lazy">' +
            '</a>' +
            '<a href="' + url + '" download title="Unduh ' + escAttr(a.filename || "") + '">' +
              name + ' <span class="ttl">' + size + '</span></a></figure>';
        }
        return '<a class="att-file" href="' + url + '" download title="Unduh ' + escAttr(a.filename || "") + '">' +
          name + ' <span class="ttl">' + size + '</span></a>';
      }).join("");
      const bodyEl = q("readBody");
      if (bodyEl) col.insertBefore(box, bodyEl); else col.appendChild(box);
    }

    let allowImages = true;
    const fitH = estimateIframeHeight(m.html_body, m.text_body);
    const showText = () => {
      const pre = document.createElement("pre");
      pre.textContent = m.text_body || "(isi kosong)";
      const body = q("readBody"); if (body) { body.innerHTML = ""; body.appendChild(pre); }
    };
    const showHtml = () => {
      const f = document.createElement("iframe");
      f.setAttribute("sandbox", "allow-popups allow-popups-to-escape-sandbox");
      f.setAttribute("referrerpolicy", "no-referrer");
      f.style.height = fitH + "px";
      f.srcdoc = prepareEmailHtml(m.html_body || "", allowImages);
      const body = q("readBody"); if (body) { body.innerHTML = ""; body.appendChild(f); }
    };
    if (hasHtml){
      showHtml();
      const setTab = (onRole, offRole) => {
        if (q(onRole)) q(onRole).setAttribute("aria-selected", "true");
        if (q(offRole)) q(offRole).setAttribute("aria-selected", "false");
      };
      q("rHtml").addEventListener("click", () => { showHtml(); setTab("rHtml", "rText"); });
      q("rText").addEventListener("click", () => { showText(); setTab("rText", "rHtml"); });
      if (q("rImgToggle")) {
        q("rImgToggle").addEventListener("click", () => {
          allowImages = !allowImages;
          q("rImgToggle").textContent = allowImages ? "Sembunyikan gambar" : "Tampilkan gambar";
          showHtml();
          setTab("rHtml", "rText");
        });
      }
      if (q("rExpandToggle")) {
        q("rExpandToggle").addEventListener("click", () => {
          const exp = col.classList.toggle("expanded");
          q("rExpandToggle").textContent = exp ? "Normal" : "Perbesar";
        });
      }
    } else showText();

    q("delBtn").addEventListener("click", async () => {
      await api("/api/message/" + encodeURIComponent(targetAddress) + "/" + encodeURIComponent(id), { method: "DELETE" });
      state.messages = state.messages.filter((x) => x.id !== id);
      state.allMessages = state.allMessages.filter((x) => x.id !== id);
      if (typeof opts.onDeleted === "function") opts.onDeleted();
      loadAddresses(); loadMatrix({ silent: true });
    });
  } catch (e){
    col.innerHTML = '<div class="read-empty">Pesan gagal dimuat: ' + esc(e.message) + "</div>";
  }
}

async function openMessage(id){
  state.selected = id;
  state.read.add(id); store.read = state.read;
  renderList();
  renderAllList();
  await renderMessageIntoColumn($("readCol"), "listCol", state.address, id, {
    showOpenInbox: false,
    onDeleted: () => {
      state.selected = null;
      if (state.allSelected === id) { state.allSelected = null; state.allSelectedAddr = ""; renderAllEmptyRead(); }
      renderEmptyRead(); renderList(); renderAllList(); renderTitle();
    },
  });
}

/* ---------- All Inbox (unified mix inbox across all user addresses) ---------- */
async function loadAllInbox(opts = {}){
  const silent = !!(opts && opts.silent);
  try {
    const j = await api("/api/my/messages?limit=300");
    const next = j.messages || [];
    if (!state.allSeen) { state.allSeen = new Set(); state.allSeenReady = false; }
    const fresh = next.filter((m) => !state.allSeen.has(m.id));
    state.allSeen = new Set(next.map((m) => m.id));
    const hadInitial = state.allSeenReady;
    state.allSeenReady = true;
    if (hadInitial && fresh.length && state.view === "all") {
      nsPlay();
      fireDesktopNotify(fresh[0]);
      if (nsPrefs().autoOtp) {
        const autoCode = extractOtp(fresh[0].subject, fresh[0].snippet || "", "");
        if (autoCode && navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(autoCode).then(() => {
            toast("OTP otomatis disalin: " + autoCode);
          }).catch(() => {});
        }
      }
    }
    state.allMessages = next;
    renderAllAddrFilter();
    renderAllList();
    if (state.view === "all") {
      renderTitle();
      renderAllEmptyRead();
    }
  } catch (e) {
    if (!silent) toast("Gagal memuat All Inbox: " + e.message, true);
  }
}

function renderAllAddrFilter(){
  const sel = $("allAddrFilter");
  const chip = $("allInboxCountChip");
  const addrs = state.addressList || [];
  if (chip) chip.textContent = addrs.length + " alamat aktif";
  if (!sel) return;
  const counts = new Map();
  for (const m of state.allMessages || []) {
    const a = (m.inbox || "").toLowerCase();
    counts.set(a, (counts.get(a) || 0) + 1);
  }
  const allKnown = new Map();
  for (const a of addrs) allKnown.set(a.address.toLowerCase(), a.note || "");
  for (const m of state.allMessages || []) {
    const a = (m.inbox || "").toLowerCase();
    if (a && !allKnown.has(a)) allKnown.set(a, m.inbox_note || "");
  }
  const prev = state.allAddrFilter || "";
  const optsHtml = ['<option value="">Semua alamat terdaftar (' + (state.allMessages || []).length + ')</option>']
    .concat([...allKnown.entries()].sort((a, b) => (counts.get(b[0]) || 0) - (counts.get(a[0]) || 0)).map(([addr, note]) => {
      const cnt = counts.get(addr) || 0;
      const lbl = addr + (note ? " · " + note : "") + " (" + cnt + ")";
      return `<option value="${escAttr(addr)}">${esc(lbl)}</option>`;
    }));
  sel.innerHTML = optsHtml.join("");
  if (prev && allKnown.has(prev)) sel.value = prev;
  else { sel.value = ""; state.allAddrFilter = ""; }
}

function visibleAllMessages(){
  let rows = state.allMessages || [];
  if (state.allAddrFilter) {
    rows = rows.filter((m) => (m.inbox || "").toLowerCase() === state.allAddrFilter);
  }
  if (state.allFilter === "unread") {
    rows = rows.filter((m) => !state.read.has(m.id));
  }
  const q = (state.allQuery || "").trim().toLowerCase();
  if (q) {
    rows = rows.filter((m) =>
      (m.from_addr || "").toLowerCase().includes(q) ||
      (m.from_name || "").toLowerCase().includes(q) ||
      (m.subject || "").toLowerCase().includes(q) ||
      (m.inbox || "").toLowerCase().includes(q) ||
      (m.inbox_note || "").toLowerCase().includes(q));
  }
  return rows;
}

function renderAllList(){
  const all = state.allMessages || [];
  if ($("navAllCount")) $("navAllCount").textContent = String(all.length);
  const list = $("allMsgList");
  if (!list) return;
  const rows = visibleAllMessages();
  if ($("allListCount")) $("allListCount").textContent = rows.length + " pesan";
  const unread = all.filter((m) => !state.read.has(m.id)).length;
  if ($("allTabUnread")) $("allTabUnread").textContent = unread ? "Belum dibaca " + unread : "Belum dibaca";
  if ($("allMarkAllReadBtn")) $("allMarkAllReadBtn").hidden = unread === 0;

  if (!rows.length){
    list.innerHTML = '<li><div class="empty-box" style="margin:12px 0">' +
      (all.length ? "Tidak ada pesan yang cocok dengan filter." : "Belum ada email masuk di alamat mana pun.") +
      "</div></li>";
    return;
  }
  list.innerHTML = rows.map((m) => {
    const isUnread = !state.read.has(m.id);
    const who = m.from_name || m.from_addr || "Pengirim tidak dikenal";
    const otp = extractOtp(m.subject, m.snippet || "", "");
    const otpBadge = otp
      ? `<span class="otp-chip" role="button" tabindex="0" data-copy-otp="${escAttr(otp)}" title="Klik untuk salin kode OTP ${escAttr(otp)}">OTP ${esc(otp)}</span>`
      : "";
    const noteChip = m.inbox_note ? `<span class="all-note-chip">${esc(m.inbox_note)}</span>` : "";
    return `<li>
      <button class="msg-row${isUnread ? " unread" : ""}" data-all-id="${escAttr(m.id)}" data-all-addr="${escAttr(m.inbox)}" aria-selected="${state.allSelected === m.id}">
        <span class="from-line">
          ${isUnread ? '<span class="unread-dot" aria-hidden="true"></span>' : ""}
          <span class="who">${esc(who)}</span>
        </span>
        <span class="when">${fmtTime(m.received_at)}</span>
        <span class="all-to-line">
          <span class="all-to-chip" title="Masuk ke ${escAttr(m.inbox)}">ke: ${esc(m.inbox)}</span>
          ${noteChip}
        </span>
        <span class="subj">${esc(m.subject || "(tanpa subjek)")}${otpBadge}</span>
      </button></li>`;
  }).join("");

  list.querySelectorAll("[data-copy-otp]").forEach((chip) => {
    chip.addEventListener("click", async (ev) => {
      ev.stopPropagation();
      ev.preventDefault();
      const code = chip.dataset.copyOtp;
      try {
        await navigator.clipboard.writeText(code);
        toast("Kode OTP disalin: " + code);
      } catch {
        toast("Kode OTP: " + code);
      }
    });
  });
  list.querySelectorAll("[data-all-id]").forEach((b) =>
    b.addEventListener("click", () => openAllMessage(b.dataset.allAddr, b.dataset.allId)));
}

async function openAllMessage(address, id){
  state.allSelected = id;
  state.allSelectedAddr = address;
  state.read.add(id); store.read = state.read;
  renderAllList();
  renderList();
  await renderMessageIntoColumn($("allReadCol"), "allListCol", address, id, {
    showOpenInbox: true,
    onDeleted: () => {
      state.allSelected = null;
      state.allSelectedAddr = "";
      if (state.selected === id) { state.selected = null; renderEmptyRead(); }
      renderAllEmptyRead(); renderAllList(); renderList(); renderTitle();
    },
  });
}

function renderAllEmptyRead(){
  if (state.allSelected) return;
  const col = $("allReadCol");
  if (!col) return;
  const total = (state.allMessages || []).length;
  const unread = (state.allMessages || []).filter((m) => !state.read.has(m.id)).length;
  col.innerHTML = `
    <div class="read-empty">
      <h2>Belum ada pesan dibuka</h2>
      <p>Semua email yang masuk ke seluruh alamat terdaftar Anda berkumpul di sini secara real-time.</p>
      <dl class="kv">
        <dt>alamat aktif</dt><dd>${(state.addressList || []).length}</dd>
        <dt>total pesan</dt><dd>${total}</dd>
        <dt>belum dibaca</dt><dd>${unread}</dd>
      </dl>
    </div>`;
}
function pickTab(on, off){
  $(on).setAttribute("aria-selected","true");
  $(off).setAttribute("aria-selected","false");
}

function renderEmptyRead(){
  if (state.selected) return;
  const col = $("readCol");
  if (!col) return;
  const live = state.expires > Date.now() || state.pinned;
  const leftText = state.pinned ? "disimpan permanen" : (live ? fmtLeft(state.expires - Date.now()) : "kedaluwarsa");
  col.innerHTML = `
    <div class="read-empty">
      <h2>Belum ada pesan dibuka</h2>
      <p>Pilih satu pesan di kolom kiri. Email yang masuk ke alamat aktif muncul di daftar itu dalam beberapa detik.</p>
      <dl class="kv">
        <dt>alamat</dt><dd class="mono">${esc(state.address || "belum ada")}</dd>
        <dt>domain</dt><dd class="mono">${esc((state.address || "").split("@")[1] || "belum ada")}</dd>
        <dt>pesan</dt><dd>${state.messages.length}</dd>
        <dt>sisa waktu</dt><dd>${state.address ? leftText : "belum ada"}</dd>
      </dl>
    </div>`;
}

/* ---------- users (staff) ---------- */
async function loadUsers(){
  if (!isStaff()) return;
  try {
    const j = await api("/api/admin/users");
    state.users = j.users || [];
    state.pending = (j.counts && j.counts.pending) || 0;
    $("navPending").textContent = String(state.pending);
    try { const rr = await api("/api/admin/resets"); state.resetRequests = rr.requests || []; } catch { state.resetRequests = []; }
    fillRoleOptions();
    renderUsers(); renderResetQueue();
  } catch { /* diamkan */ }
}

function fillRoleOptions(){
  const sel = $("cuRole");
  if (!sel) return;
  const isOwner = state.me && state.me.role === "owner";
      sel.innerHTML = '<option value="member">member</option>'
        + (isOwner ? '<option value="vip">vip</option><option value="admin">admin</option>' : "");
}

async function createUser(){
  const msg = $("cuMsg"); msg.hidden = true;
  const btn = $("cuBtn"); btn.disabled = true;
  try {
    const j = await api("/api/admin/users", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({
        email: $("cuEmail").value,
        name: $("cuName").value,
        password: $("cuPass").value,
        role: $("cuRole").value
      })
    });
    showMsg(msg, "Akun dibuat: " + j.user.email + " (" + j.user.role + ").", "ok");
    $("cuEmail").value = ""; $("cuName").value = ""; $("cuPass").value = "";
    await loadUsers();
  } catch (e){
    const map = {
      email_taken: "Email sudah terdaftar.",
      invalid_email: "Format email tidak valid.",
      password_too_short: "Kata sandi minimal 8 karakter.",
      owner_required_for_admin: "Hanya owner yang bisa membuat admin."
    };
    showMsg(msg, map[e.code] || ("Gagal membuat akun: " + e.message), "err");
  } finally { btn.disabled = false; }
}

function renderUsers(){
  const wrap = $("userTable");
  if (!wrap) return;
  let rows = state.users;
  if (state.userFilter === "pending") rows = rows.filter((u) => u.status === "pending");
  if (state.userFilter === "approved") rows = rows.filter((u) => u.status === "approved");
  $("uCount").textContent = rows.length + " akun";

  if (!rows.length){
    wrap.innerHTML = '<div class="empty-box" style="margin-top:12px">Tidak ada akun pada filter ini.</div>';
    return;
  }
  const RANK = RANK_OF;
  const myRank = RANK[state.me.role] || 0;
  const isOwner = state.me.role === "owner";

  wrap.innerHTML = rows.map((u) => {
    const chip = u.status === "approved" ? "ok" : u.status === "pending" ? "wait" : "no";
    const mine = (RANK[u.role] || 0) < myRank;
    const self = u.id === state.me.id;
    const head = `<span class="em">${esc(u.email)}<small>${esc(u.name || "tanpa nama")} - daftar ${fmtDate(u.created_at)}</small></span>
      <span class="chip ${chip}">${u.status}</span>
      ${roleBadge(u.role)}`;

    if (self || !mine) {
      return `<div class="urow">${head}<span class="acts">${self ? '<span class="status">akun Anda</span>' : ""}</span></div>`;
    }

    const items = [];
    if (u.status !== "approved") items.push(`<button class="menu-item" data-act="approve" data-id="${escAttr(u.id)}">Setujui</button>`);
    if (u.status === "approved") items.push(`<button class="menu-item" data-act="suspend" data-id="${escAttr(u.id)}">Tangguhkan</button>`);
    if (u.status !== "rejected") items.push(`<button class="menu-item" data-act="reject" data-id="${escAttr(u.id)}">Tolak</button>`);
    items.push(`<button class="menu-item" data-reset="${escAttr(u.id)}">Tautan reset</button>`);
    if (isOwner) {
      if (u.role !== "vip") items.push(`<button class="menu-item" data-act="vip" data-id="${escAttr(u.id)}">Jadikan VIP</button>`);
      if (u.role !== "admin") items.push(`<button class="menu-item" data-act="promote" data-id="${escAttr(u.id)}">Jadikan admin</button>`);
      if (u.role !== "member") items.push(`<button class="menu-item" data-act="demote" data-id="${escAttr(u.id)}">Jadikan member</button>`);
    }
    items.push(`<button class="menu-item danger" data-deluser="${escAttr(u.id)}" data-email="${escAttr(u.email)}">Hapus akun</button>`);

    return `<div class="urow">${head}
      <span class="acts">
        <button class="btn btn-sm" data-uibox="${escAttr(u.id)}">Inbox</button>
        <details class="rowmenu"><summary class="btn btn-sm">Aksi</summary>
          <div class="menu-pop">${items.join("")}</div>
        </details>
      </span>
    </div>`;
  }).join("");

  const closeMenus = () => wrap.querySelectorAll("details.rowmenu[open]").forEach((d) => d.removeAttribute("open"));

  wrap.querySelectorAll("[data-act]").forEach((b) => {
    b.addEventListener("click", () => { closeMenus(); userAction(b.dataset.id, b.dataset.act); });
  });
  wrap.querySelectorAll("[data-reset]").forEach((b) => {
    b.addEventListener("click", () => { closeMenus(); adminReset(b.dataset.reset); });
  });
  wrap.querySelectorAll("[data-deluser]").forEach((b) => {
    b.addEventListener("click", async () => {
      closeMenus();
      if (!confirm("Hapus akun " + b.dataset.email + "? Semua inbox dan datanya ikut terhapus.")) return;
      try {
        await api("/api/admin/users/" + encodeURIComponent(b.dataset.deluser), { method: "DELETE" });
        toast("Akun dihapus: " + b.dataset.email);
        await loadUsers();
      } catch (e){
        const map = {
          cannot_delete_self: "Tidak bisa menghapus akun sendiri.",
          cannot_delete_owner: "Akun owner tidak bisa dihapus.",
          not_permitted: "Tidak punya izin menghapus akun ini."
        };
        toast(map[e.code] || ("Gagal: " + e.message), true);
      }
    });
  });

  wrap.querySelectorAll("[data-uibox]").forEach((b) => {
    b.addEventListener("click", () => {
      const u = (state.users || []).find((x) => x.id === b.dataset.uibox);
      if (u) openUserInbox(u);
    });
  });
}

async function adminReset(id){
  try {
    const j = await api("/api/admin/users/" + encodeURIComponent(id) + "/reset", { method: "POST" });
    state.lastReset = j;
    renderResetQueue();
    try { await navigator.clipboard.writeText(j.link); toast("Tautan reset disalin untuk " + j.email); }
    catch { toast("Tautan reset dibuat untuk " + j.email); }
  } catch (e){ toast("Gagal membuat tautan: " + e.message, true); }
}

function renderResetQueue(){
  const wrap = $("resetQueue");
  if (!wrap) return;
  const reqs = state.resetRequests || [];
  const last = state.lastReset;
  if (!reqs.length && !last){ wrap.innerHTML = ""; return; }
  let html = '<div class="panel" style="margin-top:24px">';
  if (last){
    html += `<h2 class="panel-title">Tautan reset terakhir</h2>
      <div class="drow" style="grid-template-columns:1fr auto">
        <span class="em">${esc(last.email)}<small class="mono" style="display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(last.link)}</small></span>
        <button class="btn btn-sm act" data-copy-link="${escAttr(last.link)}">Salin tautan</button>
      </div>`;
  }
  if (reqs.length){
    html += `<h2 class="panel-title" style="margin-top:18px">Permintaan lupa sandi (${reqs.length})</h2>` +
      reqs.map((r) => `<div class="drow">
        <span class="name">${esc(r.email)}</span>
        <span class="status">${esc(r.name || "tanpa nama")}</span>
        <span class="def">${fmtDate(r.created_at)}</span>
        <button class="btn btn-sm act" data-req-reset="${escAttr(r.user_id)}">Buat tautan</button>
      </div>`).join("");
  }
  html += "</div>";
  wrap.innerHTML = html;
  wrap.querySelectorAll("[data-req-reset]").forEach((b) =>
    b.addEventListener("click", () => adminReset(b.dataset.reqReset)));
  wrap.querySelectorAll("[data-copy-link]").forEach((b) =>
    b.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(b.dataset.copyLink); toast("Tautan disalin"); }
      catch { toast("Gagal menyalin, salin manual.", true); }
    }));
}
async function userAction(id, act){
  const map = {
    approve: { status: "approved" },
    reject: { status: "rejected" },
    suspend: { status: "suspended" },
    promote: { role: "admin" },
    vip: { role: "vip" },
    demote: { role: "member" }
  };
  try {
    await api("/api/admin/users/" + encodeURIComponent(id), {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(map[act])
    });
    toast("Akun diperbarui.");
    await loadUsers();
  } catch (e){
    toast("Gagal: " + e.message, true);
  }
}

/* ---------- title / render ---------- */
function renderTitle(){
  const v = state.view;
  if (v === "all"){
    $("pageTitle").textContent = "All Inbox";
    const total = (state.allMessages || []).length;
    const unread = (state.allMessages || []).filter((m) => !state.read.has(m.id)).length;
    const parts = [total + " pesan dari " + (state.addressList || []).length + " alamat aktif"];
    if (unread) parts.push(unread + " belum dibaca");
    $("pageSub").textContent = parts.join(" · ");
    return;
  }
  if (v === "addresses"){ $("pageTitle").textContent = "Alamat"; $("pageSub").textContent = (state.addressList || []).length + " alamat aktif"; return; }
  if (v === "matrix"){ $("pageTitle").textContent = "Account Matrix"; $("pageSub").textContent = (state.matrixList || []).length + " akun terdaftar · Identity, Live 2FA TOTP & Email OTP"; return; }
  if (v === "account"){ $("pageTitle").textContent = "Pengaturan akun"; $("pageSub").innerHTML = esc(state.me ? state.me.email : "") + ' ' + (state.me ? roleBadge(state.me.role) : ""); return; }
  if (v === "audit"){ $("pageTitle").textContent = "Log aktivitas"; $("pageSub").textContent = (state.audit || []).length + " kejadian terakhir"; return; }
  if (v === "dashboard"){ $("pageTitle").textContent = "Ringkasan"; $("pageSub").textContent = "Statistik 14 hari terakhir"; return; }
  if (v === "domains"){
    $("pageTitle").textContent = "Domain";
    $("pageSub").textContent = state.domains.length + " domain terdaftar";
    return;
  }
  if (v === "users"){
    $("pageTitle").textContent = "Pengguna";
    $("pageSub").textContent = state.pending
      ? state.pending + " pendaftaran menunggu persetujuan"
      : "Tidak ada pendaftaran menunggu";
    return;
  }
  $("pageTitle").textContent = "Inbox";
  if (!state.address){
    $("pageSub").textContent = "Belum ada alamat aktif. Buat satu untuk mulai menerima email.";
    return;
  }
  const n = state.messages.length;
  const unread = state.messages.filter((m) => !state.read.has(m.id)).length;
  const left = state.expires - Date.now();
  const parts = [n + " pesan"];
  if (unread) parts.push(unread + " belum dibaca");
  parts.push(state.pinned ? "disimpan permanen" : (left > 0 ? "kedaluwarsa dalam " + fmtLeft(left) : "alamat kedaluwarsa"));
  $("pageSub").textContent = parts.join(" · ");
}

function render(){
  // satu sumber kebenaran: alamat dianggap ada kalau belum kedaluwarsa atau di-pin permanen
  const live = !!state.address && (state.expires > Date.now() || state.pinned);
  if (state.address && !live){
    state.address = ""; store.address = ""; state.pinned = false; store.pinned = false;
    state.expires = 0; store.expires = 0;
    state.messages = []; state.selected = null;
  }
  const hasAddr = !!state.address;
  $("setupBox").hidden = hasAddr;
  if ($("setupTtlWrap")) $("setupTtlWrap").hidden = !canPickTtl();
  syncTtlOptions($("setupTtl"));
  if ($("ttlInfo")) {
    const r = state.me ? state.me.role : "member";
    $("ttlInfo").textContent = r === "member" ? "7 hari" : r === "vip" ? "bebas (maks 90 hari)" : r === "admin" ? "bebas (maks 90 hari)" : "bebas (maks 365 hari)";
  }
  $("addressStrip").hidden = !hasAddr;
  $("inboxBody").hidden = !hasAddr;
  $("addrText").textContent = state.address || "—";
  if ($("addrNoteChip")) {
    $("addrNoteChip").textContent = state.note || "";
    $("addrNoteChip").hidden = !hasAddr || !state.note;
  }
  $("copyTop").disabled = !hasAddr;
  renderAddrSwitcher();
  tick(); renderTitle(); renderList(); renderEmptyRead();
}

function tick(){
  if (!state.me || !$("appShell")) return;
  if ($("ttlInfo") && state.me){
    const r = state.me.role;
    $("ttlInfo").textContent = r === "member" ? "7 hari" : r === "vip" ? "bebas (maks 90 hari)" : r === "admin" ? "bebas (maks 90 hari)" : "bebas (maks 365 hari)";
  }
  const left = state.expires - Date.now();
  const live = state.address && (left > 0 || state.pinned);
  const text = state.pinned ? "disimpan permanen" : (left > 0 ? fmtLeft(left) : "kedaluwarsa");
  if ($("ttlInline")) $("ttlInline").textContent = state.pinned ? "disimpan permanen" : (left > 0 ? "sisa " + text : "kedaluwarsa");
  if ($("ttlK")) $("ttlK").textContent = state.pinned ? "Disimpan permanen" : (live ? "Alamat aktif" : (state.address ? "Alamat kedaluwarsa" : "Belum ada alamat aktif"));
  if ($("ttlV")) $("ttlV").textContent = state.pinned ? "Permanen" : (left > 0
    ? new Date(state.expires).toLocaleTimeString("id-ID", {hour:"2-digit", minute:"2-digit"}) : "—");
  if ($("addrDomain") && state.address) $("addrDomain").textContent = state.address.split("@")[1] || "—";
  if (state.view === "matrix") tickMatrixTotp();
}

let toastTimer = null;
function toast(msg, bad){
  let el = $("toast");
  if (!el){
    el = document.createElement("div");
    el.id = "toast";
    el.style.cssText = "position:fixed;left:50%;transform:translateX(-50%);bottom:max(20px,calc(env(safe-area-inset-bottom,0px) + 14px));z-index:30;background:#1d1f20;color:#fff;padding:10px 14px;border-radius:8px;font-size:13px;max-width:90vw;box-shadow:0 6px 20px rgba(0,0,0,.22)";
    document.body.appendChild(el);
  }
  el.style.background = bad ? "#c4242a" : "#1d1f20";
  el.textContent = msg; el.style.display = "block";
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.style.display = "none"; }, 3200);
}

const VIEWS = ["inbox", "all", "addresses", "matrix", "domains", "account", "users", "audit", "dashboard"];

function route(){
  const h = location.hash.replace(/^#\/?/, "") || "inbox";
  state.view = VIEWS.includes(h) ? h : "inbox";
  if ((state.view === "users" || state.view === "audit" || state.view === "dashboard") && !isStaff()) state.view = "inbox";

  $("inboxView").hidden = state.view !== "inbox";
  if ($("allInboxView")) $("allInboxView").hidden = state.view !== "all";
  $("addressesView").hidden = state.view !== "addresses";
  if ($("matrixView")) $("matrixView").hidden = state.view !== "matrix";
  $("domainsView").hidden = state.view !== "domains";
  $("accountView").hidden = state.view !== "account";
  $("usersView").hidden = state.view !== "users";
  $("auditView").hidden = state.view !== "audit";
  if ($("dashboardView")) $("dashboardView").hidden = state.view !== "dashboard";

  document.querySelectorAll("[data-nav]").forEach((a) =>
    a.setAttribute("aria-current", a.dataset.nav === state.view ? "page" : "false"));

  const ta = document.querySelector(".title-actions");
  if (ta) ta.hidden = state.view !== "inbox";

  if (state.view === "all") {
    loadAllInbox();
    connectAllSSE();
  } else {
    disconnectAllSSE();
  }
  if (state.view === "addresses") loadAddresses();
  if (state.view === "matrix") loadMatrix();
  if (state.view === "domains") { loadDomains(); loadAdminDomains(); }
  if (state.view === "account") { loadKeys(); loadTOTP(); nsInit(); }
  if (state.view === "users") loadUsers();
  if (state.view === "audit") loadAudit();
  if (state.view === "dashboard") loadDashboard();
  if (state.view !== "addresses") { if ($("bulkBar")) $("bulkBar").hidden = true; if (state.sel) state.sel.clear(); }

  if ($("searchInput")) {
    $("searchInput").value = state.view === "all" ? (state.allQuery || "") : (state.query || "");
    $("searchInput").placeholder = state.view === "all" ? "Cari pengirim, subjek, atau alamat tujuan" : "Cari pengirim atau subjek";
  }

  renderTitle();
  closeNav();
}

/* ---------- alamat saya ---------- */
async function loadAddresses(){
  try { const j = await api("/api/my/inboxes"); state.addressList = j.inboxes || []; }
  catch { state.addressList = []; }
  $("navAddr").textContent = String(state.addressList.length);
  renderAddresses();
  renderAddrSwitcher();
  renderAllAddrFilter();
  if (state.view === "all") renderTitle();
}

function renderAddrSwitcher(){
  const wrap = $("addrSwitchWrap"), list = $("addrSwitchList");
  if (!wrap || !list) return;
  const rows = state.addressList || [];
  if (!state.address || rows.length <= 1) {
    wrap.hidden = true;
    wrap.removeAttribute("open");
    return;
  }
  wrap.hidden = false;
  list.innerHTML = rows.map((a) => {
    const cur = a.address === state.address;
    return `<button type="button" class="menu-item addr-switch-item" data-switch-addr="${escAttr(a.address)}" data-current="${cur}">
      <span class="asi-main">
        <span class="asi-addr">${esc(a.address)}</span>
        ${a.note ? `<span class="asi-note">${esc(a.note)}</span>` : ""}
      </span>
      <span class="chip${cur ? " ok" : ""}">${a.messages || 0}</span>
    </button>`;
  }).join("");
  list.querySelectorAll("[data-switch-addr]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetAddr = btn.dataset.switchAddr;
      wrap.removeAttribute("open");
      if (!targetAddr || targetAddr === state.address) return;
      const item = (state.addressList || []).find((x) => x.address === targetAddr) || {};
      state.address = targetAddr;
      state.expires = item.expires_at || 0;
      state.pinned = !!item.pinned;
      state.note = item.note || null;
      state.messages = []; state.selected = null; state.read = new Set(); state.seen = null; state.seenReady = false;
      store.address = state.address; store.expires = state.expires; store.pinned = state.pinned; store.read = state.read;
      render(); loadInbox(); connectSSE();
      toast("Beralih ke: " + targetAddr);
    });
  });
}

function renderAddresses(){
  const wrap = $("addressRows");
  if (!wrap) return;
  const all = state.addressList || [];
  const q = (state.addrQuery || "").trim().toLowerCase();
  const rows = q ? all.filter((a) =>
    a.address.toLowerCase().includes(q) ||
    (a.note || "").toLowerCase().includes(q)
  ) : all;
  const bb = $("bulkBar");
  if (bb) bb.hidden = !(state.sel && state.sel.size);
  if (!rows.length){
    wrap.innerHTML = '<div class="empty-box" style="margin-top:12px">' +
      (q ? "Tidak ada alamat yang cocok." : "Belum ada alamat aktif.") + "</div>";
    const se = $("selAll");
    if (se) { se.checked = false; se.indeterminate = false; }
    return;
  }
  wrap.innerHTML = rows.map((a) => {
    const left = a.expires_at - Date.now();
    const expTxt = left > 0 ? "sisa " + fmtLeft(left) : "kedaluwarsa";
    const live = state.address === a.address;
    const pinned = !!a.pinned;
    const checked = state.sel && state.sel.has(a.address);
    const noteBadge = a.note ? `<span class="chip note-chip" title="${escAttr(a.note)}">${esc(a.note)}</span>` : "";
    return `<div class="aitem${live ? " live" : ""}">
      <span class="sel"><input type="checkbox" data-sel="${escAttr(a.address)}"${checked ? " checked" : ""} aria-label="Pilih ${escAttr(a.address)}"></span>
      <span class="addr">
        <button type="button" class="addr-open" data-open="${escAttr(a.address)}" title="Klik untuk membuka inbox ${escAttr(a.address)}">
          <span class="addr-txt">${esc(a.address)}</span>
          ${noteBadge}
        </button>
      </span>
      <span class="meta">
        <span class="chip">${a.messages} pesan</span>
        <span class="chip ${pinned || left > 0 ? "ok" : "no"}">${pinned ? "disimpan permanen" : expTxt}</span>
      </span>
      <span class="acts">
        <details class="rowmenu">
          <summary class="btn btn-sm more-btn" title="Menu aksi" aria-label="Menu aksi">⋯</summary>
          <div class="menu-pop">
            <button type="button" class="menu-item" data-copy="${escAttr(a.address)}">Salin alamat</button>
            <button type="button" class="menu-item" data-open-mx="${escAttr(a.address)}">⚡ Buka di Account Matrix</button>
            <button type="button" class="menu-item" data-note="${escAttr(a.address)}" data-cur-note="${escAttr(a.note || "")}">Label / catatan</button>
            <button type="button" class="menu-item" data-extend="${escAttr(a.address)}">Perpanjang masa aktif</button>
            <button type="button" class="menu-item" data-pin="${escAttr(a.address)}" data-pinned="${pinned ? 1 : 0}">${pinned ? "Lepas simpanan permanen" : "Simpan permanen"}</button>
            <button type="button" class="menu-item" data-qr="${escAttr(a.address)}">Kode QR</button>
            <button type="button" class="menu-item" data-export="${escAttr(a.address)}">Ekspor pesan</button>
            <button type="button" class="menu-item" data-wh="${escAttr(a.address)}">Webhook</button>
            ${isStaff() ? `<button type="button" class="menu-item" data-log="${escAttr(a.address)}">Log email masuk</button>` : ""}
            <button type="button" class="menu-item danger" data-del="${escAttr(a.address)}">Hapus alamat</button>
          </div>
        </details>
      </span>
    </div>`;
  }).join("");

  const selAll = $("selAll");
  const syncSelAll = () => {
    if (!selAll) return;
    const addrs = rows.map((a) => a.address);
    const n = addrs.filter((a) => state.sel && state.sel.has(a)).length;
    selAll.checked = n > 0 && n === addrs.length;
    selAll.indeterminate = n > 0 && n < addrs.length;
  };
  if (selAll) {
    selAll.onchange = () => {
      const addrs = rows.map((a) => a.address);
      if (selAll.checked) addrs.forEach((a) => state.sel.add(a));
      else addrs.forEach((a) => state.sel.delete(a));
      wrap.querySelectorAll("[data-sel]").forEach((cb) => { cb.checked = selAll.checked; });
      syncBulkBar();
      syncSelAll();
    };
    syncSelAll();
  }

  wrap.querySelectorAll("[data-open]").forEach((b) =>
    b.addEventListener("click", () => {
      const item = (state.addressList || []).find((x) => x.address === b.dataset.open) || {};
      state.address = b.dataset.open;
      state.expires = item.expires_at || 0;
      state.pinned = !!item.pinned;
      state.note = item.note || null;
      state.messages = []; state.selected = null; state.read = new Set(); state.seen = null; state.seenReady = false;
      store.address = state.address; store.expires = state.expires; store.pinned = state.pinned; store.read = state.read;
      location.hash = "#/inbox";
      render(); loadInbox(); connectSSE();
    }));
  wrap.querySelectorAll("[data-copy]").forEach((b) =>
    b.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(b.dataset.copy); toast("Alamat disalin"); }
      catch { toast("Gagal menyalin", true); }
    }));
  wrap.querySelectorAll("[data-open-mx]").forEach((b) =>
    b.addEventListener("click", () => jumpToMatrixForAddress(b.dataset.openMx)));
  wrap.querySelectorAll("[data-note]").forEach((b) =>
    b.addEventListener("click", () => openNoteDialog(b.dataset.note, b.dataset.curNote || "")));
  wrap.querySelectorAll("[data-sel]").forEach((b) =>
    b.addEventListener("change", () => {
      if (b.checked) state.sel.add(b.dataset.sel); else state.sel.delete(b.dataset.sel);
      syncBulkBar();
      syncSelAll();
    }));
  wrap.querySelectorAll("[data-qr]").forEach((b) =>
    b.addEventListener("click", () => openQr(b.dataset.qr)));
  wrap.querySelectorAll("[data-export]").forEach((b) =>
    b.addEventListener("click", () => openExport(b.dataset.export)));
  wrap.querySelectorAll("[data-wh]").forEach((b) =>
    b.addEventListener("click", () => openWebhook(b.dataset.wh)));
  wrap.querySelectorAll("[data-pin]").forEach((b) =>
    b.addEventListener("click", async () => {
      const next = b.dataset.pinned !== "1";
      try {
        await api("/api/inbox/" + encodeURIComponent(b.dataset.pin), {
          method: "PATCH",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ pinned: next })
        });
        if (state.address === b.dataset.pin) {
          state.pinned = next;
          store.pinned = next;
          tick(); renderTitle();
        }
        toast(next ? "Alamat disimpan permanen" : "Penyimpanan permanen dilepas");
        loadAddresses();
      } catch (e){ toast("Gagal: " + e.message, true); }
    }));
  wrap.querySelectorAll("[data-log]").forEach((b) =>
    b.addEventListener("click", () => openInboxLog(b.dataset.log)));
  wrap.querySelectorAll("[data-extend]").forEach((b) =>
    b.addEventListener("click", () => openTtlDialog(b.dataset.extend)));
  wrap.querySelectorAll("[data-del]").forEach((b) =>
    b.addEventListener("click", async () => {
      if (!confirm("Hapus inbox " + b.dataset.del + " beserta semua pesannya?")) return;
      try {
        await api("/api/inbox/" + encodeURIComponent(b.dataset.del), { method: "DELETE" });
        toast("Inbox dihapus");
        if (state.address === b.dataset.del) {
          state.address = ""; store.address = ""; state.expires = 0; store.expires = 0;
          state.messages = []; state.selected = null; render();
        }
        loadAddresses();
        loadMatrix({ silent: true });
      } catch (e){ toast("Gagal: " + e.message, true); }
    }));
}

function jumpToMatrixForAddress(address){
  if (!address) return;
  state.mxQuery = address;
  state.mxStatus = "all";
  if ($("mxSearch")) $("mxSearch").value = address;
  location.hash = "#/matrix";
  route();
  renderMatrix();
  toast("⚡ Menampilkan " + address + " di Account Matrix");
}

/* ---------- AccountMatrix (#/matrix) ---------- */
const _MX_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function mxB32Decode(str){
  const clean = String(str || "").toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = 0, val = 0;
  const out = [];
  for (const ch of clean) {
    const idx = _MX_B32.indexOf(ch);
    if (idx < 0) continue;
    val = (val << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((val >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}
async function clientTotpAt(secretB32, atMs = Date.now()){
  const bytes = mxB32Decode(secretB32);
  if (!bytes.length) return null;
  const counter = Math.floor(atMs / 1000 / 30);
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter % 0x100000000);
  const key = await crypto.subtle.importKey("raw", bytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, buf));
  const off = mac[mac.length - 1] & 0x0f;
  const code = ((mac[off] & 0x7f) << 24) | ((mac[off + 1] & 0xff) << 16) | ((mac[off + 2] & 0xff) << 8) | (mac[off + 3] & 0xff);
  return String(code % 1000000).padStart(6, "0");
}
async function tickMatrixTotp(){
  const wrap = $("matrixRows");
  if (!wrap) return;
  const nowMs = Date.now();
  const rem = 30 - (Math.floor(nowMs / 1000) % 30);
  const pills = wrap.querySelectorAll("[data-mx-secret]");
  for (const p of pills) {
    const sec = p.dataset.mxSecret;
    if (!sec) continue;
    try {
      const code = await clientTotpAt(sec, nowMs);
      if (code) {
        p.dataset.mxTotpCode = code;
        const fmt = code.slice(0, 3) + " " + code.slice(3);
        const cEl = p.querySelector(".code");
        const rEl = p.querySelector(".rem");
        if (cEl) cEl.textContent = fmt;
        if (rEl) rEl.textContent = rem + "s";
        p.classList.toggle("low", rem <= 6);
      }
    } catch {}
  }
}

async function loadMatrix(opts = {}){
  if (loadMatrix._busy) return;
  loadMatrix._busy = true;
  try {
    const j = await api("/api/matrix");
    const nextList = j.accounts || [];
    if (!state.mxSeenOtps) {
      state.mxSeenOtps = new Map();
      state.mxSeenReady = false;
    }
    const freshOtps = [];
    for (const acc of nextList) {
      const prevOtp = state.mxSeenOtps.get(acc.id) || null;
      if (state.mxSeenReady && acc.email_otp && acc.email_otp !== prevOtp) {
        freshOtps.push(acc);
      }
      state.mxSeenOtps.set(acc.id, acc.email_otp || null);
    }
    state.mxSeenReady = true;
    state.matrixList = nextList;
    if (!opts.silent && j.auto_synced && j.auto_synced > 0) {
      toast("⚡ Auto-Sync: " + j.auto_synced + " akun terdeteksi otomatis dari inbox");
    }
    if (freshOtps.length > 0) {
      const top = freshOtps[0];
      nsPlay();
      if (nsPrefs().autoOtp || state.view === "matrix") {
        try { await navigator.clipboard.writeText(top.email_otp); } catch {}
        toast("🔑 OTP Baru (" + top.service + ") disalin: " + top.email_otp);
      } else {
        toast("🔑 OTP Baru (" + top.service + "): " + top.email_otp);
      }
    }
  } catch {
    if (!state.matrixList) state.matrixList = [];
  } finally {
    loadMatrix._busy = false;
  }
  if ($("navMatrix")) $("navMatrix").textContent = String((state.matrixList || []).length);
  renderMatrix();
  if (state.view === "matrix") renderTitle();
}

async function syncMatrixNow(){
  const btn = $("mxSyncBtn");
  if (btn) btn.disabled = true;
  try {
    const j = await api("/api/matrix/sync", { method: "POST" });
    state.matrixList = j.accounts || [];
    if ($("navMatrix")) $("navMatrix").textContent = String(state.matrixList.length);
    renderMatrix();
    renderTitle();
    if (j.added > 0) {
      toast("⚡ " + j.added + " akun baru ditemukan otomatis dari inbox");
    } else {
      toast("Semua akun dari inbox sudah tersinkron (" + state.matrixList.length + " akun)");
    }
  } catch (e) {
    toast("Gagal sinkronisasi: " + e.message, true);
  } finally {
    if (btn) btn.disabled = false;
  }
}

function mxStatusBadge(a){
  const st = a.status || "active";
  let remTxt = "";
  if (a.expires_at) {
    const left = a.expires_at - Date.now();
    remTxt = left > 0 ? " · sisa " + fmtLeft(left) : " · expired";
  }
  let chip = `<span class="chip ok">🟢 Active${esc(remTxt)}</span>`;
  if (st === "trial") chip = `<span class="chip wait">🟡 Trial${esc(remTxt)}</span>`;
  else if (st === "cooldown") chip = `<span class="chip">🔵 Cooldown${esc(remTxt)}</span>`;
  else if (st === "burned") chip = `<span class="chip no">🔴 Burned</span>`;
  return `<button type="button" class="mx-st-btn" data-mx-cycle-st="${escAttr(a.id)}" title="Klik untuk mengganti status akun (Active → Trial → Cooldown → Burned)">${chip}</button>`;
}

function renderMatrixFilterPills(all){
  const bar = $("mxFilterPills");
  if (!bar) return;
  const cur = state.mxStatus || "all";
  const otpCnt = all.filter((a) => !!(a.email_otp || a.totp_code)).length;
  const actCnt = all.filter((a) => (a.status || "active") === "active").length;
  const triCnt = all.filter((a) => a.status === "trial").length;
  const cooCnt = all.filter((a) => a.status === "cooldown").length;
  const burCnt = all.filter((a) => a.status === "burned").length;
  const items = [
    ["all", `Semua (${all.length})`],
    ["otp", `🔑 Ada OTP (${otpCnt})`],
    ["active", `🟢 Active (${actCnt})`],
    ["trial", `🟡 Trial (${triCnt})`],
    ["cooldown", `🔵 Cooldown (${cooCnt})`],
    ["burned", `🔴 Burned (${burCnt})`],
  ];
  bar.innerHTML = items.map(([val, lbl]) =>
    `<button type="button" class="mx-fpill" data-mx-filter="${escAttr(val)}" aria-pressed="${cur === val}">${esc(lbl)}</button>`
  ).join("");
  bar.querySelectorAll("[data-mx-filter]").forEach((btn) =>
    btn.addEventListener("click", () => {
      state.mxStatus = btn.dataset.mxFilter;
      renderMatrix();
    }));
}

function renderMatrix(){
  const wrap = $("matrixRows");
  if (!wrap) return;
  const all = state.matrixList || [];
  renderMatrixFilterPills(all);
  const q = (state.mxQuery || "").trim().toLowerCase();
  const sf = state.mxStatus || "all";
  const rows = all.filter((a) => {
    if (sf === "otp" && !a.email_otp && !a.totp_code) return false;
    else if (sf !== "all" && sf !== "otp" && (a.status || "active") !== sf) return false;
    if (!q) return true;
    const hay = `${a.service || ""} ${a.tag || ""} ${a.address || ""} ${a.username || ""} ${a.opsec_note || ""}`.toLowerCase();
    return hay.includes(q);
  });
  if (!rows.length) {
    wrap.innerHTML = '<div class="empty-box" style="margin:12px">' +
      (q || sf !== "all" ? "Tidak ada akun yang cocok dengan filter." : "Belum ada akun di Account Matrix. Klik tombol 1-Klik Instan di atas untuk membuat identitas baru.") +
      "</div>";
    return;
  }
  wrap.innerHTML = rows.map((a) => {
    const totpFmt = a.totp_code ? (a.totp_code.slice(0, 3) + " " + a.totp_code.slice(3)) : "—";
    const totpCell = a.totp_secret
      ? `<button type="button" class="mx-totp-pill${(a.totp_rem && a.totp_rem <= 6) ? " low" : ""}" data-mx-secret="${escAttr(a.totp_secret)}" data-mx-totp-code="${escAttr(a.totp_code || "")}" title="Klik untuk menyalin kode 2FA TOTP">
           <span class="code">${esc(totpFmt)}</span>
           <span class="rem">${a.totp_rem || 30}s</span>
         </button>`
      : `<button type="button" class="mx-mini-btn" data-mx-edit="${escAttr(a.id)}" title="Tambah 2FA TOTP Secret">+ 2FA</button>`;

    let otpCellHtml = "";
    if (a.email_otp) {
      otpCellHtml += `<button type="button" class="mx-otp-pill" data-mx-copy-val="${escAttr(a.email_otp)}" data-mx-copy-lbl="Kode OTP Email" title="Klik untuk salin OTP dari: ${escAttr(a.latest_subject || "")}">🔑 ${esc(a.email_otp)}</button>`;
    }
    if (a.magic_link) {
      otpCellHtml += `<a class="mx-link-pill" href="${escAttr(a.magic_link)}" target="_blank" rel="noopener noreferrer" title="Buka link verifikasi dari: ${escAttr(a.latest_subject || "")}">🔗 Link</a>`;
    }
    if (!a.email_otp && !a.magic_link) {
      otpCellHtml += `<span class="hint" style="font-size:11.5px">${a.message_count ? (a.message_count + " email") : "Belum ada OTP"}</span>`;
    }
    otpCellHtml += `<button type="button" class="mx-pull-btn" data-mx-pull="${escAttr(a.id)}" title="Tarik OTP &amp; cek email terbaru dari menyurat.me">🔄</button>`;

    const pwBtnHtml = a.password
      ? `<button type="button" class="mx-mini-btn" data-mx-copy-val="${escAttr(a.password)}" data-mx-copy-lbl="Password" title="Klik untuk salin password">🔑 Sandi</button>`
      : `<button type="button" class="mx-mini-btn" data-mx-gen-pw="${escAttr(a.id)}" title="Generate &amp; salin password kuat 18-karakter dalam 1 klik">⚡ +Sandi</button>`;

    return `<div class="mx-row" data-mx-id="${escAttr(a.id)}">
      <div class="mx-svc">
        <div class="mx-svc-top">
          <span class="mx-svc-name">${esc(a.service)}</span>
          ${a.tag ? `<span class="chip note-chip">${esc(a.tag)}</span>` : ""}
        </div>
        <div>${mxStatusBadge(a)}</div>
        ${a.opsec_note ? `<div class="mx-opsec" title="${escAttr(a.opsec_note)}">🛡 ${esc(a.opsec_note)}</div>` : ""}
      </div>

      <div class="mx-id">
        <div class="mx-addr-line">
          <button type="button" class="mx-copy-addr" data-mx-copy-val="${escAttr(a.address)}" data-mx-copy-lbl="Email" title="Klik untuk salin email">${esc(a.address)}</button>
          <button type="button" class="mx-mini-btn" data-mx-open-inbox="${escAttr(a.address)}" title="Buka inbox email ini">↗ Inbox (${a.message_count || 0})</button>
        </div>
        <div class="mx-cred-line">
          ${a.username ? `<button type="button" class="mx-mini-btn" data-mx-copy-val="${escAttr(a.username)}" data-mx-copy-lbl="Username" title="Klik untuk salin username">👤 ${esc(a.username)}</button>` : ""}
          ${pwBtnHtml}
          ${a.api_key ? `<button type="button" class="mx-mini-btn" data-mx-copy-val="${escAttr(a.api_key)}" data-mx-copy-lbl="API Key" title="Klik untuk salin API Key / Token">⚡ API Key</button>` : ""}
        </div>
      </div>

      <div class="mx-totp-cell">${totpCell}</div>
      <div class="mx-otp-cell">${otpCellHtml}</div>

      <div class="acts">
        <details class="rowmenu">
          <summary class="btn btn-sm more-btn" title="Menu Akun" aria-label="Menu Akun">⋯</summary>
          <div class="menu-pop">
            <button type="button" class="menu-item" data-mx-edit="${escAttr(a.id)}">Detail &amp; Vault (Edit)</button>
            <button type="button" class="menu-item" data-mx-gen-pw="${escAttr(a.id)}">${a.password ? "Regenerate Password Baru" : "Generate Password 18-Char"}</button>
            <button type="button" class="menu-item" data-mx-pull="${escAttr(a.id)}">Tarik OTP Email Terbaru</button>
            <button type="button" class="menu-item" data-mx-open-inbox="${escAttr(a.address)}">Buka Inbox Email</button>
            <button type="button" class="menu-item danger" data-mx-del="${escAttr(a.id)}" data-mx-addr="${escAttr(a.address)}">Sembunyikan / Hapus dari Matrix</button>
          </div>
        </details>
      </div>
    </div>`;
  }).join("");

  wrap.querySelectorAll("[data-mx-copy-val]").forEach((b) =>
    b.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(b.dataset.mxCopyVal);
        toast((b.dataset.mxCopyLbl || "Teks") + " disalin");
      } catch { toast("Gagal menyalin", true); }
    }));

  wrap.querySelectorAll("[data-mx-secret]").forEach((b) =>
    b.addEventListener("click", async () => {
      const code = b.dataset.mxTotpCode || "";
      if (!code) return;
      try {
        await navigator.clipboard.writeText(code);
        toast("Kode 2FA TOTP disalin: " + code);
      } catch { toast("Gagal menyalin", true); }
    }));

  wrap.querySelectorAll("[data-mx-gen-pw]").forEach((b) =>
    b.addEventListener("click", () => genMatrixPasswordQuick(b.dataset.mxGenPw)));

  wrap.querySelectorAll("[data-mx-cycle-st]").forEach((b) =>
    b.addEventListener("click", () => cycleMatrixStatus(b.dataset.mxCycleSt)));

  wrap.querySelectorAll("[data-mx-open-inbox]").forEach((b) =>
    b.addEventListener("click", () => {
      const addr = b.dataset.mxOpenInbox;
      const item = (state.addressList || []).find((x) => x.address === addr) || {};
      state.address = addr;
      state.expires = item.expires_at || (Date.now() + 14 * 86400_000);
      state.pinned  = item.pinned !== undefined ? !!item.pinned : true;
      state.note    = item.note || null;
      state.messages = []; state.selected = null; state.read = new Set(); state.seen = null; state.seenReady = false;
      store.address = state.address; store.expires = state.expires; store.pinned = state.pinned;
      location.hash = "#/inbox";
      render(); loadInbox(); connectSSE();
    }));

  wrap.querySelectorAll("[data-mx-pull]").forEach((b) =>
    b.addEventListener("click", () => pullMatrixOtp(b.dataset.mxPull)));

  wrap.querySelectorAll("[data-mx-edit]").forEach((b) =>
    b.addEventListener("click", () => openMatrixEditDlg(b.dataset.mxEdit)));

  wrap.querySelectorAll("[data-mx-del]").forEach((b) =>
    b.addEventListener("click", async () => {
      if (!confirm("Hapus/sembunyikan akun " + b.dataset.mxAddr + " dari Account Matrix? (Akun tidak akan muncul lagi saat Auto-Sync)")) return;
      try {
        await api("/api/matrix/" + encodeURIComponent(b.dataset.mxDel), { method: "DELETE" });
        toast("Akun dihapus dari Matrix");
        loadMatrix();
      } catch (e) { toast("Gagal: " + e.message, true); }
    }));

  tickMatrixTotp();
}

async function genMatrixPasswordQuick(id){
  try {
    const j = await api("/api/matrix/" + encodeURIComponent(id), {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ password: "__GENERATE__" })
    });
    const acc = j.account;
    const idx = (state.matrixList || []).findIndex((x) => x.id === id);
    if (idx >= 0 && acc) {
      state.matrixList[idx] = acc;
      renderMatrix();
    }
    if (acc && acc.password) {
      try { await navigator.clipboard.writeText(acc.password); } catch {}
      toast("🔑 Password 18-char dibuat & disalin: " + acc.password);
    }
  } catch (e) {
    toast("Gagal membuat password: " + e.message, true);
  }
}

async function cycleMatrixStatus(id){
  const order = ["active", "trial", "cooldown", "burned"];
  const a = (state.matrixList || []).find((x) => x.id === id);
  if (!a) return;
  const next = order[(order.indexOf(a.status || "active") + 1) % order.length];
  try {
    const j = await api("/api/matrix/" + encodeURIComponent(id), {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ status: next })
    });
    if (j.account) {
      Object.assign(a, j.account);
      renderMatrix();
      toast("Status " + a.service + " → " + next.toUpperCase());
    }
  } catch (e) {
    toast("Gagal mengubah status: " + e.message, true);
  }
}

function exportMatrixVault(fmt){
  const rows = state.matrixList || [];
  if (!rows.length) { toast("Belum ada akun untuk diekspor", true); return; }
  const stamp = new Date().toISOString().slice(0, 10);
  if (fmt === "csv") {
    const escCsv = (v) => {
      let s = String(v ?? "");
      if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
      return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    };
    const header = ["name", "login_uri", "login_username", "login_password", "login_totp", "notes", "email", "tag", "status", "api_key", "recovery_codes"];
    const lines = [header.join(",")].concat(rows.map((a) => [
      a.service + (a.tag ? " (" + a.tag + ")" : ""),
      a.service,
      a.username || a.address,
      a.password || "",
      a.totp_secret || "",
      a.opsec_note || "",
      a.address || "",
      a.tag || "",
      a.status || "active",
      a.api_key || "",
      a.recovery_codes || ""
    ].map(escCsv).join(",")));
    const blob = new Blob(["\uFEFF" + lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `account-matrix-vault-${stamp}.csv`;
    document.body.appendChild(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast("Vault CSV berhasil diunduh (" + rows.length + " akun)");
    return;
  }
  const payload = {
    exported_at: new Date().toISOString(),
    total_accounts: rows.length,
    accounts: rows
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `account-matrix-vault-${stamp}.json`;
  document.body.appendChild(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast("Vault JSON berhasil diunduh (" + rows.length + " akun)");
}

async function spawnMatrixAccount(presetService, presetDays){
  const msg = $("mxSpawnMsg");
  if (msg) msg.hidden = true;
  const isPreset = typeof presetService === "string" && presetService.length > 0;
  const service = isPreset ? presetService : (($("mxService") && $("mxService").value || "").trim() || "Auto-Detect");
  const btn = $("mxSpawnBtn");
  if (btn) btn.disabled = true;
  try {
    const trialDays = (isPreset && presetDays !== undefined)
      ? Number(presetDays)
      : Number($("mxTrial") ? $("mxTrial").value : 0);
    const j = await api("/api/matrix", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        service,
        tag: ($("mxTag") && $("mxTag").value || "").trim(),
        domain: $("mxDomain") ? $("mxDomain").value : "",
        local: ($("mxLocal") && $("mxLocal").value || "").trim(),
        trial_days: trialDays > 0 ? trialDays : null,
        status: trialDays > 0 ? "trial" : "active",
        username: ($("mxUser") && $("mxUser").value || "").trim(),
        password: ($("mxPass") && $("mxPass").value || "").trim(),
        totp_secret: ($("mxTotp") && $("mxTotp").value || "").trim(),
        opsec_note: ($("mxOpsec") && $("mxOpsec").value || "").trim(),
        auto_pin: true
      })
    });
    const acc = j.account;
    for (const id of ["mxService", "mxTag", "mxLocal", "mxUser", "mxPass", "mxTotp", "mxOpsec"]) {
      if ($(id)) $(id).value = "";
    }
    try { await navigator.clipboard.writeText(acc.address); } catch {}
    // Set newly spawned address as active inbox in menyurat.me so live SSE immediately watches it
    state.address = acc.address;
    state.expires = Date.now() + 14 * 86400_000;
    state.pinned  = true;
    state.note    = acc.tag ? `${acc.service} (${acc.tag})` : acc.service;
    state.messages = []; state.selected = null; state.read = new Set(); state.seen = null; state.seenReady = false;
    store.address = state.address; store.expires = state.expires; store.pinned = state.pinned;
    render();
    connectSSE();
    toast("⚡ Spawn " + acc.service + " sukses! Email disalin: " + acc.address);
    await loadMatrix();
    loadAddresses();
  } catch (e) {
    if (msg) showMsg(msg, "Gagal spawn akun: " + (e.message || "error"), "err");
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function pullMatrixOtp(id){
  try {
    const j = await api("/api/matrix/" + encodeURIComponent(id) + "/otp");
    const idx = (state.matrixList || []).findIndex((x) => x.id === id);
    if (idx >= 0) {
      Object.assign(state.matrixList[idx], j);
      renderMatrix();
    }
    if (j.email_otp) {
      try { await navigator.clipboard.writeText(j.email_otp); } catch {}
      toast("🔑 OTP ditemukan & disalin: " + j.email_otp);
    } else if (j.magic_link) {
      toast("🔗 Link verifikasi ditemukan! Klik tombol Link di baris akun.");
    } else {
      toast("Belum ada kode OTP baru di inbox " + j.address);
    }
  } catch (e) {
    toast("Gagal menarik OTP: " + e.message, true);
  }
}

function clientGenStrongPass(len = 18){
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*_-+=";
  const rnd = new Uint32Array(len);
  crypto.getRandomValues(rnd);
  return Array.from(rnd, (v) => chars[v % chars.length]).join("");
}

function openMatrixEditDlg(id){
  const a = (state.matrixList || []).find((x) => x.id === id);
  const dlg = $("matrixEditDlg");
  if (!a || !dlg) return;
  dlg.dataset.mxId = a.id;
  $("mxeAddr").textContent = a.address;
  $("mxeService").value = a.service || "";
  $("mxeTag").value = a.tag || "";
  $("mxeUser").value = a.username || "";
  $("mxePass").value = a.password || "";
  $("mxeTotp").value = a.totp_secret || "";
  $("mxeApiKey").value = a.api_key || "";
  $("mxeRecovery").value = a.recovery_codes || "";
  $("mxeOpsec").value = a.opsec_note || "";
  $("mxeStatus").value = a.status || "active";
  if ($("mxeTrial")) $("mxeTrial").value = "keep";
  if ($("mxeMsg")) $("mxeMsg").hidden = true;
  dlg.showModal();
}

async function saveMatrixEdit(){
  const dlg = $("matrixEditDlg");
  if (!dlg || !dlg.dataset.mxId) return;
  const msg = $("mxeMsg");
  if (msg) msg.hidden = true;
  const payload = {
    service: $("mxeService").value,
    tag: $("mxeTag").value,
    username: $("mxeUser").value,
    password: $("mxePass").value,
    totp_secret: $("mxeTotp").value,
    api_key: $("mxeApiKey").value,
    recovery_codes: $("mxeRecovery").value,
    opsec_note: $("mxeOpsec").value,
    status: $("mxeStatus").value
  };
  const trVal = $("mxeTrial") ? $("mxeTrial").value : "keep";
  if (trVal !== "keep") {
    const td = Number(trVal);
    payload.trial_days = td > 0 ? td : 0;
    if (td > 0 && payload.status === "active") payload.status = "trial";
  }
  try {
    await api("/api/matrix/" + encodeURIComponent(dlg.dataset.mxId), {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload)
    });
    dlg.close();
    toast("Vault akun diperbarui");
    loadMatrix({ silent: true });
    loadAddresses();
  } catch (e) {
    if (msg) showMsg(msg, "Gagal menyimpan: " + e.message, "err");
  }
}

function openTtlDialog(address){
  const dlg = $("ttlDlg"); if (!dlg) return;
  const role = state.me ? state.me.role : "member";
  const fixed = role === "member" ? 604800 : 0;
  const maxDays = TTL_MAX_DAYS[role] || 365;
  $("ttlAddr").textContent = address;
  dlg.dataset.addr = address;
  $("ttlPickWrap").hidden = !!fixed;
  syncTtlOptions($("ttlPick"));
  $("ttlHint").textContent = fixed
    ? "Peran Anda: masa aktif diperpanjang ke " + (fixed / 86400) + " hari dari sekarang."
    : "Pilih durasi baru (maks " + maxDays + " hari). Berlaku dari sekarang, tidak pernah memperpendek sisa waktu.";
  if (!fixed) $("ttlPick").value = "1209600";
  dlg.showModal();
}

function openNoteDialog(address, currentNote){
  const dlg = $("noteDlg"); if (!dlg) return;
  $("noteAddr").textContent = address;
  dlg.dataset.addr = address;
  $("noteInput").value = currentNote || "";
  dlg.showModal();
  setTimeout(() => $("noteInput").focus(), 30);
}

async function openInboxLog(address){
  const dlg = $("logDlg"); if (!dlg) return;
  $("logAddr").textContent = address;
  $("logRows").innerHTML = '<div class="empty-box">Memuat.</div>';
  dlg.showModal();
  try {
    const j = await api("/api/admin/log?limit=300&address=" + encodeURIComponent(address));
    const rows = j.log || [];
    $("logRows").innerHTML = rows.length
      ? rows.map((r) => `<div class="aitem" style="grid-template-columns:minmax(0,1fr) auto">
          <span class="addr">${esc(r.peer || "-")}${r.peer_name ? ' <span class="ttl">· ' + esc(r.peer_name) + "</span>" : ""}
            <br><span class="ttl">${esc(r.subject || "(tanpa subjek)")}</span></span>
          <span class="chip">${new Date(r.first_at).toLocaleString("id-ID")}</span>
        </div>`).join("")
      : '<div class="empty-box">Belum ada email masuk.</div>';
  } catch (e) {
    $("logRows").innerHTML = '<div class="empty-box">Gagal memuat: ' + esc(e.message) + '</div>';
  }
}

async function openUserInbox(user){
  const dlg = $("userInboxDlg");
  if (!dlg) return;
  $("uiTitle").textContent = "Inbox " + (user.email || "");
  $("uiSub").innerHTML = roleBadge(user.role) + ' <span class="status">' + esc(user.status || "") + "</span>";
  $("uiRows").innerHTML = '<div class="empty-box">Memuat…</div>';
  dlg.showModal();

  const paint = (rows) => {
    if (!rows.length){
      $("uiRows").innerHTML = '<div class="empty-box">Tidak ada alamat aktif.</div>';
      return;
    }
    $("uiRows").innerHTML = rows.map((a) => {
      const left = a.expires_at - Date.now();
      return '<div class="drow" style="grid-template-columns:minmax(0,1fr) 90px 120px auto">'
        + '<span class="name">' + esc(a.address) + '</span>'
        + '<span class="status">' + a.messages + ' pesan</span>'
        + '<span class="def">' + (a.pinned ? "permanen" : (left > 0 ? fmtLeft(left) : "kedaluwarsa")) + '</span>'
        + '<span class="act" style="display:flex;gap:6px;justify-content:flex-end">'
        + '<button class="btn btn-sm" data-peek-box="' + escAttr(a.address) + '" data-exp="' + a.expires_at + '" data-pinned="' + (a.pinned ? 1 : 0) + '">Buka</button>'
        + '<button class="btn btn-sm" data-pdel="' + escAttr(a.address) + '">Hapus</button>'
        + '</span></div>';
    }).join("");

    $("uiRows").querySelectorAll("[data-peek-box]").forEach((b) =>
      b.addEventListener("click", () => {
        state.address = b.dataset.peekBox;
        state.expires = Number(b.dataset.exp) || 0;
        state.pinned = b.dataset.pinned === "1";
        state.messages = []; state.selected = null; state.read = new Set(); state.seen = null; state.seenReady = false;
        store.address = state.address; store.expires = state.expires; store.pinned = state.pinned; store.read = state.read;
        dlg.close();
        location.hash = "#/inbox";
        render(); loadInbox(); connectSSE();
      }));

    $("uiRows").querySelectorAll("[data-pdel]").forEach((b) =>
      b.addEventListener("click", async () => {
        if (!confirm("Hapus inbox " + b.dataset.pdel + "?")) return;
        try {
          await api("/api/inbox/" + encodeURIComponent(b.dataset.pdel), { method: "DELETE" });
          toast("Inbox dihapus");
          await pull();
        } catch (e){ toast("Gagal: " + e.message, true); }
      }));
  };

  const pull = async () => {
    try {
      const j = await api("/api/admin/users/" + encodeURIComponent(user.id) + "/inboxes");
      paint(j.inboxes || []);
    } catch (e){
      $("uiRows").innerHTML = '<div class="empty-box">Gagal memuat: ' + esc(e.message) + "</div>";
    }
  };
  pull();
}

/* ---------- kunci API ---------- */
async function loadKeys(){
  try { const j = await api("/api/keys"); state.keys = j.keys || []; }
  catch { state.keys = []; }
  renderKeys();
}

function renderKeys(){
  const wrap = $("keyList");
  if (!wrap) return;
  const rows = state.keys || [];
  if (!rows.length){ wrap.innerHTML = '<div class="empty-box" style="margin-top:4px">Belum ada kunci.</div>'; return; }
  wrap.innerHTML = rows.map((k) => {
    const active = !k.revoked_at;
    return `<div class="drow">
      <span class="name">${esc(k.prefix)}…</span>
      <span class="status">${esc(k.name || "kunci")}</span>
      <span class="def">${active ? (k.last_used ? "dipakai " + fmtDate(k.last_used) : "belum dipakai") : '<span class="chip no">dicabut</span>'}</span>
      <span class="act">${active
        ? `<button class="btn btn-sm" data-revoke="${escAttr(k.id)}">Cabut</button>`
        : `<button class="btn btn-sm btn-quiet" data-delkey="${escAttr(k.id)}" title="Hapus riwayat kunci">Hapus</button>`}</span>
    </div>`;
  }).join("");
  wrap.querySelectorAll("[data-revoke]").forEach((b) =>
    b.addEventListener("click", async () => {
      try { await api("/api/keys/" + encodeURIComponent(b.dataset.revoke), { method: "DELETE" }); toast("Kunci dicabut"); loadKeys(); }
      catch (e){ toast("Gagal: " + e.message, true); }
    }));
  wrap.querySelectorAll("[data-delkey]").forEach((b) =>
    b.addEventListener("click", async () => {
      try { await api("/api/keys/" + encodeURIComponent(b.dataset.delkey) + "?purge=1", { method: "DELETE" }); toast("Riwayat kunci dihapus"); loadKeys(); }
      catch (e){ toast("Gagal: " + e.message, true); }
    }));
}

async function createKey(){
  const msg = $("keyMsg"); msg.hidden = true;
  try {
    const j = await api("/api/keys", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: $("keyName").value })
    });
    showMsg(msg, "Kunci dibuat: " + j.key + " — salin sekarang, tidak ditampilkan lagi.", "ok");
    $("keyName").value = "";
    loadKeys();
  } catch (e){
    const map = { key_limit_reached: "Maksimal 5 kunci aktif. Cabut salah satu dulu." };
    showMsg(msg, map[e.code] || ("Gagal membuat kunci: " + e.message), "err");
  }
}

async function changePassword(){
  const msg = $("pwMsg"); msg.hidden = true;
  try {
    await api("/api/auth/password", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ current: $("pwCurrent").value, next: $("pwNext").value })
    });
    showMsg(msg, "Kata sandi diperbarui.", "ok");
    $("pwCurrent").value = ""; $("pwNext").value = "";
  } catch (e){
    const map = { invalid_credentials: "Sandi sekarang salah.", password_too_short: "Sandi baru minimal 8 karakter." };
    showMsg(msg, map[e.code] || ("Gagal: " + e.message), "err");
  }
}

/* ---------- notifikasi suara & desktop ---------- */
const NS_KEY = "menyurat.notify";
const NS_DEFAULT = { enabled: false, sound: "ding", custom: null, customName: "", customSize: 0, hasCustomIdb: false, desktop: false, autoOtp: false };
let nsCustomDataUrl = null;
let nsCustomBuffer = null;
let nsCustomBufferSrc = null;

function nsPrefs(){
  try { return Object.assign({}, NS_DEFAULT, JSON.parse(localStorage.getItem(NS_KEY) || "{}")); }
  catch { return Object.assign({}, NS_DEFAULT); }
}
function nsSave(p){
  try {
    localStorage.setItem(NS_KEY, JSON.stringify(p));
  } catch {
    // Jika dataURL terlalu besar untuk localStorage, simpan metadata saja di localStorage
    const slim = Object.assign({}, p, { custom: null });
    localStorage.setItem(NS_KEY, JSON.stringify(slim));
  }
}

/* IndexedDB untuk menyimpan file audio kustom hingga 6 MB tanpa terbentur limit localStorage */
function nsIdbOpen(){
  return new Promise((resolve, reject) => {
    if (!("indexedDB" in window)) return reject(new Error("no_idb"));
    const req = indexedDB.open("menyurat_media", 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains("audio")) db.createObjectStore("audio");
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error("idb_open_failed"));
  });
}
async function nsIdbPut(dataUrl){
  try {
    const db = await nsIdbOpen();
    return await new Promise((resolve, reject) => {
      const tx = db.transaction("audio", "readwrite");
      tx.objectStore("audio").put(dataUrl, "custom_sound");
      tx.oncomplete = () => { db.close(); resolve(true); };
      tx.onerror = () => { db.close(); reject(tx.error); };
    });
  } catch { return false; }
}
async function nsIdbGet(){
  try {
    const db = await nsIdbOpen();
    return await new Promise((resolve) => {
      const tx = db.transaction("audio", "readonly");
      const req = tx.objectStore("audio").get("custom_sound");
      req.onsuccess = () => { db.close(); resolve(req.result || null); };
      req.onerror = () => { db.close(); resolve(null); };
    });
  } catch { return null; }
}
async function nsIdbDel(){
  try {
    const db = await nsIdbOpen();
    await new Promise((resolve) => {
      const tx = db.transaction("audio", "readwrite");
      tx.objectStore("audio").delete("custom_sound");
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); resolve(); };
    });
  } catch {}
}

function dataUrlToArrayBuffer(dataUrl){
  const idx = String(dataUrl || "").indexOf(",");
  if (idx < 0) return null;
  const b64 = dataUrl.slice(idx + 1);
  const bin = atob(b64);
  const len = bin.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

async function nsEnsureCustomLoaded(){
  const p = nsPrefs();
  if (!nsCustomDataUrl) {
    if (p.custom) nsCustomDataUrl = p.custom;
    else if (p.hasCustomIdb) nsCustomDataUrl = await nsIdbGet();
  }
  if (!nsCustomDataUrl) return null;
  const ctx = nsAudioCtx();
  if (ctx && (!nsCustomBuffer || nsCustomBufferSrc !== nsCustomDataUrl)) {
    try {
      const ab = dataUrlToArrayBuffer(nsCustomDataUrl);
      if (ab) {
        nsCustomBuffer = await ctx.decodeAudioData(ab.slice(0));
        nsCustomBufferSrc = nsCustomDataUrl;
      }
    } catch {}
  }
  return nsCustomDataUrl;
}

function fireDesktopNotify(msg, isTest){
  if (!("Notification" in window)) return;
  const p = nsPrefs();
  if (!isTest && !p.desktop) return;
  if (Notification.permission !== "granted") return;
  try {
    const who = (msg && (msg.from_name || msg.from_addr)) || "Pengirim";
    const subj = (msg && msg.subject) || "(tanpa subjek)";
    const otp = msg ? extractOtp(msg.subject, msg.snippet || "", "") : null;
    const title = otp ? ("OTP: " + otp + " · " + who) : ("Email baru · " + who);
    const body = subj + (state.address ? " (" + state.address + ")" : "");
    const n = new Notification(title, {
      body,
      icon: "/icon.svg",
      tag: msg && msg.id ? ("menyurat-" + msg.id) : "menyurat-test"
    });
    n.onclick = () => {
      try { window.focus(); } catch {}
      if (msg && msg.id) {
        location.hash = "#/inbox";
        openMessage(msg.id);
      }
      n.close();
    };
  } catch {}
}

let nsCtx = null;
function nsAudioCtx(){
  if (!nsCtx) { const C = window.AudioContext || window.webkitAudioContext; if (!C) return null; nsCtx = new C(); }
  if (nsCtx.state === "suspended") nsCtx.resume().catch(() => {});
  return nsCtx;
}

const NS_TONES = {
  ding:  [{ f: 880,  d: 0.16, t: 0 }, { f: 1320, d: 0.22, t: 0.08 }],
  chime: [{ f: 660,  d: 0.2,  t: 0 }, { f: 990,  d: 0.2,  t: 0.12 }, { f: 1320, d: 0.26, t: 0.24 }],
  pop:   [{ f: 420,  d: 0.12, t: 0 }, { f: 620,  d: 0.14, t: 0.06 }],
  bell:  [{ f: 1046, d: 0.5,  t: 0 }, { f: 1568, d: 0.4,  t: 0 }]
};

function nsPlayTone(name){
  const ctx = nsAudioCtx();
  if (!ctx) return;
  const notes = NS_TONES[name] || NS_TONES.ding;

  const go = () => {
    const now = ctx.currentTime;
    for (const n of notes) {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = name === "pop" ? "triangle" : "sine";
      osc.frequency.value = n.f;
      gain.gain.setValueAtTime(0.0001, now + n.t);
      gain.gain.exponentialRampToValueAtTime(0.18, now + n.t + 0.015);
      gain.gain.exponentialRampToValueAtTime(0.0001, now + n.t + n.d);
      osc.connect(gain).connect(ctx.destination);
      osc.start(now + n.t);
      osc.stop(now + n.t + n.d + 0.02);
    }
  };

  // context suspended = waktu beku; resume dulu baru jadwalkan nada
  if (ctx.state === "running") go();
  else ctx.resume().then(go).catch(() => {});
}

async function nsPlay(force){
  const p = nsPrefs();
  if (!p.enabled && !force) return;
  if (p.sound === "custom" && (p.custom || p.hasCustomIdb || nsCustomDataUrl)) {
    const dataUrl = await nsEnsureCustomLoaded();
    if (dataUrl) {
      const ctx = nsAudioCtx();
      // Prioritaskan Web Audio API (AudioBufferSourceNode) agar tetap bunyi di background/SSE
      if (ctx && nsCustomBuffer) {
        const playBuf = () => {
          try {
            const src = ctx.createBufferSource();
            const gain = ctx.createGain();
            src.buffer = nsCustomBuffer;
            gain.gain.value = 0.9;
            src.connect(gain).connect(ctx.destination);
            src.start(0);
          } catch {}
        };
        if (ctx.state === "running") playBuf();
        else ctx.resume().then(playBuf).catch(() => {});
        return;
      }
      // Fallback ke HTML5 Audio jika codec hanya didukung elemen <audio>
      try {
        const a = new Audio(dataUrl);
        a.volume = 0.9;
        const pr = a.play();
        if (pr && pr.catch) pr.catch(() => nsPlayTone("ding"));
        return;
      } catch {}
    }
  }
  nsPlayTone(p.sound === "custom" ? "ding" : p.sound);
}

/* AudioContext ditahan browser sampai ada gesture. Buka sekali di interaksi pertama. */
let nsUnlocked = false;
function nsUnlock(){
  if (nsUnlocked) return;
  nsUnlocked = true;
  const ctx = nsAudioCtx();
  if (!ctx) return;
  const prime = () => {
    try {
      const b = ctx.createBuffer(1, 1, 22050);
      const s = ctx.createBufferSource();
      s.buffer = b; s.connect(ctx.destination); s.start(0);
    } catch {}
    nsEnsureCustomLoaded().catch(() => {});
  };
  if (ctx.state === "suspended") ctx.resume().then(prime).catch(() => {}); else prime();
}

function nsRender(){
  const p = nsPrefs();
  if (!$("nsEnabled")) return;
  $("nsEnabled").checked = !!p.enabled;
  $("nsSound").value = p.sound || "ding";
  if ($("nsDesktop")) {
    $("nsDesktop").checked = !!(p.desktop && "Notification" in window && Notification.permission === "granted");
  }
  if ($("nsAutoOtp")) {
    $("nsAutoOtp").checked = !!p.autoOtp;
  }
  const info = $("nsCustomInfo");
  if (info) {
    const hasCustom = !!(p.custom || p.hasCustomIdb || nsCustomDataUrl);
    if (hasCustom) {
      info.hidden = false;
      const meta = p.customName
        ? ("Audio kustom aktif: " + p.customName + (p.customSize ? " (" + Math.round(p.customSize / 1024) + " KB)" : ""))
        : "Audio kustom tersimpan di browser ini.";
      info.textContent = meta;
    } else {
      info.hidden = true;
      info.textContent = "";
    }
  }
}

function nsMsg(text, bad){
  const el = $("nsMsg"); if (!el) return;
  if (!text) { el.hidden = true; el.textContent = ""; return; }
  el.className = "auth-msg " + (bad ? "err" : "ok");
  el.textContent = text; el.hidden = false;
}

function nsInit(){
  if (!$("nsEnabled")) return;
  nsRender();
  if (nsInit._done) return;
  nsInit._done = true;

  // buka audio context pada gesture pertama (aturan autoplay browser)

  $("nsEnabled").addEventListener("change", (e) => {
    const p = nsPrefs(); p.enabled = e.target.checked; nsSave(p);
    if (p.enabled) nsPlay(true);
  });

  if ($("nsDesktop")) {
    $("nsDesktop").addEventListener("change", async (e) => {
      const p = nsPrefs();
      if (!("Notification" in window)) {
        e.target.checked = false;
        nsMsg("Browser ini tidak mendukung notifikasi desktop.", true);
        return;
      }
      if (e.target.checked) {
        let perm = Notification.permission;
        if (perm === "default") {
          try { perm = await Notification.requestPermission(); } catch {}
        }
        if (perm !== "granted") {
          e.target.checked = false;
          p.desktop = false; nsSave(p);
          nsMsg("Izin notifikasi ditolak di pengaturan browser.", true);
          return;
        }
        p.desktop = true; nsSave(p);
        nsMsg("Notifikasi pop-up desktop aktif.", false);
        fireDesktopNotify({ from_name: "menyurat", subject: "Kode verifikasi Anda adalah 482910" }, true);
      } else {
        p.desktop = false; nsSave(p);
        nsMsg("Notifikasi pop-up desktop dinonaktifkan.", false);
      }
    });
  }

  if ($("nsAutoOtp")) {
    $("nsAutoOtp").addEventListener("change", (e) => {
      const p = nsPrefs();
      p.autoOtp = e.target.checked;
      nsSave(p);
      nsMsg(p.autoOtp ? "Auto-salin OTP ke clipboard aktif." : "Auto-salin OTP dinonaktifkan.", false);
    });
  }

  on("nsDeskTest", "click", async () => {
    if (!("Notification" in window)) { nsMsg("Browser ini tidak mendukung notifikasi desktop.", true); return; }
    let perm = Notification.permission;
    if (perm === "default") {
      try { perm = await Notification.requestPermission(); } catch {}
    }
    if (perm !== "granted") { nsMsg("Izinkan notifikasi browser terlebih dahulu.", true); return; }
    const p = nsPrefs(); p.desktop = true; nsSave(p); nsRender();
    fireDesktopNotify({ from_name: "menyurat", subject: "Kode OTP percobaan: 839201" }, true);
  });

  $("nsSound").addEventListener("change", (e) => {
    const p = nsPrefs();
    p.sound = e.target.value;
    p.enabled = true;                       // pilih suara = niat mengaktifkan
    const hasCustom = !!(p.custom || p.hasCustomIdb || nsCustomDataUrl);
    if (p.sound === "custom" && !hasCustom) {
      nsMsg("Belum ada audio kustom. Klik 'Upload audio' untuk memilih file.", true);
      if ($("nsFile")) $("nsFile").click();
    } else {
      nsMsg("", false);
    }
    nsSave(p); nsRender(); nsPlay(true);
  });

  on("nsTest", "click", () => nsPlay(true));
  on("nsUploadBtn", "click", () => { if ($("nsFile")) $("nsFile").click(); });

  $("nsFile").addEventListener("change", (e) => {
    const f = e.target.files && e.target.files[0];
    if (!f) return;
    if (!/^audio\//i.test(f.type) && !/\.(mp3|ogg|wav|m4a|aac|opus|flac|webm|mp4)$/i.test(f.name)) {
      nsMsg("Format file tidak didukung. Gunakan MP3, WAV, OGG, M4A, atau AAC.", true);
      e.target.value = "";
      return;
    }
    if (f.size > 6 * 1024 * 1024) {
      nsMsg("Ukuran file terlalu besar (maksimal 6 MB).", true);
      e.target.value = "";
      return;
    }
    nsMsg("Memproses file audio…", false);
    const fr = new FileReader();
    fr.onload = async () => {
      const dataUrl = String(fr.result || "");
      nsCustomDataUrl = dataUrl;
      nsCustomBuffer = null;
      nsCustomBufferSrc = null;
      const savedIdb = await nsIdbPut(dataUrl);
      const p = nsPrefs();
      p.sound = "custom";
      p.enabled = true;
      p.customName = f.name.slice(0, 60);
      p.customSize = f.size;
      p.hasCustomIdb = savedIdb;
      // Simpan di localStorage hanya jika kecil (< 512 KB) sebagai cadangan, sisanya di IndexedDB
      p.custom = (!savedIdb || f.size <= 512 * 1024) ? dataUrl : null;
      try {
        nsSave(p);
      } catch {
        if (!savedIdb) {
          nsMsg("Gagal menyimpan (penyimpanan browser penuh). Coba file audio yang lebih pendek.", true);
          return;
        }
      }
      await nsEnsureCustomLoaded();
      nsRender();
      nsMsg("Audio kustom \"" + p.customName + "\" tersimpan (" + Math.round(f.size / 1024) + " KB).", false);
      toast("Suara notifikasi kustom aktif: " + p.customName);
      nsPlay(true);
    };
    fr.onerror = () => nsMsg("Gagal membaca file audio.", true);
    fr.readAsDataURL(f);
    e.target.value = "";
  });

  on("nsReset", "click", async () => {
    const p = nsPrefs();
    p.custom = null; p.customName = ""; p.customSize = 0; p.hasCustomIdb = false;
    if (p.sound === "custom") p.sound = "ding";
    nsCustomDataUrl = null; nsCustomBuffer = null; nsCustomBufferSrc = null;
    await nsIdbDel();
    nsSave(p); nsRender(); nsMsg("Audio kustom dihapus.", false);
  });
}
/* ---------- 2FA (opsional) ---------- */
async function loadTOTP(){
  try { state.totp = await api("/api/auth/2fa"); }
  catch { state.totp = { enabled: false, recovery_left: 0 }; }
  renderTOTP();
}

function renderTOTP(){
  const t = state.totp || { enabled: false, recovery_left: 0 };
  if (!$("totpChip")) return;
  $("totpChip").textContent = t.enabled ? "aktif" : "nonaktif";
  $("totpChip").className = "chip " + (t.enabled ? "ok" : "");
  $("totpOff").hidden = !!t.enabled;
  $("totpOn").hidden = !t.enabled;
  if (t.enabled) $("totpLeft").textContent = String(t.recovery_left || 0);
}

async function totpStart(){
  const msg = $("totpMsg"); msg.hidden = true;
  try {
    const j = await api("/api/auth/2fa/setup", { method: "POST" });
    $("totpSecret").textContent = j.secret;
    $("totpSecret").onclick = async () => {
      try { await navigator.clipboard.writeText(j.secret); toast("Secret 2FA disalin"); }
      catch { toast("Secret: " + j.secret); }
    };
    const qrWrap = $("totpQrWrap"), qrImg = $("totpQrImg");
    if (qrWrap && qrImg && j.otpauth && typeof qrcode === "function") {
      try {
        const qr = qrcode(0, "M");
        qr.addData(j.otpauth);
        qr.make();
        qrImg.src = qr.createDataURL(5, 2);
        qrWrap.hidden = false;
      } catch {
        qrWrap.hidden = true;
      }
    }
    $("totpSetup").hidden = false;
    $("totpOff").hidden = true;
    $("totpCodes").hidden = true;
    $("totpCode").value = "";
    $("totpCode").focus();
  } catch (e){
    showMsg(msg, "Gagal menyiapkan 2FA: " + e.message, "err");
  }
}

async function totpEnable(){
  const msg = $("totpMsg"); msg.hidden = true;
  try {
    const j = await api("/api/auth/2fa/enable", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: $("totpCode").value })
    });
    $("totpCodesList").textContent = (j.recovery_codes || []).join("\n");
    $("totpCodes").hidden = false;
    $("totpSetup").hidden = true;
    toast("2FA aktif. Simpan kode cadangan.");
    await loadTOTP();
  } catch (e){
    const map = { invalid_code: "Kode salah, coba lagi.", setup_required: "Mulai ulang proses aktivasi." };
    showMsg(msg, map[e.code] || ("Gagal: " + e.message), "err");
  }
}

async function totpDisable(){
  const msg = $("totpMsg2"); msg.hidden = true;
  try {
    await api("/api/auth/2fa/disable", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ password: $("totpPass").value })
    });
    $("totpPass").value = "";
    $("totpCodes").hidden = true;
    $("totpSetup").hidden = true;
    toast("2FA dinonaktifkan");
    await loadTOTP();
  } catch (e){
    const map = { invalid_credentials: "Sandi salah." };
    showMsg(msg, map[e.code] || ("Gagal: " + e.message), "err");
  }
}

/* ---------- kelola domain ---------- */
async function loadAdminDomains(){
  if (!isStaff()) return;
  try { const j = await api("/api/admin/domains"); state.adminDomains = j.domains || []; }
  catch { state.adminDomains = []; }
  $("domainForm").hidden = !isStaff();
  $("domainAdmin").hidden = !isStaff();
  renderAdminDomains();
}

function renderAdminDomains(){
  const wrap = $("adminDomainRows");
  if (!wrap) return;
  const rows = state.adminDomains || [];
  if (!rows.length){ wrap.innerHTML = '<div class="empty-box" style="margin-top:4px">Belum ada domain.</div>'; return; }
  wrap.innerHTML = rows.map((d) => `<div class="arow">
      <span class="name">@${esc(d.domain)}</span>
      <span class="chips">
        <span class="chip ${d.is_active ? "ok" : "no"}">${d.is_active ? "aktif" : "nonaktif"}</span>
        ${d.is_default ? '<span class="chip">default</span>' : ""}
        ${d.is_premium ? '<span class="chip wait">premium</span>' : ""}
      </span>
      <span class="acts">
        <details class="rowmenu">
          <summary class="btn btn-sm">Kelola</summary>
          <div class="menu-pop">
            ${d.is_active && !d.is_default ? `<button class="menu-item" data-default="${escAttr(d.domain)}">Jadikan default</button>` : ""}
            <button class="menu-item" data-premium="${escAttr(d.domain)}" data-prem="${d.is_premium ? 1 : 0}">${d.is_premium ? "Jadikan standar" : "Jadikan premium"}</button>
            <button class="menu-item${d.is_active ? " danger" : ""}" data-toggle="${escAttr(d.domain)}" data-active="${d.is_active ? 1 : 0}">${d.is_active ? "Nonaktifkan" : "Aktifkan"}</button>
          </div>
        </details>
      </span>
    </div>`).join("");

  wrap.querySelectorAll("[data-premium]").forEach((b) =>
    b.addEventListener("click", async () => {
      try {
        await api("/api/admin/domains/" + encodeURIComponent(b.dataset.premium), {
          method: "PATCH", headers: { "content-type": "application/json" },
          body: JSON.stringify({ is_premium: b.dataset.prem !== "1" })
        });
        await loadDomains(); await loadAdminDomains();
      } catch (e){ toast("Gagal: " + e.message, true); }
    }));
  wrap.querySelectorAll("[data-toggle]").forEach((b) =>
    b.addEventListener("click", async () => {
      try {
        await api("/api/admin/domains/" + encodeURIComponent(b.dataset.toggle), {
          method: "PATCH", headers: { "content-type": "application/json" },
          body: JSON.stringify({ is_active: b.dataset.active !== "1" })
        });
        await loadDomains(); await loadAdminDomains();
      } catch (e){ toast("Gagal: " + e.message, true); }
    }));
  wrap.querySelectorAll("[data-default]").forEach((b) =>
    b.addEventListener("click", async () => {
      try {
        await api("/api/admin/domains/" + encodeURIComponent(b.dataset.default), {
          method: "PATCH", headers: { "content-type": "application/json" },
          body: JSON.stringify({ is_default: true })
        });
        await loadDomains(); await loadAdminDomains();
      } catch (e){ toast("Gagal: " + e.message, true); }
    }));
}

async function addDomain(){
  const msg = $("ndMsg"); msg.hidden = true;
  try {
    await api("/api/admin/domains", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ domain: $("ndDomain").value, label: $("ndLabel").value })
    });
    showMsg(msg, "Domain ditambahkan.", "ok");
    $("ndDomain").value = ""; $("ndLabel").value = "";
    await loadDomains(); await loadAdminDomains();
  } catch (e){
    const map = { invalid_domain: "Format domain tidak valid." };
    showMsg(msg, map[e.code] || ("Gagal: " + e.message), "err");
  }
}

/* ---------- audit ---------- */
async function loadAudit(){
  if (!isStaff()) return;
  try { const j = await api("/api/admin/audit?limit=200"); state.audit = j.entries || []; }
  catch { state.audit = []; }
  renderAudit();
}

function renderAudit(){
  const wrap = $("auditRows");
  if (!wrap) return;
  const rows = state.audit || [];
  if (!rows.length){ wrap.innerHTML = '<div class="empty-box" style="margin-top:12px">Belum ada aktivitas.</div>'; return; }
  wrap.innerHTML = rows.map((e) => `<div class="drow" style="grid-template-columns:170px minmax(0,1fr) 140px auto">
      <span class="status">${esc(e.action)}</span>
      <span class="name">${esc(e.actor_email || "sistem")}${e.target ? " -> " + esc(e.target) : ""}</span>
      <span class="status">${esc(e.ip || "")}</span>
      <span class="def">${fmtDate(e.created_at)}</span>
    </div>`).join("");
}

/* ---------- realtime ---------- */
let evtSource = null;
let sseReconnectTimer = null;
let allEvtSource = null;
let allSseReconnectTimer = null;

function setSseLive(isLive){
  const badge = $("sseLiveBadge"), txt = $("sseLiveText");
  if (!badge) return;
  badge.dataset.live = isLive ? "true" : "false";
  if (txt) txt.textContent = isLive ? "Live" : "Idle";
}

function setAllSseLive(isLive){
  const badge = $("allSseLiveBadge"), txt = $("allSseLiveText");
  if (!badge) return;
  badge.dataset.live = isLive ? "true" : "false";
  if (txt) txt.textContent = isLive ? "Live" : "Idle";
}

function disconnectAllSSE(){
  clearTimeout(allSseReconnectTimer);
  if (allEvtSource) { try { allEvtSource.close(); } catch {} allEvtSource = null; }
  setAllSseLive(false);
}

function connectAllSSE(){
  disconnectAllSSE();
  if (!state.me || state.view !== "all") return;
  if (!("EventSource" in window)) return;
  try {
    const es = new EventSource("/api/events?address=__all__");
    allEvtSource = es;
    es.onopen = () => setAllSseLive(true);
    es.onmessage = (ev) => {
      try {
        const d = JSON.parse(ev.data);
        if (d.type === "open" || d.type === "ping") setAllSseLive(true);
        if (d.type === "state") {
          setAllSseLive(true);
          const curLatestId = state.allMessages[0] ? state.allMessages[0].id : null;
          const nextLatestId = d.latest ? d.latest.id : null;
          if (d.count !== state.allMessages.length || nextLatestId !== curLatestId) {
            loadAllInbox({ silent: true });
            loadAddresses();
            loadMatrix({ silent: true });
            if (state.address && d.latest && d.latest.inbox === state.address) loadInbox();
          }
        }
      } catch {}
    };
    es.onerror = () => {
      try { es.close(); } catch {}
      if (allEvtSource === es) allEvtSource = null;
      if (state.me && state.view === "all" && !document.hidden) {
        allSseReconnectTimer = setTimeout(connectAllSSE, 1500);
      } else {
        setAllSseLive(false);
      }
    };
  } catch {
    setAllSseLive(false);
  }
}

function connectSSE(){
  clearTimeout(sseReconnectTimer);
  if (evtSource) { try { evtSource.close(); } catch {} evtSource = null; }
  if (!state.address || !state.me) { setSseLive(false); return; }
  if (!("EventSource" in window)) { setSseLive(false); return; }
  try {
    const es = new EventSource("/api/events?address=" + encodeURIComponent(state.address));
    evtSource = es;
    es.onopen = () => setSseLive(true);
    es.onmessage = (ev) => {
      try {
        const d = JSON.parse(ev.data);
        if (d.type === "open" || d.type === "ping") setSseLive(true);
        if (d.type === "state") {
          setSseLive(true);
          const curLatestId = state.messages[0] ? state.messages[0].id : null;
          const nextLatestId = d.latest ? d.latest.id : null;
          if (d.count !== state.messages.length || nextLatestId !== curLatestId) {
            loadInbox();
            loadAllInbox({ silent: true });
            loadAddresses();
            loadMatrix({ silent: true });
          }
        }
      } catch {}
    };
    es.onerror = () => {
      try { es.close(); } catch {}
      if (evtSource === es) evtSource = null;
      // Worker menutup stream setiap ~18 detik; sambung ulang otomatis jika inbox masih aktif
      if (state.address && state.me && !document.hidden) {
        sseReconnectTimer = setTimeout(connectSSE, 1500);
      } else {
        setSseLive(false);
      }
    };
  } catch {
    setSseLive(false);
  }
}

document.addEventListener("visibilitychange", () => {
  if (!document.hidden && state.me) {
    if (state.address) {
      loadInbox();
      if (!evtSource) connectSSE();
    }
    if (state.view === "all") {
      loadAllInbox({ silent: true });
      if (!allEvtSource) connectAllSSE();
    }
    if (state.view === "matrix") {
      loadMatrix({ silent: true });
    }
  }
});
window.addEventListener("hashchange", route);

async function copyAddress(){
  if (!state.address) return;
  try { await navigator.clipboard.writeText(state.address); toast("Alamat disalin"); }
  catch { toast("Gagal menyalin, salin manual: " + state.address, true); }
}

function openNav(){
  const src = document.querySelector(".sidebar nav");
  if (!src) return;
  // Hapus atribut id agar tidak membuat duplikat ID DOM dengan sidebar desktop
  $("navSheetBody").innerHTML = src.innerHTML.replace(/\sid="[^"]*"/g, "");
  $("navSheetBody").querySelectorAll("a[href]").forEach((a) => {
    a.addEventListener("click", () => closeNav());
  });
  $("navSheet").dataset.open = "true";
}
function closeNav(){ if ($("navSheet")) $("navSheet").dataset.open = "false"; }

function bindAppShellEvents(){
  if (bindAppShellEvents._bound) return;
  bindAppShellEvents._bound = true;

  on("acctLogout", "click", async () => {
    try { await api("/api/auth/logout", { method: "POST" }); } catch {}
    state.me = null; state.address = ""; state.pinned = false; state.messages = []; state.selected = null;
    state.allMessages = []; state.allSelected = null; state.allSelectedAddr = ""; state.allSeen = null; state.allSeenReady = false;
    state.matrixList = []; state.addressList = []; state.mxSeenOtps = null; state.mxSeenReady = false;
    if ($("navMatrix")) $("navMatrix").textContent = "0";
    if ($("navAllCount")) $("navAllCount").textContent = "0";
    if ($("navAddr")) $("navAddr").textContent = "0";
    store.address = ""; store.expires = 0; store.pinned = false;
    if (evtSource) { try { evtSource.close(); } catch {} evtSource = null; }
    disconnectAllSSE();
    if ($("appShell")) $("appShell").hidden = true;
    $("authScreen").hidden = false;
    authTab("login");
  });

  on("dlgLocal", "input", dlgPreviewText);
  on("dlgDomain", "change", dlgPreviewText);
  on("dlgCancel", "click", () => $("newAddrDlg").close());
  on("uiClose", "click", () => $("userInboxDlg").close());
  on("newAddrForm", "submit", (e) => {
    e.preventDefault();
    const local = $("dlgLocal").value.trim();
    const domain = dlgDomainValue();
    const note = $("dlgNote") ? $("dlgNote").value.trim() : "";
    $("newAddrDlg").close();
    createInbox(local, domain, $("dlgTtl") ? $("dlgTtl").value : null, note);
  });
  on("totpStart", "click", totpStart);
  on("totpEnable", "click", totpEnable);
  on("totpDisable", "click", totpDisable);

  on("newTop", "click", openNewDialog);
  on("logClose", "click", () => { const d = $("logDlg"); if (d) d.close(); });
  on("ttlCancel", "click", () => { const d = $("ttlDlg"); if (d) d.close(); });
  on("ttlApply", "click", async () => {
    const d = $("ttlDlg"); if (!d) return;
    const address = d.dataset.addr;
    const role = state.me ? state.me.role : "member";
    const body = role === "member" ? { days: 0 } : { ttl: Number($("ttlPick").value) };
    try {
      const j = await api("/api/inbox/" + encodeURIComponent(address), {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body)
      });
      d.close();
      toast("Masa aktif diperpanjang: sisa " + fmtLeft(j.expires_at - Date.now()));
      if (state.address === address) { state.expires = j.expires_at; store.expires = j.expires_at; render(); }
      loadAddresses();
    } catch (e){ toast("Gagal: " + e.message, true); }
  });
  on("acctTheme", "click", () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    setTheme(next);
    toast(next === "dark" ? "Mode gelap aktif" : "Mode terang aktif");
  });
  on("themeToggle", "change", (e) => setTheme(e.target.checked ? "dark" : "light"));
  on("qrBtn", "click", () => { if (state.address) openQr(state.address); });
  on("noteBtn", "click", () => { if (state.address) openNoteDialog(state.address, state.note || ""); });
  on("openMatrixBtn", "click", () => { if (state.address) jumpToMatrixForAddress(state.address); });
  on("noteCancel", "click", () => { const d = $("noteDlg"); if (d) d.close(); });
  on("noteSave", "click", async () => {
    const d = $("noteDlg"); if (!d) return;
    const address = d.dataset.addr; if (!address) return;
    const note = ($("noteInput") && $("noteInput").value || "").trim();
    try {
      const j = await api("/api/inbox/" + encodeURIComponent(address), {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ note })
      });
      d.close();
      if (state.address === address) {
        state.note = j.note || null;
        if ($("addrNoteChip")) {
          $("addrNoteChip").textContent = state.note || "";
          $("addrNoteChip").hidden = !state.note;
        }
      }
      toast(j.note ? "Label disimpan" : "Label dihapus");
      loadAddresses();
      loadMatrix({ silent: true });
    } catch (e) { toast("Gagal menyimpan label: " + e.message, true); }
  });
  on("noteInput", "keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); $("noteSave").click(); } });
  on("exportBtn", "click", () => { if (state.address) openExport(state.address); });
  on("qrTop", "click", () => { if (state.address) openQr(state.address); });
  on("exportTop", "click", () => { if (state.address) openExport(state.address); });
  on("qrClose", "click", () => { const d = $("qrDlg"); if (d) d.close(); });
  on("expClose", "click", () => { const d = $("exportDlg"); if (d) d.close(); });
  on("expJson", "click", () => doExport("json"));
  on("expCsv", "click", () => doExport("csv"));
  on("expZip", "click", () => doExport("zip"));
  on("whClose", "click", () => { const d = $("whDlg"); if (d) d.close(); });
  on("whAdd", "click", addWebhook);
  on("annBtn", "click", createAnnouncement);
  on("addrSearch", "input", (e) => { state.addrQuery = e.target.value; renderAddresses(); });
  on("mxSpawnBtn", "click", () => spawnMatrixAccount());
  on("mxService", "keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); spawnMatrixAccount(); } });
  on("mxSyncBtn", "click", syncMatrixNow);
  document.querySelectorAll("[data-mx-quick]").forEach((b) =>
    b.addEventListener("click", () => spawnMatrixAccount(b.dataset.mxQuick, b.dataset.mxDays)));
  on("mxSearch", "input", (e) => { state.mxQuery = e.target.value; renderMatrix(); });
  on("mxRefreshAllBtn", "click", () => { loadMatrix(); toast("Memperbarui semua OTP Matrix…"); });
  on("mxExportJson", "click", () => exportMatrixVault("json"));
  on("mxExportCsv", "click", () => exportMatrixVault("csv"));
  on("mxeGenPass", "click", async () => {
    const pw = clientGenStrongPass(18);
    if ($("mxePass")) $("mxePass").value = pw;
    try { await navigator.clipboard.writeText(pw); } catch {}
    toast("Password 18-char dibuat & disalin");
  });
  on("mxeCancel", "click", () => { const d = $("matrixEditDlg"); if (d) d.close(); });
  on("mxeSave", "click", saveMatrixEdit);
  on("bulkExtend", "click", () => {
    const role = state.me ? state.me.role : "member";
    bulkPatch(role === "member" ? { days: 0 } : { ttl: 1209600 });
  });
  on("bulkPin", "click", () => bulkPatch({ pinned: true }));
  on("bulkUnpin", "click", () => bulkPatch({ pinned: false }));
  on("bulkDel", "click", bulkDelete);
  on("bulkExport", "click", bulkExport);
  on("createBtn", "click", () => createInbox($("localInput").value, null, ($("setupTtlWrap") && !$("setupTtlWrap").hidden) ? $("setupTtl").value : null));
  on("localInput", "keydown", (e) => { if (e.key === "Enter") createInbox($("localInput").value, null, ($("setupTtlWrap") && !$("setupTtlWrap").hidden) ? $("setupTtl").value : null); });
  on("copyBtn", "click", copyAddress);
  on("copyTop", "click", copyAddress);
  on("refreshBtn", "click", () => {
    if (state.view === "all") { loadAllInbox(); loadAddresses(); return; }
    if (state.view === "matrix") { loadMatrix(); return; }
    if (state.view === "addresses") { loadAddresses(); return; }
    loadInbox();
    loadAllInbox({ silent: true });
    if (isStaff()) loadUsers();
  });
  on("menuBtn", "click", openNav);
  on("navClose", "click", closeNav);
  on("searchInput", "input", (e) => {
    if (state.view === "all") {
      state.allQuery = e.target.value;
      if ($("allMobileSearchInput") && $("allMobileSearchInput").value !== state.allQuery) $("allMobileSearchInput").value = state.allQuery;
      renderAllList();
      return;
    }
    state.query = e.target.value;
    if ($("mobileSearchInput") && $("mobileSearchInput").value !== state.query) $("mobileSearchInput").value = state.query;
    renderList();
  });
  on("mobileSearchInput", "input", (e) => {
    state.query = e.target.value;
    if ($("searchInput") && $("searchInput").value !== state.query) $("searchInput").value = state.query;
    renderList();
  });
  on("allMobileSearchInput", "input", (e) => {
    state.allQuery = e.target.value;
    if ($("searchInput") && state.view === "all" && $("searchInput").value !== state.allQuery) $("searchInput").value = state.allQuery;
    renderAllList();
  });
  on("allAddrFilter", "change", (e) => {
    state.allAddrFilter = e.target.value || "";
    renderAllList();
  });
  on("allTabAll", "click", () => {
    state.allFilter = "all";
    if ($("allTabAll")) $("allTabAll").setAttribute("aria-selected", "true");
    if ($("allTabUnread")) $("allTabUnread").setAttribute("aria-selected", "false");
    renderAllList();
  });
  on("allTabUnread", "click", () => {
    state.allFilter = "unread";
    if ($("allTabUnread")) $("allTabUnread").setAttribute("aria-selected", "true");
    if ($("allTabAll")) $("allTabAll").setAttribute("aria-selected", "false");
    renderAllList();
  });
  on("allMarkAllReadBtn", "click", () => {
    if (!state.allMessages.length) return;
    for (const m of state.allMessages) state.read.add(m.id);
    store.read = state.read;
    renderAllList(); renderList(); renderTitle();
    toast("Semua pesan di All Inbox ditandai sudah dibaca");
  });
  on("tabAll", "click", () => { state.filter = "all"; $("tabAll").setAttribute("aria-selected","true"); $("tabUnread").setAttribute("aria-selected","false"); renderList(); });
  on("tabUnread", "click", () => { state.filter = "unread"; $("tabUnread").setAttribute("aria-selected","true"); $("tabAll").setAttribute("aria-selected","false"); renderList(); });
  on("markAllReadBtn", "click", () => {
    if (!state.messages.length) return;
    for (const m of state.messages) state.read.add(m.id);
    store.read = state.read;
    renderList(); renderTitle();
    toast("Semua pesan ditandai sudah dibaca");
  });
  on("clearMsgsBtn", "click", async () => {
    if (!state.address || !state.messages.length) return;
    if (!confirm("Kosongkan semua (" + state.messages.length + ") pesan di " + state.address + "? Alamat inbox tetap aktif.")) return;
    try {
      await api("/api/inbox/" + encodeURIComponent(state.address) + "/messages", { method: "DELETE" });
      state.messages = [];
      state.selected = null;
      state.read = new Set();
      store.read = state.read;
      renderList(); renderTitle(); renderEmptyRead();
      loadAddresses();
      loadMatrix({ silent: true });
      toast("Semua pesan di inbox dikosongkan");
    } catch (e) {
      toast("Gagal mengosongkan pesan: " + e.message, true);
    }
  });
  on("domainSelect", "change", (e) => { store.domain = e.target.value; renderDomainControls(); });
  on("cuBtn", "click", createUser);
  on("keyBtn", "click", createKey);
  on("pwBtn", "click", changePassword);
  on("ndBtn", "click", addDomain);
  on("uAll", "click", () => { state.userFilter = "all"; userTab("uAll","uPending","uApproved"); renderUsers(); });
  on("uPending", "click", () => { state.userFilter = "pending"; userTab("uPending","uAll","uApproved"); renderUsers(); });
  on("uApproved", "click", () => { state.userFilter = "approved"; userTab("uApproved","uAll","uPending"); renderUsers(); });
}

on("mobileLoginJump", "click", (e) => {
  e.preventDefault();
  const c = $("authCard") || $("loginForm");
  if (c) {
    try { c.scrollIntoView({ behavior: "smooth", block: "start" }); } catch {}
  }
  setTimeout(() => { if ($("loginEmail")) $("loginEmail").focus(); }, 150);
});

document.addEventListener("click", (e) => {
  document.querySelectorAll("details.rowmenu[open], details.more[open]").forEach((d) => {
    if (!d.contains(e.target) || e.target.closest(".menu-item, [data-qr], [data-export], [data-wh], [data-pin], [data-log], [data-del]")) {
      d.removeAttribute("open");
    }
  });
});
function userTab(on, ...off){ $(on).setAttribute("aria-selected","true"); off.forEach((x) => $(x).setAttribute("aria-selected","false")); }

/* ---------- tema ---------- */
function applyTheme(t){
  document.documentElement.dataset.theme = t;
  const cb = $("themeToggle"); if (cb) cb.checked = t === "dark";
  const m = document.querySelector('meta[name="theme-color"]');
  if (m) m.content = t === "dark" ? "#111315" : "#f9fbfc";
}
function setTheme(t){ try { localStorage.setItem("menyurat.theme2", t); } catch {} applyTheme(t); }
applyTheme(document.documentElement.dataset.theme === "dark" ? "dark" : "light");

/* ---------- banner pengumuman (hanya untuk user yang sudah login) ---------- */
async function loadBanner(){
  if (!state.me) return;
  const el = $("banner");
  if (!el) return;
  try {
    const j = await api("/api/announcement");
    const a = j && j.announcement;
    if (!a || !a.message) { el.hidden = true; return; }
    el.className = "banner" + (a.level && a.level !== "info" ? " " + a.level : "");
    el.innerHTML = '<span class="banner-text">' + esc(a.message) + '</span>' +
      '<button class="banner-x" type="button" aria-label="Tutup">&times;</button>';
    el.hidden = false;
    const x = el.querySelector(".banner-x");
    if (x) x.addEventListener("click", () => { el.hidden = true; });
  } catch { el.hidden = true; }
}

/* ---------- ringkasan (staff) ---------- */
async function loadDashboard(){
  if (!isStaff()) return;
  try { state.stats = await api("/api/admin/stats?days=14"); } catch { state.stats = null; }
  renderStats();
  loadAnnouncements();
}
function renderStats(){
  const g = $("statGrid"), bars = $("statsBars"), dom = $("statsDomains");
  if (!g) return;
  const s = state.stats;
  if (!s) { g.innerHTML = '<div class="empty-box">Gagal memuat statistik.</div>'; if (bars) bars.innerHTML = ""; if (dom) dom.innerHTML = ""; return; }
  const t = s.totals || {};
  g.innerHTML = [
    ["Alamat aktif", t.inboxes ?? 0],
    ["Email tersimpan", t.messages ?? 0],
    ["Pengguna", t.users ?? 0],
    ["Menunggu persetujuan", t.pending ?? 0]
  ].map(([k, v]) => '<div class="stat"><div class="stat-k">' + k + '</div><div class="stat-v">' + v + "</div></div>").join("");
  const span = Math.max(1, parseInt(s.days || "14", 10) || 14);
  const map = new Map((s.by_day || []).map((d) => [d.day, d]));
  const series = [];
  for (let i = span - 1; i >= 0; i--) {
    const dt = new Date(Date.now() - i * 86400000);
    const key = dt.toISOString().slice(0, 10);
    const row = map.get(key) || { day: key, inboxes: 0, messages: 0 };
    series.push(row);
  }
  const max = Math.max(1, ...series.map((d) => Math.max(d.inboxes || 0, d.messages || 0)));
  if (bars) {
    bars.innerHTML = series.map((d) => '<div class="bar-col" title="' + esc(d.day) + ': ' + (d.inboxes || 0) + ' alamat, ' + (d.messages || 0) + ' email">' +
        '<div class="bar-pair"><span class="bar b1" style="height:' + Math.round(((d.inboxes || 0) / max) * 100) + '%"></span>' +
        '<span class="bar b2" style="height:' + Math.round(((d.messages || 0) / max) * 100) + '%"></span></div>' +
        '<span class="bar-lbl">' + esc((d.day || "").slice(5)) + "</span></div>").join("");
  }
  if (dom) {
    const ds = s.top_domains || [];
    dom.innerHTML = ds.length
      ? ds.map((d) => '<div class="drow2"><span class="name">' + esc(d.domain) + '</span><span class="act"><span class="chip">' + (d.inboxes || 0) + " alamat</span></span></div>").join("")
      : '<div class="empty-box">Belum ada domain.</div>';
  }
}
async function loadAnnouncements(){
  if (!isStaff()) return;
  try {
    const j = await api("/api/admin/announcements");
    state.announcements = j.announcements || [];
  } catch { state.announcements = []; }
  renderAnnouncements();
}
function renderAnnouncements(){
  const wrap = $("annList"); if (!wrap) return;
  const rows = state.announcements || [];
  wrap.innerHTML = rows.length
    ? rows.map((a) => '<div class="annrow"><span class="ann-text">' + esc(a.message) + '</span>' +
        '<span class="meta"><span class="chip ' + (a.active ? "ok" : "no") + '">' + (a.active ? "aktif" : "nonaktif") + "</span></span>" +
        '<span class="acts"><button class="btn btn-sm" data-ann-toggle="' + a.id + '" data-active="' + (a.active ? "1" : "0") + '">' +
        (a.active ? "Nonaktifkan" : "Aktifkan") + '</button>' +
        '<button class="btn btn-sm" data-ann-del="' + a.id + '">Hapus</button></span></div>').join("")
    : '<div class="empty-box">Belum ada pengumuman.</div>';
  wrap.querySelectorAll("[data-ann-toggle]").forEach((b) =>
    b.addEventListener("click", async () => {
      try {
        await api("/api/admin/announcements/" + encodeURIComponent(b.dataset.annToggle), {
          method: "PATCH", headers: { "content-type": "application/json" },
          body: JSON.stringify({ active: b.dataset.active !== "1" })
        });
        await loadAnnouncements(); loadBanner();
      } catch (e) { toast("Gagal: " + e.message, true); }
    }));
  wrap.querySelectorAll("[data-ann-del]").forEach((b) =>
    b.addEventListener("click", async () => {
      if (!confirm("Hapus pengumuman ini?")) return;
      try {
        await api("/api/admin/announcements/" + encodeURIComponent(b.dataset.annDel), { method: "DELETE" });
        await loadAnnouncements(); loadBanner();
      } catch (e) { toast("Gagal: " + e.message, true); }
    }));
}
async function createAnnouncement(){
  const inp = $("annText"), msg = $("annMsg");
  const text = (inp && inp.value || "").trim();
  if (!text) { if (msg) { msg.textContent = "Isi pengumuman dulu."; msg.hidden = false; } return; }
  try {
    await api("/api/admin/announcements", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ message: text, level: ($("annLevel") && $("annLevel").value) || "info" })
    });
    if (inp) inp.value = "";
    if (msg) {
      msg.textContent = "Pengumuman tampil."; msg.hidden = false;
      clearTimeout(createAnnouncement._t);
      createAnnouncement._t = setTimeout(() => { msg.hidden = true; msg.textContent = ""; }, 2500);
    }
    await loadAnnouncements(); loadBanner();
  } catch (e) { if (msg) { msg.textContent = "Gagal: " + e.message; msg.hidden = false; } }
}

/* ---------- QR ---------- */
function openQr(address){
  const dlg = $("qrDlg"); if (!dlg) return;
  $("qrAddr").textContent = address;
  if ($("qrLink")) $("qrLink").textContent = address;
  const img = $("qrImg");
  try {
    const qr = qrcode(0, "M");
    qr.addData(address);
    qr.make();
    img.src = qr.createDataURL(6, 2);
  } catch { img.removeAttribute("src"); }
  dlg.showModal();
}

/* ---------- ekspor ---------- */
function openExport(address){
  const dlg = $("exportDlg"); if (!dlg) return;
  $("expAddr").textContent = address;
  dlg.dataset.addr = address;
  dlg.showModal();
}
function doExport(fmt){
  const dlg = $("exportDlg"); if (!dlg) return;
  const address = dlg.dataset.addr; if (!address) return;
  dlg.close();
  const a = document.createElement("a");
  a.href = "/api/inbox/" + encodeURIComponent(address) + "/export?format=" + encodeURIComponent(fmt);
  a.rel = "noopener";
  document.body.appendChild(a); a.click(); a.remove();
  toast("Menyiapkan ekspor " + fmt.toUpperCase() + ".");
}

/* ---------- webhook ---------- */
async function openWebhook(address){
  const dlg = $("whDlg"); if (!dlg) return;
  $("whAddr").textContent = address;
  dlg.dataset.addr = address;
  $("whMsg").hidden = true;
  dlg.showModal();
  await loadWebhooks(address);
}
async function loadWebhooks(address){
  const wrap = $("whList"); if (!wrap) return;
  wrap.innerHTML = '<div class="empty-box">Memuat.</div>';
  try {
    const j = await api("/api/webhook/" + encodeURIComponent(address));
    const rows = j.webhooks || [];
    wrap.innerHTML = rows.length
      ? rows.map((w) => '<div class="drow2"><span class="name mono" style="word-break:break-all">' + esc(w.url) + '</span>' +
          '<span class="status"><span class="chip ' + (w.last_status && w.last_status >= 200 && w.last_status < 300 ? "ok" : "no") + '">' +
          (w.last_status ? "HTTP " + w.last_status : "belum dipanggil") + '</span></span>' +
          '<span class="act"><button class="btn btn-sm" data-wh-del="' + w.id + '">Hapus</button></span></div>').join("")
      : '<div class="empty-box">Belum ada webhook.</div>';
    wrap.querySelectorAll("[data-wh-del]").forEach((b) =>
      b.addEventListener("click", async () => {
        try {
          await api("/api/webhook/" + encodeURIComponent(address) + "?id=" + encodeURIComponent(b.dataset.whDel), { method: "DELETE" });
          await loadWebhooks(address);
        } catch (e) { toast("Gagal: " + e.message, true); }
      }));
  } catch (e) {
    wrap.innerHTML = '<div class="empty-box">Gagal memuat: ' + esc(e.message) + "</div>";
  }
}
async function addWebhook(){
  const dlg = $("whDlg"), msg = $("whMsg");
  if (!dlg) return;
  const address = dlg.dataset.addr;
  const url = ($("whUrl") && $("whUrl").value || "").trim();
  if (!url) { if (msg) { msg.textContent = "URL wajib diisi."; msg.hidden = false; } return; }
  try {
    const j = await api("/api/webhook/" + encodeURIComponent(address), {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ url })
    });
    if (msg) { msg.textContent = "Webhook ditambahkan." + (j.secret ? " Simpan secret: " + j.secret : ""); msg.hidden = false; }
    if ($("whUrl")) $("whUrl").value = "";
    await loadWebhooks(address);
  } catch (e) { if (msg) { msg.textContent = "Gagal: " + e.message; msg.hidden = false; } }
}

/* ---------- aksi massal ---------- */
function syncBulkBar(){
  const bb = $("bulkBar"); if (!bb) return;
  const n = state.sel ? state.sel.size : 0;
  bb.hidden = n === 0;
  if ($("bulkCount")) $("bulkCount").textContent = n + " dipilih";
}
async function bulkPatch(body){
  const list = [...(state.sel || [])];
  if (!list.length) return;
  let ok = 0, fail = 0;
  for (const address of list) {
    try {
      await api("/api/inbox/" + encodeURIComponent(address), {
        method: "PATCH", headers: { "content-type": "application/json" },
        body: JSON.stringify(body)
      });
      ok++;
    } catch { fail++; }
  }
  state.sel.clear();
  toast("Diperbarui: " + ok + (fail ? ", gagal: " + fail : ""));
  loadAddresses();
}
async function bulkDelete(){
  const list = [...(state.sel || [])];
  if (!list.length) return;
  if (!confirm("Hapus " + list.length + " alamat terpilih?")) return;
  let ok = 0, fail = 0;
  for (const address of list) {
    try { await api("/api/inbox/" + encodeURIComponent(address), { method: "DELETE" }); ok++; }
    catch { fail++; }
  }
  if (state.address && list.includes(state.address)) {
    state.address = ""; store.address = ""; state.expires = 0; store.expires = 0;
    render();
  }
  state.sel.clear();
  toast("Dihapus: " + ok + (fail ? ", gagal: " + fail : ""));
  loadAddresses();
  loadMatrix({ silent: true });
}
function bulkExport(){
  const list = [...(state.sel || [])];
  if (!list.length) return;
  list.forEach((address, i) => {
    setTimeout(() => {
      const a = document.createElement("a");
      a.href = "/api/inbox/" + encodeURIComponent(address) + "/export?format=json";
      a.rel = "noopener";
      document.body.appendChild(a); a.click(); a.remove();
    }, i * 400);
  });
  toast("Menyiapkan ekspor " + list.length + " alamat.");
}

/* ---------- boot ---------- */
(async function boot(){
  initTurnstile();
  if ("serviceWorker" in navigator) { navigator.serviceWorker.register("/sw.js").catch(() => {}); }
  // izin audio dibuka pada interaksi pertama di halaman mana pun
  ["pointerdown","keydown","touchstart"].forEach((ev) =>
    document.addEventListener(ev, nsUnlock, { once: true, passive: true }));
  setInterval(tick, 1000);
  const rm = location.hash.match(/#\/reset\?token=(.+)$/);
  if (rm){
    $("resetToken").value = decodeURIComponent(rm[1]);
    authTab("reset");
    return;
  }
  try {
    const j = await api("/api/auth/me");
    if (j && j.user) {
      state.me = j.user;
      await enterApp();
    } else {
      authTab("login");
    }
  } catch {
    authTab("login");
  }
  setInterval(() => { if (state.me && state.address && !evtSource) loadInbox(); }, 15000);
  setInterval(() => { if (state.me && state.view === "all" && !allEvtSource && !document.hidden) loadAllInbox({ silent: true }); }, 10000);
  setInterval(() => { if (state.me && state.view === "matrix" && !document.hidden) loadMatrix({ silent: true }); }, 8000);
  setInterval(() => { if (state.me && isStaff() && state.view === "users") loadUsers(); }, 20000);
})();
