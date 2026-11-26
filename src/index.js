// src/index.js — Temp Mail multi-domain: auth, API key, attachment (R2), audit, SSE
import { parseEmail } from "./mime.js";
import { newSecret, verifyTotp, otpauthUri, recoveryCodes, totpAt, b32decode } from "./totp.js";
import {
  hashPassword, verifyPassword, createSession, destroySession, getSessionUser,
  sessionCookie, clearCookie, listUsers, getUserById, countUsers, purgeExpiredSessions,
  randomToken, sha256Hex
} from "./auth.js";

const ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";
const now = () => Date.now();
const isStaff = (u) => !!u && (u.role === "owner" || u.role === "admin");
const RANK = { owner: 4, admin: 3, vip: 2, member: 1 };
const rank = (r) => RANK[r] || 0;
const canManage = (me, target) => !!me && !!target && rank(me.role) > rank(target.role);

// TTL default per role (detik)
const TTL_ROLE = { member: 7 * 86400, vip: 14 * 86400, admin: 14 * 86400, owner: 14 * 86400 };
const TTL_MAX = 365 * 86400;
const TTL_MAX_ROLE = { member: 7 * 86400, vip: 90 * 86400, admin: 90 * 86400, owner: 365 * 86400 };
const TTL_MIN = 3600;
const MEMBER_QUOTA_PER_DOMAIN = 10;

function ttlFor(user, requested) {
  const role = user ? user.role : "member";
  if (role === "member") return TTL_ROLE.member;          // 7 hari, tidak bisa diubah
  // vip, admin & owner: custom masa aktif, dibatasi per peran (vip/admin 90 hari, owner 365 hari)
  if (!requested) return TTL_ROLE[role] || 14 * 86400;
  const n = parseInt(requested, 10);
  if (!Number.isFinite(n)) return TTL_ROLE[role] || 14 * 86400;
  return Math.min(Math.max(n, TTL_MIN), TTL_MAX_ROLE[role] || TTL_MAX);
}

/* ---------------- util ---------------- */
function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers },
  });
}
// nama depan/belakang supaya alamat acak terlihat seperti orang, bukan string acak
const FIRST = [
  "roro","janeru","budi","siti","andi","dewi","rizky","putri","agus","maya",
  "dimas","intan","fajar","nadia","reza","sari","yoga","lia","hafiz","tari",
  "galih","wulan","arif","ratna","bayu","sinta","eko","mega","hendra","vina",
  "irfan","citra","doni","ayu","fauzi","nisa","gunawan","tika","ilham","diah",
  "joko","lisa","kurnia","mira","lukman","okta","maulana","prima","nanda","rika"
];
const LAST = [
  "janeru","pratama","saputra","wijaya","nugroho","rahmawati","setiawan","kusuma",
  "haryanto","permata","firdaus","anggraini","wibowo","lestari","sanjaya","maulida",
  "prakoso","safitri","gunadi","ardiani","susanto","handayani","nurhadi","oktaviani",
  "purnama","suryani","taufik","utami","wahyudi","yuliani","firmansyah","ginting",
  "habibi","iswara","jailani","karim","lubis","mahardika","nasution","pradana"
];
const pickOne = (arr) => arr[Math.floor(Math.random() * arr.length)];
const digits = (n) => String(Math.floor(Math.random() * Math.pow(10, n))).padStart(n, "0");

function randLocal() {
  const f = pickOne(FIRST);
  const l = pickOne(LAST);
  if (f === l) return `${f}.${pickOne(LAST.filter((x) => x !== f))}`;
  const r = Math.random();
  if (r < 0.55) return `${f}.${l}`;
  if (r < 0.72) return `${f}${l}`;
  if (r < 0.86) return `${f}.${l}${digits(2)}`;
  return `${f}${digits(3)}`;
}

function validLocal(s) {
  if (!s || s.length < 3 || s.length > 64) return false;
  if (!/^[a-z0-9._-]+$/.test(s)) return false;
  if (s.startsWith(".") || s.endsWith(".")) return false;
  if (s.includes("..")) return false;
  return true;
}
const num = (env, key, def) => {
  const n = parseInt(env[key] || "", 10);
  return Number.isFinite(n) && n > 0 ? n : def;
};
const ttlSeconds = (env) => num(env, "INBOX_TTL_SECONDS", 1209600);
// batas ukuran email masuk (byte mentah). Default 5 MB.
const maxMailBytes = (env) => Math.max(1024, num(env, "MAX_MESSAGE_BYTES", 15 * 1024 * 1024));
// di atas ambang ini, .eml mentah tidak diarsipkan (lampiran tetap disimpan terpisah)
const rawKeepBytes = (env) => Math.max(1024, num(env, "RAW_KEEP_BYTES", 6 * 1024 * 1024));
// D1 membatasi ukuran baris (~2 MB); badan teks dipotong supaya simpan tidak gagal 500
const BODY_MAX_CHARS = 200000;
const clipBody = (s) => (typeof s === "string" && s.length > BODY_MAX_CHARS)
  ? s.slice(0, BODY_MAX_CHARS) + "\n\n[...isi dipotong]"
  : s;
const normalizeLocal = (s) => (s || "").trim().toLowerCase().replace(/[^a-z0-9._-]/g, "").slice(0, 64);
const normalizeDomain = (s) => (s || "").trim().toLowerCase().replace(/^@/, "").replace(/[^a-z0-9.-]/g, "");
const normalizeEmail = (s) => (s || "").trim().toLowerCase();
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i;
const ipOf = (request) => request.headers.get("cf-connecting-ip") || request.headers.get("x-real-ip") || "0.0.0.0";

/* ---------------- webhook helpers ---------------- */
// Tolak URL tujuan internal/loopback/self-domain (SSRF & loop protection).
function isSafeWebhookUrl(u, selfHost = "") {
  let x;
  try { x = new URL(u); } catch { return false; }
  if (x.protocol !== "https:" && x.protocol !== "http:") return false;
  if (x.username || x.password) return false;
  const rawHost = (x.hostname || "").toLowerCase();
  const h = rawHost.replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (!h || h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal")) return false;
  if (h.endsWith(".workers.dev")) return false;
  if (selfHost && (h === selfHost || h.endsWith("." + selfHost))) return false;
  // Block all IPv6 literals (loopback [::1], link-local [fe80::], unique-local [fc00::/fd00::], IPv4-mapped [::ffff:...])
  if (h.includes(":")) return false;
  // Block integer/hex/octal single-number IPv4 encodings
  if (/^(0x[0-9a-f]+|\d+)$/i.test(h)) return false;
  // If numeric dotted-quad IPv4, strictly validate public ranges
  if (/^[0-9.]+$/.test(h)) {
    const parts = h.split(".");
    if (parts.length !== 4) return false;
    const nums = parts.map((p) => (/^(0|[1-9]\d*)$/.test(p) ? Number(p) : -1));
    if (nums.some((n) => n < 0 || n > 255)) return false;
    const [a, b] = nums;
    if (a === 0 || a === 10 || a === 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a >= 224) return false;
  }
  return true;
}

async function hmacHex(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Kirim notifikasi email baru ke URL webhook terdaftar. Gagal senyap:
// pengiriman email tidak boleh bergantung pada endpoint pihak ketiga.
async function fireWebhook(env, address, msg) {
  try {
    const { results } = await env.DB.prepare(
      `SELECT id, url, secret FROM webhooks WHERE address = ?1 AND active = 1 LIMIT 5`
    ).bind(address).all();
    if (!results || !results.length) return;
    for (const h of results) {
      if (!isSafeWebhookUrl(h.url)) continue;
      const payload = JSON.stringify({
        event: "message.new", inbox: address,
        id: msg.id, from: msg.from, subject: msg.subject,
        received_at: msg.received_at, attachments: msg.attachments || 0,
      });
      const headers = { "content-type": "application/json", "user-agent": "menyurat-webhook/1" };
      if (h.secret) {
        const ts = String(now());
        headers["x-menyurat-timestamp"] = ts;
        headers["x-menyurat-signature"] = "sha256=" + await hmacHex(h.secret, ts + "." + payload);
      }
      const ctrl = new AbortController();
      const to = setTimeout(() => ctrl.abort(), 5000);
      try {
        const res = await fetch(h.url, { method: "POST", headers, body: payload, redirect: "manual", signal: ctrl.signal });
        await env.DB.prepare(`UPDATE webhooks SET last_status = ?2, last_at = ?3 WHERE id = ?1`)
          .bind(h.id, res.status, now()).run();
      } catch (e) {
        await env.DB.prepare(`UPDATE webhooks SET last_status = -1, last_at = ?2 WHERE id = ?1`)
          .bind(h.id, now()).run();
      } finally { clearTimeout(to); }
    }
  } catch (e) { console.error("webhook error:", e); }
}

/* ---------------- zip (store, tanpa kompresi) ---------------- */
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(bytes) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function zipStore(files) {
  const enc = new TextEncoder();
  const locals = [], centrals = [];
  let offset = 0;
  for (const f of files) {
    const name = enc.encode(f.name);
    const data = f.bytes instanceof Uint8Array ? f.bytes : enc.encode(String(f.bytes ?? ""));
    const crc = crc32(data);
    const lh = new DataView(new ArrayBuffer(30));
    lh.setUint32(0, 0x04034b50, true); lh.setUint16(4, 20, true); lh.setUint16(6, 0x0800, true);
    lh.setUint16(8, 0, true); lh.setUint16(10, 0, true); lh.setUint16(12, 0, true);
    lh.setUint32(14, crc, true); lh.setUint32(18, data.length, true); lh.setUint32(22, data.length, true);
    lh.setUint16(26, name.length, true); lh.setUint16(28, 0, true);
    locals.push(new Uint8Array(lh.buffer), name, data);

    const ch = new DataView(new ArrayBuffer(46));
    ch.setUint32(0, 0x02014b50, true); ch.setUint16(4, 20, true); ch.setUint16(6, 20, true);
    ch.setUint16(8, 0x0800, true); ch.setUint16(10, 0, true); ch.setUint16(12, 0, true);
    ch.setUint16(14, 0, true); ch.setUint32(16, crc, true); ch.setUint32(20, data.length, true);
    ch.setUint32(24, data.length, true); ch.setUint16(28, name.length, true);
    ch.setUint16(30, 0, true); ch.setUint16(32, 0, true); ch.setUint16(34, 0, true);
    ch.setUint16(36, 0, true); ch.setUint32(38, 0, true); ch.setUint32(42, offset, true);
    centrals.push(new Uint8Array(ch.buffer), name);
    offset += 30 + name.length + data.length;
  }
  const cdSize = centrals.reduce((n, p) => n + p.length, 0);
  const eocd = new DataView(new ArrayBuffer(22));
  eocd.setUint32(0, 0x06054b50, true); eocd.setUint16(4, 0, true); eocd.setUint16(6, 0, true);
  eocd.setUint16(8, files.length, true); eocd.setUint16(10, files.length, true);
  eocd.setUint32(12, cdSize, true); eocd.setUint32(16, offset, true); eocd.setUint16(20, 0, true);
  const all = [...locals, ...centrals, new Uint8Array(eocd.buffer)];
  const total = all.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of all) { out.set(p, o); o += p.length; }
  return out;
}
function csvCell(v) {
  let s = String(v ?? "");
  // Netralisir CSV Formula Injection (Excel / Calc / Sheets)
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

/* ---------------- hardening ---------------- */
function allowedOriginsFor(request) {
  try {
    const u = new URL(request.url);
    const baseHost = u.hostname.toLowerCase().replace(/^www\./, "");
    return new Set([u.origin, `https://${baseHost}`, `https://www.${baseHost}`]);
  } catch {
    return new Set();
  }
}

const SEC_HEADERS = {
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "permissions-policy": "geolocation=(), microphone=(), camera=()",
  "content-security-policy": "default-src 'self'; script-src 'self' https://challenges.cloudflare.com https://static.cloudflareinsights.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob: https:; media-src 'self' data: blob:; connect-src 'self' https://challenges.cloudflare.com https://cloudflareinsights.com; frame-src https://challenges.cloudflare.com; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
};

function isValidCsrfRequest(request) {
  const method = request.method.toUpperCase();
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") return true;
  const hasApiKey = Boolean(
    (request.headers.get("x-api-key") || "").trim() ||
    /^bearer\s+mn_/i.test(request.headers.get("authorization") || "")
  );
  if (hasApiKey) return true;
  const secSite = (request.headers.get("sec-fetch-site") || "").toLowerCase();
  if (secSite === "cross-site") return false;
  const origin = request.headers.get("origin");
  if (origin) {
    if (allowedOriginsFor(request).has(origin)) return true;
    try {
      const oh = new URL(origin).hostname.toLowerCase();
      if (oh === "localhost" || oh === "127.0.0.1") return true;
    } catch {}
    return false;
  }
  return true;
}

function corsFor(request) {
  const origin = request.headers.get("origin") || "";
  if (!allowedOriginsFor(request).has(origin)) return { vary: "Origin" };
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-credentials": "true",
    vary: "Origin",
  };
}

// Terima parameter dari query string DAN body JSON. Klien otomasi biasanya
// mengirim JSON; kalau body diabaikan diam-diam, request tetap balas 200
// padahal alamat/TTL yang dipakai cuma default (bug senyap).
async function paramsFor(request, url) {
  const p = new URLSearchParams(url.searchParams);
  const ct = request.headers.get("content-type") || "";
  if (ct.includes("application/json")) {
    try {
      const b = await request.json();
      if (b && typeof b === "object" && !Array.isArray(b)) {
        for (const [k, v] of Object.entries(b)) {
          if (v === undefined || v === null || v === "") continue;
          p.set(k, typeof v === "object" ? JSON.stringify(v) : String(v));
        }
      }
    } catch { /* body kosong / bukan JSON: pakai query */ }
  }
  return p;
}

// CSP inline-script hash dihitung ulang dari HTML yang benar-benar disajikan,
// supaya hash tidak pernah basi setiap kali public/index.html diedit.
const CSP_INLINE_CACHE = { key: null, value: null };
const CSP_BASE = "default-src 'self'; script-src 'self' %HASHES% https://challenges.cloudflare.com https://static.cloudflareinsights.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob: https:; media-src 'self' data: blob:; connect-src 'self' https://challenges.cloudflare.com https://cloudflareinsights.com; frame-src https://challenges.cloudflare.com; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests";

function b64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

async function cspForHtml(html) {
  const key = String(html.length) + ":" + (html.charCodeAt(0) || 0) + ":" + (html.charCodeAt(html.length - 1) || 0);
  if (CSP_INLINE_CACHE.key === key && CSP_INLINE_CACHE.value) return CSP_INLINE_CACHE.value;
  const hashes = [];
  const re = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    let body = m[1];
    if (!body || !body.trim()) continue;
    // Browser menormalkan CRLF/CR menjadi LF sebelum menghitung hash CSP.
    // Kalau di sini tidak dinormalkan, hash tidak cocok dan seluruh inline
    // script diblokir (widget Turnstile mati, form tidak berfungsi).
    body = body.replace(/\r\n?/g, "\n");
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body));
    hashes.push("'sha256-" + b64(digest) + "'");
  }
  const csp = CSP_BASE.replace("%HASHES%", hashes.join(" "));
  CSP_INLINE_CACHE.key = key;
  CSP_INLINE_CACHE.value = csp;
  return csp;
}

function harden(res, request, csp) {
  const h = new Headers(res.headers);
  for (const [k, v] of Object.entries(SEC_HEADERS)) h.set(k, v);
  if (csp) h.set("content-security-policy", csp);
  if (request) for (const [k, v] of Object.entries(corsFor(request))) h.set(k, v);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
}

/* ---------------- reserved local-part ---------------- */
const RESERVED_WORDS = [
  "admin","administrator","administrasi","admins","root","owner","sysadmin","superuser",
  "postmaster","hostmaster","webmaster","abuse","security","secure","support","help","helpdesk",
  "it","ict","noc","ops","operation","operations","devops","dev","developer","api","apis",
  "bot","bots","mail","mailer","mailerdaemon","daemon","noreply","donotreply",
  "notification","notifications","notify","alert","alerts","info","information","contact",
  "hello","hi","sales","marketing","billing","invoice","invoices","payment","payments",
  "finance","legal","privacy","dmca","compliance","hr","career","careers","job","jobs",
  "recruitment","press","media","news","newsletter","team","staff","official","verify",
  "verification","account","accounts","auth","login","signup","register","password","reset",
  "token","key","keys","test","demo","example","sample","null","undefined","system","service",
  "services","cloudflare","dns","smtp","imap","pop","mx","email","emails","inbox","outbox",
  "spam","junk","phishing","fraud","report","reports","status","monitor","monitoring",
  "uptime","stat","stats","cdn","static","assets","files","file","upload","download",
  "docs","doc","blog","forum","community","discord","telegram","whatsapp","instagram",
  "facebook","twitter","tiktok","youtube","google","microsoft","apple","amazon","meta",
  "paypal","bank","bca","bri","bni","mandiri","ovo","gopay","dana","shopee","tokopedia",
  "bukalapak","lazada","grab","gojek","traveloka","tiket","jne","jnt","sicepat","kai",
  "pln","telkom","indihome","telkomsel","xl","tri","smartfren","otp","verifikasi",
];
const RESERVED = new Set(RESERVED_WORDS);

function isReservedLocal(local) {
  const l = String(local || "").toLowerCase();
  const canon = l.replace(/[^a-z0-9]/g, "");
  if (RESERVED.has(l) || RESERVED.has(canon)) return true;
  for (const w of RESERVED_WORDS) {
    if (w.length < 3) continue;
    if (canon.startsWith(w) && /^[0-9]*$/.test(canon.slice(w.length))) return true;
    if (l.startsWith(w + ".") || l.startsWith(w + "-") || l.startsWith(w + "_")) return true;
  }
  return false;
}

/* ---------------- Turnstile ---------------- */
async function verifyTurnstile(env, request, token) {
  if (!env.TURNSTILE_SECRET) return { ok: true, skipped: true };
  const t = String(token || "").trim();
  if (!t) return { ok: false, error: "captcha_required" };
  try {
    const form = new URLSearchParams();
    form.set("secret", env.TURNSTILE_SECRET);
    form.set("response", t);
    const ip = ipOf(request);
    if (ip && ip !== "0.0.0.0") form.set("remoteip", ip);
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form });
    const j = await r.json().catch(() => ({}));
    return j.success ? { ok: true } : { ok: false, error: "captcha_failed" };
  } catch {
    return { ok: false, error: "captcha_unavailable" };
  }
}

/* ---------------- rate limit generik ---------------- */
async function hitRate(env, key, limit, windowMs) {
  const t = now();
  const row = await env.DB.prepare(`SELECT count, window_start FROM rate_limits WHERE rl_key = ?1`).bind(key).first();
  if (!row || t - row.window_start > windowMs) {
    await env.DB.prepare(
      `INSERT INTO rate_limits (rl_key, count, window_start) VALUES (?1, 1, ?2)
       ON CONFLICT(rl_key) DO UPDATE SET count = 1, window_start = ?2`
    ).bind(key, t).run();
    return { ok: true };
  }
  if (row.count >= limit) {
    return { ok: false, retry: Math.max(1, Math.ceil((row.window_start + windowMs - t) / 1000)) };
  }
  await env.DB.prepare(`UPDATE rate_limits SET count = count + 1 WHERE rl_key = ?1`).bind(key).run();
  return { ok: true };
}

/* ---------------- audit ---------------- */
async function audit(env, actor, action, target, meta, request) {
  try {
    await env.DB.prepare(
      `INSERT INTO audit_log (id, actor_id, actor_email, action, target, meta, ip, created_at)
       VALUES (?1,?2,?3,?4,?5,?6,?7,?8)`
    ).bind(
      crypto.randomUUID(),
      actor ? actor.id : null,
      actor ? actor.email : null,
      action,
      target || null,
      meta ? JSON.stringify(meta).slice(0, 500) : null,
      request ? ipOf(request) : null,
      now()
    ).run();
  } catch (e) { console.error("audit fail", e); }
}

/* ---------------- domains ---------------- */
async function listDomains(env, activeOnly = true) {
  const sql = activeOnly
    ? `SELECT domain, label, is_default, is_premium FROM domains WHERE is_active = 1 ORDER BY is_default DESC, domain`
    : `SELECT domain, label, is_active, is_default, is_premium FROM domains ORDER BY domain`;
  const { results } = await env.DB.prepare(sql).all();
  return results || [];
}
async function getDomain(env, domain) {
  return env.DB.prepare(`SELECT domain, label, is_active, is_default, is_premium FROM domains WHERE domain = ?1`).bind(domain).first();
}
async function resolveDomain(env, requested) {
  if (requested) {
    const d = normalizeDomain(requested);
    const row = await getDomain(env, d);
    if (!row || !row.is_active) return { error: "domain_not_available", domain: d };
    return { domain: row.domain };
  }
  if (env.DEFAULT_DOMAIN) {
    const row = await getDomain(env, normalizeDomain(env.DEFAULT_DOMAIN));
    if (row && row.is_active) return { domain: row.domain };
  }
  const def = await env.DB.prepare(
    `SELECT domain FROM domains WHERE is_active = 1 ORDER BY is_default DESC, domain LIMIT 1`
  ).first();
  if (!def) return { error: "no_domain_configured" };
  return { domain: def.domain };
}

/* ---------------- inbox ---------------- */
const inboxRow = (env, address) =>
  env.DB.prepare(`SELECT address, domain, user_id, created_at, expires_at, pinned, note FROM inboxes WHERE address = ?1`).bind(address).first();

async function purgeInboxContents(env, address) {
  const { results: msgs } = await env.DB.prepare(`SELECT raw_key FROM messages WHERE inbox = ?1`).bind(address).all();
  const { results: atts } = await env.DB.prepare(`SELECT r2_key FROM attachments WHERE inbox = ?1`).bind(address).all();
  for (const m of msgs || []) if (m.raw_key) await fileDel(env, m.raw_key);
  for (const a of atts || []) if (a.r2_key) await fileDel(env, a.r2_key);
  await env.DB.batch([
    env.DB.prepare(`DELETE FROM attachments WHERE inbox = ?1`).bind(address),
    env.DB.prepare(`DELETE FROM messages WHERE inbox = ?1`).bind(address),
    env.DB.prepare(`DELETE FROM webhooks WHERE address = ?1`).bind(address),
  ]);
}

async function ensureInbox(env, address, domain, userId = null, ttlSec = null, note = null) {
  const t = now();
  const exp = t + (ttlSec || ttlSeconds(env)) * 1000;
  const cleanNote = note ? String(note).trim().slice(0, 120) : null;
  const existing = await inboxRow(env, address);
  if (existing) {
    const active = existing.expires_at > t || existing.pinned === 1;
    // Block takeover or TTL sabotage of another user's active inbox
    if (active && existing.user_id !== userId) {
      return { conflict: true, address, domain };
    }
    if (existing.user_id && existing.user_id === userId) {
      // Re-selecting own inbox: never shorten existing expiry
      const safeExp = Math.max(Number(existing.expires_at) || 0, exp);
      const nextNote = cleanNote !== null ? cleanNote : existing.note || null;
      await env.DB.prepare(
        `UPDATE inboxes SET last_seen = ?2, expires_at = ?3, note = ?4 WHERE address = ?1`
      ).bind(address, t, safeExp, nextNote).run();
      return { address, domain, created_at: existing.created_at, expires_at: safeExp, note: nextNote };
    }
    // Expired unpinned inbox previously owned by someone else (or orphaned):
    // purge old messages, attachments, and webhooks before assigning to new owner
    await purgeInboxContents(env, address);
    await env.DB.prepare(
      `UPDATE inboxes SET user_id = ?2, created_at = ?3, expires_at = ?4, last_seen = ?3, pinned = 0, note = ?5 WHERE address = ?1`
    ).bind(address, userId, t, exp, cleanNote).run();
    return { address, domain, created_at: t, expires_at: exp, note: cleanNote };
  }
  await env.DB.prepare(
    `INSERT INTO inboxes (address, local_part, domain, user_id, created_at, expires_at, last_seen, note)
     VALUES (?1,?2,?3,?4,?5,?6,?5,?7)`
  ).bind(address, address.split("@")[0], domain, userId, t, exp, cleanNote).run();
  return { address, domain, created_at: t, expires_at: exp, note: cleanNote };
}

// owner: semua. admin: vip/member (termasuk inbox tak bertuan). vip/member: miliknya.
async function canSee(env, user, box) {
  if (!box) return false;
  if (box.user_id && box.user_id === user.id) return true;
  if (user.role === "owner") return true;
  if (user.role === "admin") {
    if (!box.user_id) return true;
    const o = await env.DB.prepare(`SELECT role FROM users WHERE id = ?1`).bind(box.user_id).first();
    return !o ? true : rank(o.role) < rank("admin");
  }
  return false;
}

async function listMessages(env, address) {
  const { results } = await env.DB.prepare(
    `SELECT m.id, m.from_addr, m.from_name, m.subject, m.received_at, m.raw_size, m.attach_count,
            SUBSTR(COALESCE(m.text_body, m.html_body, ''), 1, 1200) AS snippet
       FROM messages m
       LEFT JOIN inboxes i ON i.address = m.inbox
      WHERE m.inbox = ?1 AND (m.expires_at > ?2 OR i.pinned = 1)
      ORDER BY m.received_at DESC LIMIT 200`
  ).bind(address, now()).all();
  return results || [];
}
const getMessage = (env, address, id) =>
  env.DB.prepare(
    `SELECT m.* FROM messages m
       LEFT JOIN inboxes i ON i.address = m.inbox
      WHERE m.id = ?1 AND m.inbox = ?2 AND (m.expires_at > ?3 OR i.pinned = 1)`
  ).bind(id, address, now()).first();

// member: 10 alamat aktif per domain. role lain: tanpa batas.
async function quotaCheck(env, user, domain) {
  if (user.role !== "member") return null;
  const row = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM inboxes
      WHERE user_id = ?1 AND domain = ?2 AND (expires_at > ?3 OR pinned = 1)`
  ).bind(user.id, domain, now()).first();
  const used = row ? row.n : 0;
  if (used >= MEMBER_QUOTA_PER_DOMAIN) {
    return { error: "inbox_quota_reached", scope: "domain", domain, max: MEMBER_QUOTA_PER_DOMAIN, used };
  }
  return null;
}

/* ---------------- storage ---------------- */
const store = (env) => env.BUCKET || env.FILE_KV || null;

async function filePut(env, key, bytes, contentType) {
  if (env.BUCKET) {
    await env.BUCKET.put(key, bytes, { httpMetadata: { contentType } });
    return true;
  }
  if (env.FILE_KV) {
    await env.FILE_KV.put(key, bytes, { metadata: { contentType, size: bytes.length } });
    return true;
  }
  return false;
}

async function fileGet(env, key) {
  if (env.BUCKET) {
    const o = await env.BUCKET.get(key);
    return o ? { body: o.body, contentType: o.httpMetadata?.contentType || null } : null;
  }
  if (env.FILE_KV) {
    const buf = await env.FILE_KV.get(key, { type: "arrayBuffer" });
    return buf ? { body: buf, contentType: null } : null;
  }
  return null;
}

async function fileDel(env, key) {
  if (env.BUCKET) { try { await env.BUCKET.delete(key); } catch {} return; }
  if (env.FILE_KV) { try { await env.FILE_KV.delete(key); } catch {} }
}

/* ---------------- email ---------------- */
async function streamToBytes(stream, limit = 10 * 1024 * 1024) {
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.length;
    if (total > limit) break;
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { buf.set(c, off); off += c.length; }
  return buf;
}

// satu jalur untuk email masuk asli maupun injeksi (tes)
async function ingest(env, to, bytes, preloadedBox = null) {
  const box = preloadedBox || await inboxRow(env, to);
  if (!box) return null;
  const t = now();
  if (box.expires_at <= t && !box.pinned) return null;

  const raw = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const parsed = parseEmail(raw);
  parsed.to = to;

  // Hash penuh Message-ID: dedupe tetap per-inbox (PK komposit), tapi tidak
  // lagi memotong 40 char sehingga dua Message-ID berbeda tidak bertabrakan.
  const msgId = parsed.messageId ? await sha256Hex(parsed.messageId) : crypto.randomUUID();

  // Cegah duplikasi file KV, attachment, dan webhook saat email yang sama di-retry MTA
  const existingMsg = await env.DB.prepare(`SELECT id FROM messages WHERE inbox = ?1 AND id = ?2`).bind(to, msgId).first();
  if (existingMsg) return msgId;

  let rawKey = null;
  // hindari duplikasi besar: .eml (yang memuat lampiran base64) hanya untuk pesan kecil
  if (store(env) && bytes.length <= rawKeepBytes(env)) {
    rawKey = `raw/${to}/${msgId}.eml`;
    await filePut(env, rawKey, bytes, "message/rfc822");
  }

  const exp = box.expires_at && box.expires_at > t ? box.expires_at : t + ttlSeconds(env) * 1000;
  const ins = await env.DB.prepare(
    `INSERT OR IGNORE INTO messages
       (id, inbox, from_addr, from_name, to_addr, subject, text_body, html_body,
        raw_size, received_at, expires_at, raw_key, attach_count)
     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)`
  ).bind(
    msgId, to, parsed.from?.address || null, parsed.from?.name || null,
    to, parsed.subject || "(no subject)", clipBody(parsed.text) || null, clipBody(parsed.html) || null,
    bytes.length, t, exp, rawKey, parsed.attachments.length
  ).run();
  if (ins && ins.meta && ins.meta.changes === 0) return msgId;

  await env.DB.prepare(
    `INSERT OR IGNORE INTO inbox_log (inbox, domain, peer, peer_name, subject, message_id, first_at)
     VALUES (?1,?2,?3,?4,?5,?6,?7)`
  ).bind(to, to.split("@")[1] || null, parsed.from?.address || null, parsed.from?.name || null,
    parsed.subject || null, msgId, t).run();

for (const a of parsed.attachments) {
    const attId = crypto.randomUUID();
    const key = `att/${to}/${msgId}/${attId}`;
    if (store(env)) {
      await filePut(env, key, a.bytes, a.mime);
      await env.DB.prepare(
        `INSERT INTO attachments (id, message_id, inbox, filename, mime, size, r2_key, created_at, expires_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)`
      ).bind(attId, msgId, to, a.filename.slice(0, 180), a.mime, a.bytes.length, key, t, exp).run();
    }
  }
  await fireWebhook(env, to, {
    id: msgId,
    from: parsed.from?.address || null,
    subject: parsed.subject || "(no subject)",
    received_at: t,
    attachments: parsed.attachments.length,
  });
  if (box.user_id) {
    try {
      await autoRegisterMatrixFromEmail(
        env,
        box.user_id,
        to,
        parsed.from?.address || null,
        parsed.from?.name || null,
        parsed.subject || null,
        t
      );
    } catch {}
  }
  return msgId;
}

async function handleEmail(message, env) {
  const to = (message.to || "").trim().toLowerCase();
  if (!to.includes("@")) return;
  const row = await getDomain(env, to.split("@")[1]);
  if (!row || !row.is_active) return;
  // Cek eksistensi dan masa aktif inbox sebelum membaca stream email mentah ke RAM
  const box = await inboxRow(env, to);
  if (!box || (box.expires_at <= now() && !box.pinned)) return;
  const maxBytes = maxMailBytes(env);
  const bytes = await streamToBytes(message.raw, maxBytes + 1);
  // tolak email kebesaran: jangan simpan ke KV/D1 sama sekali
  if (bytes.length > maxBytes) return;
  await ingest(env, to, bytes, box);
}
/* ---------------- auth helpers ---------------- */
async function userFromApiKey(env, request) {
  const auth = request.headers.get("authorization") || "";
  const xk = (request.headers.get("x-api-key") || "").trim();
  let raw = xk;
  if (!raw && /^bearer\s+mn_/i.test(auth)) raw = auth.replace(/^bearer\s+/i, "").trim();
  if (!raw || !raw.startsWith("mn_")) return null;

  const hash = await sha256Hex(raw);
  const row = await env.DB.prepare(
    `SELECT k.id AS key_id, u.id, u.email, u.name, u.role, u.status
       FROM api_keys k JOIN users u ON u.id = k.user_id
      WHERE k.key_hash = ?1 AND k.revoked_at IS NULL`
  ).bind(hash).first();
  if (!row || row.status !== "approved") return null;
  await env.DB.prepare(`UPDATE api_keys SET last_used = ?2 WHERE id = ?1`).bind(row.key_id, now()).run();
  return { id: row.id, email: row.email, name: row.name, role: row.role, status: row.status, authType: "api_key" };
}

async function currentUser(env, request) {
  return (await getSessionUser(env, request)) || (await userFromApiKey(env, request));
}

/* ---------------- rate limit ---------------- */
async function hitLogin(env, ip, email) {
  const key = await sha256Hex(ip + "|" + email);
  const row = await env.DB.prepare(
    `SELECT count, window_start, locked_until FROM login_attempts WHERE rl_key = ?1`
  ).bind(key).first();
  const t = now();
  if (row && row.locked_until > t) {
    return { key, row, blocked: true, retry: Math.ceil((row.locked_until - t) / 1000) };
  }
  return { key, row, blocked: false };
}

async function failLogin(env, key, row) {
  const t = now();
  const WINDOW = 15 * 60 * 1000, MAX = 5, LOCK = 15 * 60 * 1000;
  if (!row || t - row.window_start > WINDOW) {
    await env.DB.prepare(
      `INSERT INTO login_attempts (rl_key, count, window_start, locked_until) VALUES (?1,1,?2,0)
       ON CONFLICT(rl_key) DO UPDATE SET count = 1, window_start = ?2, locked_until = 0`
    ).bind(key, t).run();
    return { remaining: MAX - 1 };
  }
  const count = row.count + 1;
  const locked = count >= MAX ? t + LOCK : 0;
  await env.DB.prepare(`UPDATE login_attempts SET count = ?2, locked_until = ?3 WHERE rl_key = ?1`)
    .bind(key, count, locked).run();
  return locked ? { locked_for: LOCK / 1000 } : { remaining: MAX - count };
}
const clearLogin = (env, key) => env.DB.prepare(`DELETE FROM login_attempts WHERE rl_key = ?1`).bind(key).run();

/* ---------------- auth routes ---------------- */
async function handleAuth(request, env, url) {
  const p = url.pathname, method = request.method;

  if (p === "/api/auth/me" && method === "GET") {
    const user = await currentUser(env, request);
    if (!user) return json({ user: null }, 401);
    return json({
      user: { id: user.id, email: user.email, name: user.name, role: user.role, totp: !!user.totp_enabled },
      pending_approvals: isStaff(user) ? await countUsers(env, "pending") : 0,
    });
  }

  if (p === "/api/auth/register" && method === "POST") {
    const rlIp = await hitRate(env, "reg|" + ipOf(request), 5, 3600_000);
    if (!rlIp.ok) return json({ error: "too_many_requests", retry_after: rlIp.retry }, 429, { "retry-after": String(rlIp.retry) });
    const b = await request.json().catch(() => ({}));
    const cap = await verifyTurnstile(env, request, b.captcha);
    if (!cap.ok) return json({ error: cap.error }, 400);

    const email = normalizeEmail(b.email);
    const password = String(b.password || "");
    const name = (b.name || "").trim().slice(0, 60) || null;
    if (!EMAIL_RE.test(email)) return json({ error: "invalid_email" }, 400);
    if (password.length < 8) return json({ error: "password_too_short", min: 8 }, 400);

    if (await env.DB.prepare(`SELECT id FROM users WHERE email = ?1`).bind(email).first())
      return json({ error: "email_taken" }, 409);

    const isOwner = normalizeEmail(env.OWNER_EMAIL || "") === email;
    const id = crypto.randomUUID(), t = now();
    await env.DB.prepare(
      `INSERT INTO users (id,email,name,pass_hash,role,status,created_at,approved_at,approved_by)
       VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)`
    ).bind(id, email, name, await hashPassword(password), isOwner ? "owner" : "member",
      isOwner ? "approved" : "pending", t, isOwner ? t : null, isOwner ? "bootstrap" : null).run();

    await audit(env, { id, email }, "user.register", email, { owner: isOwner }, request);

    if (!isOwner) return json({ ok: true, status: "pending", message: "Pendaftaran diterima. Tunggu persetujuan owner." }, 201);
    const token = await createSession(env, id, request);
    return json({ ok: true, status: "approved", user: { id, email, name, role: "owner" } }, 201,
      { "set-cookie": sessionCookie(token) });
  }

  if (p === "/api/auth/login" && method === "POST") {
    const b = await request.json().catch(() => ({}));
    const email = normalizeEmail(b.email);
    const password = String(b.password || "");
    const ip = ipOf(request);

    const rlIp = await hitRate(env, "login|" + ip, 30, 15 * 60_000);
    if (!rlIp.ok) return json({ error: "too_many_requests", retry_after: rlIp.retry }, 429, { "retry-after": String(rlIp.retry) });

    const cap = await verifyTurnstile(env, request, b.captcha);
    if (!cap.ok) return json({ error: cap.error }, 400);

    const rl = await hitLogin(env, ip, email);
    if (rl.blocked) return json({ error: "too_many_attempts", retry_after: rl.retry }, 429, { "retry-after": String(rl.retry) });

    const user = await env.DB.prepare(
      `SELECT id,email,name,role,status,pass_hash,totp_enabled FROM users WHERE email = ?1`
    ).bind(email).first();

    // biaya respons disamakan: email tidak terdaftar tetap menjalankan PBKDF2 penuh
    let ok = false;
    if (user) ok = await verifyPassword(password, user.pass_hash);
    else await hashPassword(password);
    if (!user || !ok) {
      const f = await failLogin(env, rl.key, rl.row);
      await audit(env, null, "login.fail", email, { ip }, request);
      return json({ error: "invalid_credentials", ...f }, 401);
    }

    if (user.status === "pending") return json({ error: "pending_approval" }, 403);
    if (user.status === "rejected") return json({ error: "registration_rejected" }, 403);
    if (user.status === "suspended") return json({ error: "account_suspended" }, 403);

    await clearLogin(env, rl.key);

    if (user.totp_enabled) {
      const ticket = randomToken(24);
      await env.DB.prepare(
        `INSERT INTO login_tickets (token_hash,user_id,created_at,expires_at) VALUES (?1,?2,?3,?4)`
      ).bind(await sha256Hex(ticket), user.id, now(), now() + 5 * 60_000).run();
      await audit(env, user, "login.otp_required", user.email, null, request);
      return json({ ok: true, otp_required: true, ticket });
    }

    const token = await createSession(env, user.id, request);
    await audit(env, user, "login.ok", user.email, null, request);
    return json({ ok: true, user: { id: user.id, email: user.email, name: user.name, role: user.role } }, 200,
      { "set-cookie": sessionCookie(token) });
  }

  /* ---------- 2FA opsional (TOTP) ---------- */
  if (p === "/api/auth/2fa" && method === "GET") {
    const me = await currentUser(env, request);
    if (!me) return json({ error: "unauthorized" }, 401);
    const row = await env.DB.prepare(`SELECT totp_enabled FROM users WHERE id = ?1`).bind(me.id).first();
    const left = await env.DB.prepare(
      `SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ?1 AND used_at IS NULL`
    ).bind(me.id).first();
    return json({ enabled: !!(row && row.totp_enabled), recovery_left: left ? left.n : 0 });
  }

  if (p === "/api/auth/2fa/setup" && method === "POST") {
    const me = await currentUser(env, request);
    if (!me) return json({ error: "unauthorized" }, 401);
    if (me.authType !== "session") return json({ error: "session_required" }, 403);
    const rl = await hitRate(env, "2fa-set|" + me.id, 10, 15 * 60_000);
    if (!rl.ok) return json({ error: "too_many_requests", retry_after: rl.retry }, 429);
    const secret = newSecret();
    await env.DB.prepare(`UPDATE users SET totp_secret = ?2, totp_enabled = 0 WHERE id = ?1`)
      .bind(me.id, secret).run();
    await audit(env, me, "2fa.setup", me.email, null, request);
    return json({ ok: true, secret, otpauth: otpauthUri(secret, me.email) });
  }

  if (p === "/api/auth/2fa/enable" && method === "POST") {
    const me = await currentUser(env, request);
    if (!me) return json({ error: "unauthorized" }, 401);
    if (me.authType !== "session") return json({ error: "session_required" }, 403);
    const rl = await hitRate(env, "2fa-en|" + me.id, 10, 15 * 60_000);
    if (!rl.ok) return json({ error: "too_many_requests", retry_after: rl.retry }, 429);
    const b = await request.json().catch(() => ({}));
    const row = await env.DB.prepare(`SELECT totp_secret FROM users WHERE id = ?1`).bind(me.id).first();
    if (!row || !row.totp_secret) return json({ error: "setup_required" }, 400);
    const cleanCode = String(b.code || "").replace(/\D/g, "");
    if (!(await verifyTotp(row.totp_secret, cleanCode))) return json({ error: "invalid_code" }, 400);
    const once = await hitRate(env, `totp-used|${me.id}|${cleanCode}`, 1, 90_000);
    if (!once.ok) return json({ error: "invalid_code" }, 400);

    const codes = recoveryCodes(8);
    await env.DB.prepare(`DELETE FROM recovery_codes WHERE user_id = ?1`).bind(me.id).run();
    for (const c of codes) {
      await env.DB.prepare(
        `INSERT INTO recovery_codes (id,user_id,code_hash) VALUES (?1,?2,?3)`
      ).bind(crypto.randomUUID(), me.id, await sha256Hex(me.id + "|" + c.replace("-", "").toLowerCase())).run();
    }
    await env.DB.prepare(`UPDATE users SET totp_enabled = 1 WHERE id = ?1`).bind(me.id).run();
    await audit(env, me, "2fa.enable", me.email, null, request);
    return json({ ok: true, recovery_codes: codes, note: "Simpan kode cadangan; hanya tampil sekali." });
  }

  if (p === "/api/auth/2fa/disable" && method === "POST") {
    const me = await currentUser(env, request);
    if (!me) return json({ error: "unauthorized" }, 401);
    if (me.authType !== "session") return json({ error: "session_required" }, 403);
    const rl = await hitRate(env, "2fa-dis|" + me.id, 10, 15 * 60_000);
    if (!rl.ok) return json({ error: "too_many_requests", retry_after: rl.retry }, 429);
    const b = await request.json().catch(() => ({}));
    const row = await env.DB.prepare(`SELECT pass_hash FROM users WHERE id = ?1`).bind(me.id).first();
    if (!row || !(await verifyPassword(String(b.password || ""), row.pass_hash)))
      return json({ error: "invalid_credentials" }, 401);
    await env.DB.batch([
      env.DB.prepare(`UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?1`).bind(me.id),
      env.DB.prepare(`DELETE FROM recovery_codes WHERE user_id = ?1`).bind(me.id),
    ]);
    await audit(env, me, "2fa.disable", me.email, null, request);
    return json({ ok: true });
  }

  // langkah kedua login (publik, butuh ticket)
  if (p === "/api/auth/2fa/verify" && method === "POST") {
    const rl = await hitRate(env, "2fa|" + ipOf(request), 20, 15 * 60_000);
    if (!rl.ok) return json({ error: "too_many_requests", retry_after: rl.retry }, 429);
    const b = await request.json().catch(() => ({}));
    const ticket = String(b.ticket || "");
    const code = String(b.code || "").trim();
    if (!ticket || !code) return json({ error: "ticket_and_code_required" }, 400);

    const tHash = await sha256Hex(ticket);
    const t = await env.DB.prepare(
      `SELECT token_hash, user_id, expires_at, used_at FROM login_tickets WHERE token_hash = ?1`
    ).bind(tHash).first();
    if (!t) return json({ error: "invalid_ticket" }, 400);
    if (t.used_at) return json({ error: "ticket_used" }, 400);
    if (t.expires_at <= now()) return json({ error: "ticket_expired" }, 400);

    const u = await env.DB.prepare(
      `SELECT id,email,name,role,status,totp_secret,totp_enabled FROM users WHERE id = ?1`
    ).bind(t.user_id).first();
    if (!u || u.status !== "approved") return json({ error: "account_unavailable" }, 403);

    const cleanCode = code.replace(/\D/g, "");
    let passed = u.totp_secret ? await verifyTotp(u.totp_secret, cleanCode) : false;
    if (passed) {
      const once = await hitRate(env, `totp-used|${u.id}|${cleanCode}`, 1, 90_000);
      if (!once.ok) passed = false;
    }
    if (!passed) {
      const rc = await env.DB.prepare(
        `SELECT id FROM recovery_codes WHERE user_id = ?1 AND code_hash = ?2 AND used_at IS NULL`
      ).bind(u.id, await sha256Hex(u.id + "|" + code.replace(/-/g, "").toLowerCase())).first();
      if (rc) {
        await env.DB.prepare(`UPDATE recovery_codes SET used_at = ?2 WHERE id = ?1`).bind(rc.id, now()).run();
        passed = true;
      }
    }
    if (!passed) return json({ error: "invalid_code" }, 401);

    await env.DB.prepare(`UPDATE login_tickets SET used_at = ?2 WHERE token_hash = ?1`).bind(tHash, now()).run();
    const token = await createSession(env, u.id, request);
    await audit(env, u, "login.2fa_ok", u.email, null, request);
    return json({
      ok: true,
      user: { id: u.id, email: u.email, name: u.name, role: u.role, totp: true },
    }, 200, { "set-cookie": sessionCookie(token) });
  }
  if (p === "/api/auth/logout" && method === "POST") {
    await destroySession(env, request);
    return json({ ok: true }, 200, { "set-cookie": clearCookie() });
  }

  if (p === "/api/auth/forgot" && method === "POST") {
    const rlIp = await hitRate(env, "forgot|" + ipOf(request), 3, 3600_000);
    if (!rlIp.ok) return json({ error: "too_many_requests", retry_after: rlIp.retry }, 429, { "retry-after": String(rlIp.retry) });
    const b = await request.json().catch(() => ({}));
    const cap = await verifyTurnstile(env, request, b.captcha);
    if (!cap.ok) return json({ error: cap.error }, 400);

    const email = normalizeEmail(b.email);
    const user = await env.DB.prepare(`SELECT id,email FROM users WHERE email = ?1`).bind(email).first();
    if (user) {
      const open = await env.DB.prepare(
        `SELECT id FROM password_resets WHERE user_id = ?1 AND used_at IS NULL AND token_hash IS NULL`
      ).bind(user.id).first();
      if (!open) {
        await env.DB.prepare(
          `INSERT INTO password_resets (id,user_id,token_hash,source,created_at,expires_at,used_at)
           VALUES (?1,?2,NULL,'self',?3,0,NULL)`
        ).bind(crypto.randomUUID(), user.id, now()).run();
      }
      await audit(env, null, "password.forgot", email, null, request);
    }
    return json({ ok: true, message: "Permintaan dikirim. Owner akan mengirim tautan reset." });
  }

  if (p === "/api/auth/reset" && method === "POST") {
    const rlIp = await hitRate(env, "reset|" + ipOf(request), 10, 15 * 60_000);
    if (!rlIp.ok) return json({ error: "too_many_requests", retry_after: rlIp.retry }, 429, { "retry-after": String(rlIp.retry) });
    const b = await request.json().catch(() => ({}));
    const token = String(b.token || "").trim();
    const next = String(b.next || "");
    if (!token) return json({ error: "token_required" }, 400);
    if (next.length < 8) return json({ error: "password_too_short", min: 8 }, 400);

    const row = await env.DB.prepare(
      `SELECT id,user_id,expires_at,used_at FROM password_resets WHERE token_hash = ?1`
    ).bind(await sha256Hex(token)).first();
    if (!row) return json({ error: "invalid_token" }, 400);
    if (row.used_at) return json({ error: "token_used" }, 400);
    if (row.expires_at <= now()) return json({ error: "token_expired" }, 400);

    const t = now();
    await env.DB.batch([
      env.DB.prepare(`UPDATE users SET pass_hash = ?2 WHERE id = ?1`).bind(row.user_id, await hashPassword(next)),
      env.DB.prepare(`UPDATE password_resets SET used_at = ?2 WHERE id = ?1`).bind(row.id, t),
      env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?1`).bind(row.user_id),
      env.DB.prepare(`DELETE FROM login_tickets WHERE user_id = ?1`).bind(row.user_id),
      env.DB.prepare(`UPDATE api_keys SET revoked_at = ?2 WHERE user_id = ?1 AND revoked_at IS NULL`).bind(row.user_id, t),
      env.DB.prepare(`DELETE FROM password_resets WHERE user_id = ?1 AND used_at IS NULL`).bind(row.user_id),
    ]);
    await audit(env, null, "password.reset", null, { user_id: row.user_id }, request);
    return json({ ok: true });
  }

  if (p === "/api/auth/password" && method === "POST") {
    const me = await currentUser(env, request);
    if (!me) return json({ error: "unauthorized" }, 401);
    if (me.authType !== "session") return json({ error: "session_required" }, 403);
    const rl = await hitRate(env, "pw|" + me.id, 10, 15 * 60_000);
    if (!rl.ok) return json({ error: "too_many_requests", retry_after: rl.retry }, 429);
    const b = await request.json().catch(() => ({}));
    const next = String(b.next || "");
    if (next.length < 8) return json({ error: "password_too_short", min: 8 }, 400);
    const row = await env.DB.prepare(`SELECT pass_hash FROM users WHERE id = ?1`).bind(me.id).first();
    if (!row || !(await verifyPassword(String(b.current || ""), row.pass_hash)))
      return json({ error: "invalid_credentials" }, 401);

    await env.DB.batch([
      env.DB.prepare(`UPDATE users SET pass_hash = ?2 WHERE id = ?1`).bind(me.id, await hashPassword(next)),
      env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?1`).bind(me.id),
      env.DB.prepare(`DELETE FROM login_tickets WHERE user_id = ?1`).bind(me.id),
    ]);
    await audit(env, me, "password.change", me.email, null, request);
    return json({ ok: true }, 200, { "set-cookie": sessionCookie(await createSession(env, me.id, request)) });
  }

  return json({ error: "not_found" }, 404);
}

/* ---------------- admin ---------------- */


async function handleAdmin(request, env, url, user) {
  const p = url.pathname, method = request.method;
  const staff = isStaff(user);
  if (!staff) return json({ error: "unauthorized" }, 401);
  const hasSession = user.authType === "session";

  if (p === "/api/admin/users" && method === "GET") {
    return json({
      users: await listUsers(env, url.searchParams.get("status") || null),
      counts: {
        pending: await countUsers(env, "pending"),
        approved: await countUsers(env, "approved"),
        total: await countUsers(env),
      },
    });
  }

  if (p === "/api/admin/users" && method === "POST") {
    if (!hasSession) return json({ error: "session_required" }, 403);
    const b = await request.json().catch(() => ({}));
    const email = normalizeEmail(b.email);
    const password = String(b.password || "");
    const name = (b.name || "").trim().slice(0, 60) || null;
    const allowedRoles = user.role === "owner" ? ["member", "vip", "admin"] : ["member"];
    if ((b.role === "admin" || b.role === "vip") && user.role !== "owner")
      return json({ error: "owner_required_for_role" }, 403);
    const role = allowedRoles.includes(b.role) ? b.role : "member";
    if (!EMAIL_RE.test(email)) return json({ error: "invalid_email" }, 400);
    if (password.length < 8) return json({ error: "password_too_short", min: 8 }, 400);
    
    if (await env.DB.prepare(`SELECT id FROM users WHERE email = ?1`).bind(email).first())
      return json({ error: "email_taken" }, 409);

    const id = crypto.randomUUID(), t = now();
    await env.DB.prepare(
      `INSERT INTO users (id,email,name,pass_hash,role,status,created_at,approved_at,approved_by)
       VALUES (?1,?2,?3,?4,?5,'approved',?6,?6,?7)`
    ).bind(id, email, name, await hashPassword(password), role, t, user.id).run();
    await audit(env, user, "user.create", email, { role }, request);
    return json({ ok: true, user: await getUserById(env, id) }, 201);
  }

  const mUser = p.match(/^\/api\/admin\/users\/([^/]+)$/);
  if (mUser && method === "PATCH") {
    if (!hasSession) return json({ error: "session_required" }, 403);
    const id = decodeURIComponent(mUser[1]);
    const b = await request.json().catch(() => ({}));
    const target = await getUserById(env, id);
    if (!target) return json({ error: "user_not_found" }, 404);
    if (!canManage(user, target)) return json({ error: "not_permitted", reason: "target_rank_higher_or_equal" }, 403);
    if (target.id === user.id && b.status && b.status !== "approved") return json({ error: "cannot_change_own_status" }, 400);

    const allowed = ["pending", "approved", "rejected", "suspended"];
    const status = b.status && allowed.includes(b.status) ? b.status : null;
    let role = null;
    if (b.role && ["admin", "vip", "member"].includes(b.role)) {
      if (user.role !== "owner") return json({ error: "owner_required_for_role" }, 403);
      role = b.role;
    }
    if (!status && !role) return json({ error: "nothing_to_update" }, 400);

    await env.DB.prepare(
      `UPDATE users SET status = COALESCE(?2,status), role = COALESCE(?3,role),
         approved_at = CASE WHEN ?2='approved' THEN ?4 ELSE approved_at END,
         approved_by = CASE WHEN ?2='approved' THEN ?5 ELSE approved_by END
       WHERE id = ?1`
    ).bind(id, status, role, now(), user.id).run();

    if (status && status !== "approved") {
      await env.DB.batch([
        env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?1`).bind(id),
        env.DB.prepare(`DELETE FROM login_tickets WHERE user_id = ?1`).bind(id),
        env.DB.prepare(`UPDATE api_keys SET revoked_at = ?2 WHERE user_id = ?1 AND revoked_at IS NULL`).bind(id, now()),
      ]);
    }
    await audit(env, user, "user.update", target.email, { status, role }, request);
    return json({ ok: true, user: await getUserById(env, id) });
  }

  // hapus akun (owner: semua bukan owner; admin: member/vip)
  if (mUser && method === "DELETE") {
    if (!hasSession) return json({ error: "session_required" }, 403);
    const id = decodeURIComponent(mUser[1]);
    const target = await getUserById(env, id);
    if (!target) return json({ error: "user_not_found" }, 404);
    if (target.id === user.id) return json({ error: "cannot_delete_self" }, 400);
    if (target.role === "owner") return json({ error: "cannot_delete_owner" }, 403);
    if (!canManage(user, target)) return json({ error: "not_permitted", reason: "target_rank_higher_or_equal" }, 403);

    const { results: boxes } = await env.DB.prepare(`SELECT address FROM inboxes WHERE user_id = ?1`).bind(id).all();
    for (const b of boxes || []) {
      const { results: msgs } = await env.DB.prepare(`SELECT raw_key FROM messages WHERE inbox = ?1`).bind(b.address).all();
      for (const m of msgs || []) if (m.raw_key) await fileDel(env, m.raw_key);
      const { results: atts } = await env.DB.prepare(`SELECT r2_key FROM attachments WHERE inbox = ?1`).bind(b.address).all();
      for (const a of atts || []) if (a.r2_key) await fileDel(env, a.r2_key);
    }

    await env.DB.batch([
      env.DB.prepare(`DELETE FROM webhooks WHERE address IN (SELECT address FROM inboxes WHERE user_id = ?1)`).bind(id),
      env.DB.prepare(`DELETE FROM attachments WHERE inbox IN (SELECT address FROM inboxes WHERE user_id = ?1)`).bind(id),
      env.DB.prepare(`DELETE FROM messages WHERE inbox IN (SELECT address FROM inboxes WHERE user_id = ?1)`).bind(id),
      env.DB.prepare(`DELETE FROM inboxes WHERE user_id = ?1`).bind(id),
      env.DB.prepare(`DELETE FROM recovery_codes WHERE user_id = ?1`).bind(id),
      env.DB.prepare(`DELETE FROM api_keys WHERE user_id = ?1`).bind(id),
      env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?1`).bind(id),
      env.DB.prepare(`DELETE FROM password_resets WHERE user_id = ?1`).bind(id),
      env.DB.prepare(`DELETE FROM login_tickets WHERE user_id = ?1`).bind(id),
      env.DB.prepare(`DELETE FROM users WHERE id = ?1`).bind(id),
    ]);
    await audit(env, user, "user.delete", target.email, { role: target.role }, request);
    return json({ ok: true, deleted: target.email });
  }
  if (p === "/api/admin/resets" && method === "GET") {
    const { results } = await env.DB.prepare(
      `SELECT r.id, r.user_id, r.source, r.created_at, u.email, u.name
         FROM password_resets r JOIN users u ON u.id = r.user_id
        WHERE r.used_at IS NULL AND r.token_hash IS NULL ORDER BY r.created_at DESC LIMIT 100`
    ).all();
    return json({ requests: results || [] });
  }

  // inbox milik satu user (owner/admin) — untuk fitur "intip"
  const mUserBoxes = p.match(/^\/api\/admin\/users\/([^/]+)\/inboxes$/);
  if (mUserBoxes && method === "GET") {
    if (!hasSession) return json({ error: "session_required" }, 403);
    const target = await getUserById(env, decodeURIComponent(mUserBoxes[1]));
    if (!target) return json({ error: "user_not_found" }, 404);
    if (target.id !== user.id && !canManage(user, target))
      return json({ error: "not_permitted", reason: "target_rank_higher_or_equal" }, 403);
    const { results } = await env.DB.prepare(
      `SELECT i.address, i.domain, i.created_at, i.expires_at, i.pinned, i.note,
              (SELECT COUNT(*) FROM messages m WHERE m.inbox = i.address AND (m.expires_at > ?2 OR i.pinned = 1)) AS messages
         FROM inboxes i WHERE i.user_id = ?1 AND (i.expires_at > ?2 OR i.pinned = 1)
        ORDER BY i.pinned DESC, i.created_at DESC LIMIT 200`
    ).bind(target.id, now()).all();
    await audit(env, user, "user.peek", target.email, null, request);
    return json({
      user: { id: target.id, email: target.email, role: target.role, status: target.status },
      inboxes: results || [],
    });
  }
  const mReset = p.match(/^\/api\/admin\/users\/([^/]+)\/reset$/);
  if (mReset && method === "POST") {
    if (!hasSession) return json({ error: "session_required" }, 403);
    const id = decodeURIComponent(mReset[1]);
    const target = await getUserById(env, id);
    if (!target) return json({ error: "user_not_found" }, 404);
    if (!canManage(user, target)) return json({ error: "not_permitted", reason: "target_rank_higher_or_equal" }, 403);

    const token = randomToken(24);
    const t = now(), exp = t + 30 * 60 * 1000;
    await env.DB.prepare(`DELETE FROM password_resets WHERE user_id = ?1 AND used_at IS NULL`).bind(id).run();
    await env.DB.prepare(
      `INSERT INTO password_resets (id,user_id,token_hash,source,created_at,expires_at,used_at)
       VALUES (?1,?2,?3,'admin',?4,?5,NULL)`
    ).bind(crypto.randomUUID(), id, await sha256Hex(token), t, exp).run();
    await audit(env, user, "user.reset_link", target.email, null, request);

    return json({
      ok: true, token,
      link: `${new URL(request.url).origin}/#/reset?token=${encodeURIComponent(token)}`,
      expires_at: exp, email: target.email,
    });
  }

  /* --- inject (tes pipeline email) --- */
  if (p === "/api/admin/inject" && method === "POST") {
    if (!hasSession) return json({ error: "session_required" }, 403);
    const b = await request.json().catch(() => ({}));
    const to = normalizeEmail(b.to);
    if (!EMAIL_RE.test(to)) return json({ error: "invalid_email" }, 400);
    if (!b.raw) return json({ error: "raw_required" }, 400);
    const domain = to.split("@")[1];
    if (!(await getDomain(env, domain))) return json({ error: "domain_unknown" }, 400);
    if (!(await inboxRow(env, to))) await ensureInbox(env, to, domain, user.id);
    const enc = new TextEncoder().encode(String(b.raw));
    if (enc.length > maxMailBytes(env))
      return json({ error: "message_too_large", max_bytes: maxMailBytes(env) }, 413);
    const id = await ingest(env, to, enc);
    await audit(env, user, "message.inject", to, null, request);
    return json({ ok: true, id, address: to }, 201);
  }
  /* --- semua inbox (owner/admin) --- */
  if (p === "/api/admin/inboxes" && method === "GET") {
    if (!hasSession) return json({ error: "session_required" }, 403);
    const limit = Math.min(parseInt(url.searchParams.get("limit") || "200", 10) || 200, 500);
    const dom = normalizeDomain(url.searchParams.get("domain") || "");
    let sql = `SELECT i.address, i.domain, i.created_at, i.expires_at, i.pinned, i.user_id, i.note,
                      u.email AS owner_email, u.role AS owner_role,
                      (SELECT COUNT(*) FROM messages m WHERE m.inbox = i.address AND (m.expires_at > ?1 OR i.pinned = 1)) AS messages
                 FROM inboxes i LEFT JOIN users u ON u.id = i.user_id
                WHERE (i.expires_at > ?1 OR i.pinned = 1)`;
    const args = [now()];
    if (user.role === "admin") sql += ` AND (i.user_id IS NULL OR u.role IN ('vip','member'))`;
    if (dom) { sql += ` AND i.domain = ?${args.length + 1}`; args.push(dom); }
    sql += ` ORDER BY i.created_at DESC LIMIT ?${args.length + 1}`;
    args.push(limit);
    const { results } = await env.DB.prepare(sql).bind(...args).all();
    return json({ inboxes: results || [] });
  }

  /* --- domains --- */
  if (p === "/api/admin/domains" && method === "GET") return json({ domains: await listDomains(env, false) });

  if (p === "/api/admin/domains" && method === "POST") {
    if (!hasSession) return json({ error: "session_required" }, 403);
    const b = await request.json().catch(() => ({}));
    const domain = normalizeDomain(b.domain);
    if (!domain || !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) return json({ error: "invalid_domain" }, 400);
    if (b.is_default) await env.DB.prepare(`UPDATE domains SET is_default = 0`).run();
    await env.DB.prepare(
      `INSERT INTO domains (domain,is_active,is_default,label,is_premium,created_at) VALUES (?1,1,?2,?3,?5,?4)
       ON CONFLICT(domain) DO UPDATE SET is_active = 1, is_default = excluded.is_default,
         label = COALESCE(excluded.label, domains.label), is_premium = excluded.is_premium`
    ).bind(domain, b.is_default ? 1 : 0, b.label || null, now(), b.is_premium ? 1 : 0).run();
    await audit(env, user, "domain.add", domain, { is_default: !!b.is_default }, request);
    return json({ ok: true, domain });
  }

  const mDom = p.match(/^\/api\/admin\/domains\/([^/]+)$/);
  if (mDom && method === "PATCH") {
    if (!hasSession) return json({ error: "session_required" }, 403);
    const domain = normalizeDomain(decodeURIComponent(mDom[1]));
    const b = await request.json().catch(() => ({}));
    if (!(await getDomain(env, domain))) return json({ error: "domain_not_found" }, 404);
    if (b.is_default) await env.DB.prepare(`UPDATE domains SET is_default = 0`).run();
    await env.DB.prepare(
      `UPDATE domains SET is_active = COALESCE(?2,is_active), is_default = COALESCE(?3,is_default),
         label = COALESCE(?4,label), is_premium = COALESCE(?5,is_premium) WHERE domain = ?1`
    ).bind(domain,
      b.is_active === undefined ? null : b.is_active ? 1 : 0,
      b.is_default === undefined ? null : b.is_default ? 1 : 0,
      b.label ?? null,
      b.is_premium === undefined ? null : b.is_premium ? 1 : 0).run();
    await audit(env, user, "domain.update", domain, b, request);
    return json({ ok: true, domain });
  }

  if (mDom && method === "DELETE") {
    if (!hasSession) return json({ error: "session_required" }, 403);
    const domain = normalizeDomain(decodeURIComponent(mDom[1]));
    await env.DB.prepare(`UPDATE domains SET is_active = 0, is_default = 0 WHERE domain = ?1`).bind(domain).run();
    await audit(env, user, "domain.disable", domain, null, request);
    return json({ ok: true, domain });
  }

  if (p === "/api/admin/audit" && method === "GET") {
    const limit = Math.min(parseInt(url.searchParams.get("limit") || "100", 10) || 100, 500);
    const { results } = await env.DB.prepare(
      `SELECT id, actor_email, action, target, meta, ip, created_at FROM audit_log ORDER BY created_at DESC LIMIT ?1`
    ).bind(limit).all();
    return json({ entries: results || [] });
  }

  if (p === "/api/admin/log" && method === "GET") {
    const q = (url.searchParams.get("address") || "").trim().toLowerCase();
    const limit = Math.min(parseInt(url.searchParams.get("limit") || "200", 10) || 200, 500);
    const sel = `SELECT id, inbox, domain, peer, peer_name, subject, message_id, first_at FROM inbox_log`;
    const rows = q
      ? await env.DB.prepare(sel + ` WHERE inbox = ?1 ORDER BY first_at DESC LIMIT ?2`).bind(q, limit).all()
      : await env.DB.prepare(sel + ` ORDER BY first_at DESC LIMIT ?1`).bind(limit).all();
    return json({ log: rows.results || [] });
  }

  /* --- ringkasan statistik (dashboard) --- */
  if (p === "/api/admin/stats" && method === "GET") {
    /* by_day: gabungan inbox+email per hari agar grafik frontend terisi */
    const days = Math.min(Math.max(parseInt(url.searchParams.get("days") || "14", 10) || 14, 7), 30);
    const since = now() - days * 86400_000;
    const [inbox, mail, top, tot] = await Promise.all([
      env.DB.prepare(`SELECT date(created_at/1000,'unixepoch') AS d, COUNT(*) AS n
                        FROM inboxes WHERE created_at >= ?1 GROUP BY d ORDER BY d`).bind(since).all(),
      env.DB.prepare(`SELECT date(received_at/1000,'unixepoch') AS d, COUNT(*) AS n
                        FROM messages WHERE received_at >= ?1 GROUP BY d ORDER BY d`).bind(since).all(),
      env.DB.prepare(`SELECT domain, COUNT(*) AS inboxes FROM inboxes
                       WHERE (expires_at > ?1 OR pinned = 1) GROUP BY domain ORDER BY inboxes DESC LIMIT 8`).bind(now()).all(),
      env.DB.prepare(`SELECT (SELECT COUNT(*) FROM inboxes WHERE expires_at > ?1 OR pinned = 1) AS inboxes,
                             (SELECT COUNT(*) FROM messages m LEFT JOIN inboxes i ON i.address = m.inbox WHERE m.expires_at > ?1 OR i.pinned = 1) AS messages,
                             (SELECT COUNT(*) FROM users) AS users,
                             (SELECT COUNT(*) FROM users WHERE status = 'pending') AS pending`).bind(now()).first(),
    ]);
    const inboxRows = inbox.results || [];
    const mailRows = mail.results || [];
    const byDay = new Map();
    for (const r of inboxRows) byDay.set(r.d, { day: r.d, inboxes: r.n, messages: 0 });
    for (const r of mailRows) {
      const cur = byDay.get(r.d) || { day: r.d, inboxes: 0, messages: 0 };
      cur.messages = r.n;
      byDay.set(r.d, cur);
    }
    const by_day = [...byDay.values()].sort((a, b) => String(a.day).localeCompare(String(b.day)));
    return json({
      days,
      inboxes: inboxRows,
      messages: mailRows,
      by_day,
      top_domains: top.results || [],
      totals: tot || {},
    });
  }

  /* --- pengumuman (banner) --- */
  if (p === "/api/admin/announcements" && method === "GET") {
    const { results } = await env.DB.prepare(
      `SELECT id, message, level, active, created_at FROM announcements ORDER BY created_at DESC LIMIT 50`
    ).all();
    return json({ announcements: results || [] });
  }
  if (p === "/api/admin/announcements" && method === "POST") {
    if (!hasSession) return json({ error: "session_required" }, 403);
    const b = await request.json().catch(() => ({}));
    const message = String(b.message || "").trim().slice(0, 300);
    if (!message) return json({ error: "message_required" }, 400);
    const level = ["info", "warning", "critical"].includes(b.level) ? b.level : "info";
    if (b.active !== false) await env.DB.prepare(`UPDATE announcements SET active = 0`).run();
    const id = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO announcements (id,message,level,active,created_by,created_at) VALUES (?1,?2,?3,?4,?5,?6)`
    ).bind(id, message, level, b.active === false ? 0 : 1, user.id, now()).run();
    await audit(env, user, "announcement.create", id, { level }, request);
    return json({ ok: true, id }, 201);
  }
  const mAnn = p.match(/^\/api\/admin\/announcements\/([^/]+)$/);
  if (mAnn && method === "PATCH") {
    if (!hasSession) return json({ error: "session_required" }, 403);
    const id = decodeURIComponent(mAnn[1]);
    const b = await request.json().catch(() => ({}));
    if (b.active === true) await env.DB.prepare(`UPDATE announcements SET active = 0`).run();
    await env.DB.prepare(`UPDATE announcements SET active = COALESCE(?2,active) WHERE id = ?1`)
      .bind(id, b.active === undefined ? null : (b.active ? 1 : 0)).run();
    await audit(env, user, "announcement.update", id, { active: b.active }, request);
    return json({ ok: true });
  }
  if (mAnn && method === "DELETE") {
    if (!hasSession) return json({ error: "session_required" }, 403);
    const id = decodeURIComponent(mAnn[1]);
    await env.DB.prepare(`DELETE FROM announcements WHERE id = ?1`).bind(id).run();
    await audit(env, user, "announcement.delete", id, null, request);
    return json({ ok: true });
  }

  return json({ error: "admin_route_not_found" }, 404);
}

/* ---------------- SSE ---------------- */
async function handleEvents(request, env, url, user) {
  const rl = await hitRate(env, "sse|" + ipOf(request), 60, 5 * 60_000);
  if (!rl.ok) return json({ error: "too_many_requests", retry_after: rl.retry }, 429);
  const address = (url.searchParams.get("address") || "").toLowerCase();
  const box = await inboxRow(env, address);
  if (!box) return json({ error: "inbox_not_found" }, 404);
  if (!(await canSee(env, user, box))) return json({ error: "not_found" }, 404);

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    start(controller) {
      let ticks = 0;
      let closed = false;
      const send = (obj) => {
        if (closed) return;
        try { controller.enqueue(encoder.encode(`data: ${JSON.stringify(obj)}\n\n`)); } catch { closed = true; }
      };
      const finish = () => {
        if (closed) return;
        closed = true;
        clearInterval(timer);
        try { controller.close(); } catch {}
      };
      send({ type: "open", address });

      const isPinned = box.pinned === 1;
      let prevSig = "";
      const timer = setInterval(async () => {
        ticks++;
        try {
          const stmt = isPinned
            ? env.DB.prepare(`SELECT id, received_at FROM messages WHERE inbox = ?1 ORDER BY received_at DESC LIMIT 200`).bind(address)
            : env.DB.prepare(`SELECT id, received_at FROM messages WHERE inbox = ?1 AND expires_at > ?2 ORDER BY received_at DESC LIMIT 200`).bind(address, Date.now());
          const { results } = await stmt.all();
          const rows = results || [];
          const latest = rows[0] || null;
          const sig = `${rows.length}:${latest ? latest.id : ""}`;
          if (sig !== prevSig) {
            prevSig = sig;
            send({ type: "state", count: rows.length, latest });
          } else {
            send({ type: "ping" });
          }
        } catch {
          send({ type: "ping" });
        }
        if (ticks >= 6) finish();
      }, 3000);

      request.signal?.addEventListener?.("abort", finish);
    },
  });

  return new Response(stream, {
    headers: {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-store",
      "x-accel-buffering": "no",
      "connection": "keep-alive",
    },
  });
}

/* ---------------- member ---------------- */
async function handleApi(request, env, url, user) {
  const p = url.pathname, method = request.method;

if (p === "/api/health" && method === "GET") {
    return json({ ok: true, time: now() });
  }
  // pengumuman publik: tampil juga untuk tamu di layar login
  if (p === "/api/announcement" && method === "GET") {
    const row = await env.DB.prepare(
      `SELECT id, message, level, created_at FROM announcements WHERE active = 1 ORDER BY created_at DESC LIMIT 1`
    ).first();
    return json({ announcement: row || null });
  }
  if (p.startsWith("/api/auth/")) return handleAuth(request, env, url);
  if (p.startsWith("/api/admin/")) return handleAdmin(request, env, url, user);

  if (!user) return json({ error: "unauthorized" }, 401);
  /* domain list hanya untuk sesi terautentikasi (tidak boleh bocor ke publik) */
if (p === "/api/domains" && method === "GET") return json({ domains: await listDomains(env, true) });

  /* --- api keys --- */
  if (p === "/api/keys" && method === "GET") {
    const { results } = await env.DB.prepare(
      `SELECT id, name, prefix, created_at, last_used, revoked_at FROM api_keys
        WHERE user_id = ?1 ORDER BY created_at DESC`
    ).bind(user.id).all();
    return json({ keys: results || [] });
  }
  if (p === "/api/keys" && method === "POST") {
    if (user.authType !== "session") return json({ error: "session_required" }, 403);
    const b = await request.json().catch(() => ({}));
    const count = await env.DB.prepare(
      `SELECT COUNT(*) AS n FROM api_keys WHERE user_id = ?1 AND revoked_at IS NULL`
    ).bind(user.id).first();
    if ((count ? count.n : 0) >= 5) return json({ error: "key_limit_reached", max: 5 }, 400);

    const raw = "mn_" + randomToken(32);
    const id = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO api_keys (id,user_id,name,key_hash,prefix,created_at) VALUES (?1,?2,?3,?4,?5,?6)`
    ).bind(id, user.id, (b.name || "").trim().slice(0, 40) || "kunci", await sha256Hex(raw), raw.slice(0, 11), now()).run();
    await audit(env, user, "key.create", raw.slice(0, 11), null, request);
    return json({ ok: true, id, key: raw, note: "Simpan sekarang, tidak ditampilkan lagi." }, 201);
  }
  const mKey = p.match(/^\/api\/keys\/([^/]+)$/);
  if (mKey && method === "DELETE") {
    if (user.authType !== "session") return json({ error: "session_required" }, 403);
    const id = decodeURIComponent(mKey[1]);
    const purge = url.searchParams.get("purge") === "1";
    if (purge) {
      await env.DB.prepare(`DELETE FROM api_keys WHERE id = ?1 AND user_id = ?2 AND revoked_at IS NOT NULL`)
        .bind(id, user.id).run();
      await audit(env, user, "key.delete", id, null, request);
      return json({ ok: true, deleted: true });
    }
    await env.DB.prepare(`UPDATE api_keys SET revoked_at = ?3 WHERE id = ?1 AND user_id = ?2`)
      .bind(id, user.id, now()).run();
    await audit(env, user, "key.revoke", id, null, request);
    return json({ ok: true });
  }

  /* --- inbox --- */
  if (p === "/api/new" && method === "POST") {
    const qp = await paramsFor(request, url);
    const r = await resolveDomain(env, qp.get("domain"));
    if (r.error) return json(r, r.error === "domain_not_available" ? 400 : 500);
    const dom = await getDomain(env, r.domain);
    if (dom && dom.is_premium && user.role === "member")
      return json({ error: "domain_premium", note: "domain ini khusus VIP ke atas" }, 403);
    const q = await quotaCheck(env, user, r.domain);
    if (q) return json(q, 429);
    const ttl = ttlFor(user, qp.get("ttl"));
    const note = qp.get("note") || null;
    let info = null;
    for (let attempt = 0; attempt < 6; attempt++) {
      const address = `${randLocal()}@${r.domain}`;
      const res = await ensureInbox(env, address, r.domain, user.id, ttl, note);
      if (!res.conflict) { info = res; break; }
    }
    if (!info) return json({ error: "address_collision_retry" }, 409);
    await audit(env, user, "inbox.create", info.address, null, request);
    return json({ ...info, ttl_seconds: Math.round((info.expires_at - info.created_at) / 1000) });
  }

  if (p === "/api/custom" && method === "POST") {
    const qp = await paramsFor(request, url);
    const local = normalizeLocal(qp.get("local"));
    if (!local) return json({ error: "local_part_required" }, 400);
    if (!validLocal(local)) return json({ error: "local_invalid", note: "3-64 karakter, huruf/angka/titik, tidak diawali/diakhiri titik, tanpa titik ganda" }, 400);
    if (!isStaff(user) && isReservedLocal(local))
      return json({ error: "local_reserved", note: "nama alamat ini dicadangkan" }, 400);
    const r = await resolveDomain(env, qp.get("domain"));
    if (r.error) return json(r, r.error === "domain_not_available" ? 400 : 500);
    const dom = await getDomain(env, r.domain);
    if (dom && dom.is_premium && user.role === "member")
      return json({ error: "domain_premium", note: "domain ini khusus VIP ke atas" }, 403);
    const address = `${local}@${r.domain}`;
    const existingBox = await inboxRow(env, address);
    const alreadyOwnActive = existingBox && existingBox.user_id === user.id && (existingBox.expires_at > now() || existingBox.pinned === 1);
    if (!alreadyOwnActive) {
      const q = await quotaCheck(env, user, r.domain);
      if (q) return json(q, 429);
    }
    const info = await ensureInbox(env, address, r.domain, user.id, ttlFor(user, qp.get("ttl")), qp.get("note") || null);
    if (info.conflict) {
      return json({ error: "address_taken", note: "Alamat ini sedang digunakan oleh pengguna lain." }, 409);
    }
    await audit(env, user, "inbox.create", address, null, request);
    return json({ ...info, ttl_seconds: Math.round((info.expires_at - info.created_at) / 1000) });
  }

  if (p === "/api/my/inboxes" && method === "GET") {
    const { results } = await env.DB.prepare(
      `SELECT i.address, i.domain, i.created_at, i.expires_at, i.pinned, i.note,
              (SELECT COUNT(*) FROM messages m WHERE m.inbox = i.address AND (m.expires_at > ?2 OR i.pinned = 1)) AS messages
         FROM inboxes i WHERE i.user_id = ?1 AND (i.expires_at > ?2 OR i.pinned = 1)
        ORDER BY i.pinned DESC, i.last_seen DESC LIMIT 100`
    ).bind(user.id, now()).all();
return json({ inboxes: results || [] });
  }

  /* --- kosongkan semua pesan di inbox tanpa menghapus alamat --- */
  const mClearMsgs = p.match(/^\/api\/inbox\/([^/]+)\/messages$/);
  if (mClearMsgs && method === "DELETE") {
    const address = decodeURIComponent(mClearMsgs[1]).toLowerCase();
    const box = await inboxRow(env, address);
    if (!box) return json({ error: "inbox_not_found" }, 404);
    const own = box.user_id && box.user_id === user.id;
    if (!own && !isStaff(user)) return json({ error: "forbidden" }, 403);
    const { results: msgs } = await env.DB.prepare(`SELECT raw_key FROM messages WHERE inbox = ?1`).bind(address).all();
    const { results: atts } = await env.DB.prepare(`SELECT r2_key FROM attachments WHERE inbox = ?1`).bind(address).all();
    for (const m of msgs || []) if (m.raw_key) await fileDel(env, m.raw_key);
    for (const a of atts || []) if (a.r2_key) await fileDel(env, a.r2_key);
    await env.DB.batch([
      env.DB.prepare(`DELETE FROM attachments WHERE inbox = ?1`).bind(address),
      env.DB.prepare(`DELETE FROM messages WHERE inbox = ?1`).bind(address),
    ]);
    await audit(env, user, "inbox.clear", address, { deleted: (msgs || []).length }, request);
    return json({ ok: true, address, deleted: (msgs || []).length });
  }

  /* --- export inbox (JSON / CSV / ZIP berisi .eml) --- */
  const mExport = p.match(/^\/api\/inbox\/([^/]+)\/export$/);
  if (mExport && method === "GET") {
    const address = decodeURIComponent(mExport[1]).toLowerCase();
    const box = await inboxRow(env, address);
    if (!box) return json({ error: "inbox_not_found" }, 404);
    if (!(await canSee(env, user, box))) return json({ error: "not_found" }, 404);
    const fmt = (url.searchParams.get("format") || "json").toLowerCase();
    const { results: msgs } = await env.DB.prepare(
      `SELECT m.id, m.from_addr, m.from_name, m.to_addr, m.subject, m.text_body, m.html_body,
              m.raw_size, m.received_at, m.attach_count, m.raw_key
         FROM messages m
         LEFT JOIN inboxes i ON i.address = m.inbox
        WHERE m.inbox = ?1 AND (m.expires_at > ?2 OR i.pinned = 1)
        ORDER BY m.received_at DESC`
    ).bind(address, now()).all();
    const rows = msgs || [];
    await audit(env, user, "inbox.export", address, { format: fmt, count: rows.length }, request);
    const base = address.replace(/[@.]/g, "_");
    const HEADER = ["id", "from", "from_name", "subject", "received_at", "size_bytes", "attachments"];
    const csvLine = (m) => [m.id, m.from_addr, m.from_name, m.subject,
      new Date(m.received_at).toISOString(), m.raw_size, m.attach_count].map(csvCell).join(",");
    if (fmt === "csv") {
      const body = "\uFEFF" + [HEADER.join(",")].concat(rows.map(csvLine)).join("\r\n");
      return new Response(body, {
        headers: { "content-type": "text/csv; charset=utf-8", "content-disposition": `attachment; filename="${base}.csv"`, "cache-control": "no-store" },
      });
    }
    if (fmt === "zip") {
      const files = [
        { name: "messages.csv", bytes: "\uFEFF" + [HEADER.join(",")].concat(rows.map(csvLine)).join("\r\n") },
        { name: "messages.json", bytes: JSON.stringify(rows.map(({ raw_key, ...m }) => ({ ...m, has_eml: !!raw_key })), null, 2) },
      ];
      for (const m of rows) {
        if (!m.raw_key) continue;
        const obj = await fileGet(env, m.raw_key);
        if (!obj) continue;
        const buf = obj.body instanceof Uint8Array
          ? obj.body
          : new Uint8Array(await new Response(obj.body).arrayBuffer());
        files.push({ name: `eml/${m.id}.eml`, bytes: buf });
      }
      return new Response(zipStore(files), {
        headers: { "content-type": "application/zip", "content-disposition": `attachment; filename="${base}.zip"`, "cache-control": "no-store" },
      });
    }
    const pub = rows.map(({ raw_key, ...m }) => ({ ...m, has_eml: !!raw_key }));
    return new Response(JSON.stringify({ address, exported_at: now(), messages: pub }, null, 2), {
      headers: { "content-type": "application/json; charset=utf-8", "content-disposition": `attachment; filename="${base}.json"`, "cache-control": "no-store" },
    });
  }

  /* --- webhook per inbox --- */
  const mWh = p.match(/^\/api\/webhook\/([^/]+)$/);
  if (mWh) {
    const address = decodeURIComponent(mWh[1]).toLowerCase();
    const box = await inboxRow(env, address);
    if (!box) return json({ error: "inbox_not_found" }, 404);
    const own = box.user_id && box.user_id === user.id;
    if (!own && user.role !== "owner") return json({ error: "forbidden" }, 403);
    if (method === "GET") {
      const { results } = await env.DB.prepare(
        `SELECT id, url, active, last_status, last_at, created_at FROM webhooks WHERE address = ?1 ORDER BY created_at DESC`
      ).bind(address).all();
      return json({ webhooks: results || [] });
    }
    if (method === "POST") {
      if (rank(user.role) < 2) return json({ error: "vip_required", note: "webhook hanya untuk VIP ke atas" }, 403);
      const b = await request.json().catch(() => ({}));
      const whUrl = String(b.url || "").trim();
      const selfHost = url.hostname.toLowerCase().replace(/^www\./, "");
      if (!isSafeWebhookUrl(whUrl, selfHost))
        return json({ error: "invalid_url", note: "URL harus http(s) publik, bukan alamat internal" }, 400);
      const whHost = new URL(whUrl).hostname.toLowerCase().replace(/\.$/, "");
      const ownDom = await env.DB.prepare(`SELECT domain FROM domains WHERE domain = ?1 OR ?1 LIKE '%.' || domain LIMIT 1`).bind(whHost).first();
      if (ownDom) return json({ error: "invalid_url", note: "Webhook tidak boleh mengarah ke domain menyurat sendiri" }, 400);
      const cnt = await env.DB.prepare(`SELECT COUNT(*) AS n FROM webhooks WHERE address = ?1 AND active = 1`).bind(address).first();
      if ((cnt ? cnt.n : 0) >= 3) return json({ error: "webhook_limit", max: 3 }, 400);
      const id = crypto.randomUUID(), secret = randomToken(24);
      await env.DB.prepare(`INSERT INTO webhooks (id,address,url,secret,active,created_at) VALUES (?1,?2,?3,?4,1,?5)`)
        .bind(id, address, whUrl, secret, now()).run();
      await audit(env, user, "webhook.create", address, { url: whUrl }, request);
      return json({ ok: true, id, secret, note: "Simpan secret untuk verifikasi signature." }, 201);
    }
    if (method === "DELETE") {
      const whId = (url.searchParams.get("id") || "").trim();
      if (!whId) return json({ error: "id_required" }, 400);
      await env.DB.prepare(`DELETE FROM webhooks WHERE id = ?1 AND address = ?2`).bind(whId, address).run();
      await audit(env, user, "webhook.delete", address, { id: whId }, request);
      return json({ ok: true });
    }
  }

  const mInbox = p.match(/^\/api\/inbox\/([^/]+)$/);
  if (mInbox && method === "GET") {
    const address = decodeURIComponent(mInbox[1]).toLowerCase();
    const box = await inboxRow(env, address);
    if (!box) return json({ error: "inbox_not_found", address }, 404);
    if (!(await canSee(env, user, box))) return json({ error: "not_found" }, 404);
    return json({ address, domain: box.domain, expires_at: box.expires_at, pinned: box.pinned, note: box.note || null, messages: await listMessages(env, address) });
  }

  // owner: semua inbox. admin: inbox vip/member. user: miliknya sendiri.
  if (mInbox && method === "DELETE") {
    const address = decodeURIComponent(mInbox[1]).toLowerCase();
    const box = await inboxRow(env, address);
    if (!box) return json({ error: "inbox_not_found" }, 404);

    const own = box.user_id && box.user_id === user.id;
    let allowed = !!own || user.role === "owner";
    if (!allowed && user.role === "admin") {
      if (!box.user_id) allowed = true;
      else {
        const o = await env.DB.prepare(`SELECT role FROM users WHERE id = ?1`).bind(box.user_id).first();
        allowed = !!o && rank(o.role) < rank("admin");
      }
    }
    if (!allowed) return json({ error: "forbidden" }, 403);

    await purgeInboxContents(env, address);
    await env.DB.prepare(`DELETE FROM inboxes WHERE address = ?1`).bind(address).run();
    await audit(env, user, "inbox.delete", address, { owner: box.user_id }, request);
    return json({ ok: true, address });
  }

  // pin/unpin, extend TTL, atau simpan catatan/label singkat per alamat
  if (mInbox && method === "PATCH") {
    const address = decodeURIComponent(mInbox[1]).toLowerCase();
    const box = await inboxRow(env, address);
    if (!box) return json({ error: "inbox_not_found" }, 404);
    const own = box.user_id && box.user_id === user.id;
    if (!own && !isStaff(user)) return json({ error: "forbidden" }, 403);
    const body = await request.json().catch(() => ({}));

    if (body && body.note !== undefined) {
      const cleanNote = String(body.note || "").trim().slice(0, 120) || null;
      await env.DB.prepare(`UPDATE inboxes SET note = ?2 WHERE address = ?1`).bind(address, cleanNote).run();
      await audit(env, user, "inbox.note", address, { note: cleanNote }, request);
      if (body.ttl === undefined && body.days === undefined && body.pinned === undefined) {
        return json({ ok: true, address, note: cleanNote });
      }
    }

    // Jika alamat sudah kedaluwarsa & tidak di-pin, mengaktifkan kembali (extend/pin) wajib cek kuota member
    const wasActive = box.expires_at > now() || box.pinned === 1;
    if (!wasActive && (body.ttl !== undefined || body.days !== undefined || body.pinned)) {
      const q = await quotaCheck(env, user, box.domain);
      if (q) return json(q, 429);
    }

    // perpanjang masa aktif: member dikunci 7 hari; vip & admin bebas 1 jam-90 hari; owner 1 jam-365 hari
    if (body && (body.ttl !== undefined || body.days !== undefined)) {
      const role = user.role;
      const requested = body.days !== undefined ? Number(body.days) * 86400 : Number(body.ttl);
      let ttl;
      if (role === "member") ttl = TTL_ROLE.member;
      else if (!Number.isFinite(requested) || requested <= 0) ttl = TTL_ROLE[role] || 14 * 86400;
      else ttl = Math.min(Math.max(requested, TTL_MIN), TTL_MAX_ROLE[role] || TTL_MAX);
      const t = now();
      const newExp = Math.max(Number(box.expires_at) || 0, t + ttl * 1000);
      await env.DB.batch([
        env.DB.prepare(`UPDATE inboxes SET expires_at = ?2 WHERE address = ?1`).bind(address, newExp),
        env.DB.prepare(`UPDATE messages SET expires_at = ?2 WHERE inbox = ?1 AND expires_at < ?2`).bind(address, newExp),
        env.DB.prepare(`UPDATE attachments SET expires_at = ?2 WHERE inbox = ?1 AND expires_at < ?2`).bind(address, newExp),
      ]);
      await audit(env, user, "inbox.extend", address, { ttl, expires_at: newExp }, request);
      return json({ ok: true, address, expires_at: newExp, ttl_seconds: ttl });
    }

    const pinned = (body && (body.pinned === true || body.pinned === 1 || body.pinned === "1")) ? 1 : 0;
    await env.DB.prepare(`UPDATE inboxes SET pinned = ?2 WHERE address = ?1`).bind(address, pinned).run();
    await audit(env, user, "inbox.pin", address, { pinned }, request);
    return json({ ok: true, address, pinned });
  }


  if (p === "/api/events" && method === "GET") return handleEvents(request, env, url, user);

  const mMsg = p.match(/^\/api\/message\/([^/]+)\/([^/]+)$/);
  if (mMsg) {
    const address = decodeURIComponent(mMsg[1]).toLowerCase();
    const id = decodeURIComponent(mMsg[2]);
    const box = await inboxRow(env, address);
    if (!box) return json({ error: "inbox_not_found" }, 404);
    if (!(await canSee(env, user, box))) return json({ error: "not_found" }, 404);

    if (method === "GET") {
      const msg = await getMessage(env, address, id);
      if (!msg) return json({ error: "message_not_found" }, 404);
      const { results: atts } = await env.DB.prepare(
        `SELECT id, filename, mime, size FROM attachments WHERE message_id = ?1 AND inbox = ?2`
      ).bind(id, address).all();
      const { raw_key, ...pub } = msg;
      return json({ ...pub, has_eml: !!raw_key, attachments: atts || [] });
    }
    if (method === "DELETE") {
      const msgRow = await env.DB.prepare(`SELECT raw_key FROM messages WHERE id = ?1 AND inbox = ?2`).bind(id, address).first();
      const { results: attRows } = await env.DB.prepare(`SELECT r2_key FROM attachments WHERE message_id = ?1 AND inbox = ?2`).bind(id, address).all();
      if (msgRow && msgRow.raw_key) await fileDel(env, msgRow.raw_key);
      for (const a of attRows || []) if (a.r2_key) await fileDel(env, a.r2_key);
      await env.DB.batch([
        env.DB.prepare(`DELETE FROM messages WHERE id = ?1 AND inbox = ?2`).bind(id, address),
        env.DB.prepare(`DELETE FROM attachments WHERE message_id = ?1 AND inbox = ?2`).bind(id, address),
      ]);
      await audit(env, user, "message.delete", `${address}/${id}`, null, request);
      return json({ ok: true });
    }
  }

  const mEml = p.match(/^\/api\/message\/([^/]+)\/([^/]+)\/eml$/);
  if (mEml && method === "GET") {
    if (!store(env)) return json({ error: "storage_unavailable" }, 503);
    const address = decodeURIComponent(mEml[1]).toLowerCase();
    const id = decodeURIComponent(mEml[2]);
    const box = await inboxRow(env, address);
    if (!box) return json({ error: "inbox_not_found" }, 404);
    if (!(await canSee(env, user, box))) return json({ error: "not_found" }, 404);
    const msg = await getMessage(env, address, id);
    if (!msg || !msg.raw_key) return json({ error: "eml_not_found" }, 404);
    const obj = await fileGet(env, msg.raw_key);
    if (!obj) return json({ error: "eml_not_found" }, 404);
    await audit(env, user, "message.download_eml", `${address}/${id}`, null, request);
    return new Response(obj.body, {
      headers: {
        "content-type": "message/rfc822",
        "content-disposition": `attachment; filename="${id}.eml"`,
        "cache-control": "no-store",
      },
    });
  }

  const mAtt = p.match(/^\/api\/attachment\/([^/]+)\/([^/]+)\/([^/]+)$/);
  if (mAtt && method === "GET") {
    if (!store(env)) return json({ error: "storage_unavailable" }, 503);
    const address = decodeURIComponent(mAtt[1]).toLowerCase();
    const messageId = decodeURIComponent(mAtt[2]);
    const attId = decodeURIComponent(mAtt[3]);
    const box = await inboxRow(env, address);
    if (!box) return json({ error: "inbox_not_found" }, 404);
    if (!(await canSee(env, user, box))) return json({ error: "not_found" }, 404);
    const att = await env.DB.prepare(
      `SELECT * FROM attachments WHERE id = ?1 AND message_id = ?2 AND inbox = ?3`
    ).bind(attId, messageId, address).first();
    if (!att) return json({ error: "attachment_not_found" }, 404);
    const obj = await fileGet(env, att.r2_key);
    if (!obj) return json({ error: "attachment_not_found" }, 404);
    const safe = String(att.filename || "lampiran").replace(/["\\\r\n]/g, "_");
    const rawMime = String(att.mime || "application/octet-stream").split(";")[0].trim().toLowerCase();
    const safeMime = /^(image\/(png|jpe?g|gif|webp|avif|bmp)|application\/pdf|text\/plain|audio\/(mpeg|wav|ogg|mp4)|video\/mp4)$/.test(rawMime)
      ? rawMime
      : "application/octet-stream";
    await audit(env, user, "attachment.download", `${address}/${attId}`, null, request);
    return new Response(obj.body, {
      headers: {
        "content-type": safeMime,
        "content-disposition": `attachment; filename="${safe}"; filename*=UTF-8''${encodeURIComponent(safe)}`,
        "cache-control": "no-store",
      },
    });
  }

  /* ---------------- AccountMatrix (/api/matrix) ---------------- */
  if (p === "/api/matrix" || p.startsWith("/api/matrix/")) {
    return handleMatrixApi(request, env, url, user, p, method);
  }

  return json({ error: "not_found" }, 404);
}

/* ---------------- AccountMatrix helpers & router ---------------- */
function parseTotpSecretInput(raw) {
  if (!raw) return null;
  let str = String(raw).trim();
  if (/^otpauth:\/\//i.test(str)) {
    try {
      const u = new URL(str);
      str = u.searchParams.get("secret") || "";
    } catch {
      const m = str.match(/[?&]secret=([A-Za-z2-7=\s-]+)/i);
      str = m ? m[1] : "";
    }
  }
  const clean = str.toUpperCase().replace(/[^A-Z2-7]/g, "").slice(0, 128);
  if (!clean || b32decode(clean).length === 0) return null;
  return clean;
}

function generateStrongPassword(len = 18) {
  const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const lower = "abcdefghijkmnopqrstuvwxyz";
  const nums  = "23456789";
  const syms  = "!@#$%^&*_-+=";
  const all   = upper + lower + nums + syms;
  const rnd   = new Uint32Array(len + 4);
  crypto.getRandomValues(rnd);
  const chars = [
    upper[rnd[0] % upper.length],
    lower[rnd[1] % lower.length],
    nums[rnd[2] % nums.length],
    syms[rnd[3] % syms.length],
  ];
  for (let i = 4; i < len; i++) {
    chars.push(all[rnd[i] % all.length]);
  }
  for (let i = chars.length - 1; i > 0; i--) {
    const j = rnd[i] % (i + 1);
    const tmp = chars[i]; chars[i] = chars[j]; chars[j] = tmp;
  }
  return chars.join("");
}

function cleanHtmlToPlainText(html) {
  if (!html) return "";
  return String(html)
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<head[\s\S]*?<\/head>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
    .replace(/\s+/g, " ")
    .trim();
}

function extractOtpServer(subject, textBody, htmlBody) {
  const subj = String(subject || "").trim();
  const cleanHtml = htmlBody ? cleanHtmlToPlainText(htmlBody) : "";
  // Prefer cleanHtml if textBody looks polluted with raw CSS rules from older MIME parser
  const rawTxt = String(textBody || "");
  const cssPolluted = /@font-face|\bbox-sizing\s*:|mso-table-lspace|\bmargin\s*:\s*0/i.test(rawTxt);
  const body = ((cssPolluted && cleanHtml) ? cleanHtml : (rawTxt || cleanHtml))
    .replace(/#[0-9a-fA-F]{3,8}\b/g, " ")
    .replace(/https?:\/\/\S+/gi, " ")
    .slice(0, 12000);
  const combined = `${subj} \n ${body}`;
  const hasCtx = /\b(otp|kode|code|pin|verifikasi|verification|verify|passcode|token|authenticat|masuk|login|sign[\s-]?in|confirm|konfirmasi|sandi|password|security|aktivasi|activate)\b/i.test(combined);
  if (!hasCtx) return null;

  // 1. Explicit pattern right after keyword (e.g. "Login Code: 036688", "verification code is G-582910")
  const explicitRe = /\b(?:kode\s*(?:otp|verifikasi|keamanan|akses)?|verification\s*code|security\s*code|confirmation\s*code|login\s*code|sign[-\s]?in\s*code|passcode|one[-\s]?time\s*(?:password|code)|otp|pin|code|kode)\b[^0-9A-Za-z\n]{0,32}(?:G-)?\b(\d{4,8}|[A-Z0-9]{6,8})\b/gi;
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

  // 2. Pattern before keyword (e.g. "544654 is your verification code", "482910 adalah kode verifikasi")
  const beforeRe = /\b(\d{4,8})\b[^0-9A-Za-z\n]{0,24}\b(?:adalah\s+kode|is\s+your\s+(?:verification|security|login|sign[-\s]?in|confirmation|one-time|temporary)?\s*(?:code|otp|pin))\b/i.exec(combined);
  if (beforeRe) return beforeRe[1];

  // 3. Fallback: 6-digit number in subject or body when verification context is present
  const sixSubj = /\b(\d{6})\b/.exec(subj);
  if (sixSubj && !/^(19\d\d|20[2-3]\d|000000)$/.test(sixSubj[1])) return sixSubj[1];
  const sixRe = /\b([0-9]{6})\b/g;
  while ((m = sixRe.exec(body)) !== null) {
    const c = m[1];
    if (!/^(19\d\d|20[2-3]\d|000000)$/.test(c)) return c;
  }
  return null;
}

function extractMagicLinkServer(subject, textBody, htmlBody, hasExtractedOtp = false) {
  const subj = String(subject || "");
  // If this email is strictly a numeric verification/login code email and we already extracted the OTP,
  // avoid returning generic footer/login links unless it's an explicit magic-link email.
  if (hasExtractedOtp && /\b(verification\s+code|sign[-\s]?in\s+code|login\s+code|kode\s+otp|is\s+your\s+verification\s+code)\b/i.test(subj)) {
    return null;
  }

  const skipHostRe = /^(click|links?|trk|track|metrics|pixel|open|ablink|email\.mg|url\d+)\.|mandrillapp\.com|sendgrid\.net|list-manage\.com|customeriomail\.com|braze\.com|aklamio\.com/i;
  const skipUrlRe = /\.(png|jpe?g|gif|svg|webp|css|js|woff2?|ttf|eot|ico|pdf)(\?|$)|unsubscribe|berhenti|privacy|privasi|terms|ketentuan|help\.|support\.|status\.|preferences|manage|billing|invoice|mailto:|w3\.org|schema\.org|schemas\.microsoft|facebook\.com|twitter\.com|x\.com|instagram\.com|linkedin\.com|youtube\.com|tiktok\.com|fonts\.googleapis|fonts\.gstatic/i;
  const tokenQueryRe = /([?&](token|code|key|ticket|magic|verify|confirmation|confirmation_token|access_token|auth|state)=|\/verify\/|\/confirm\/|\/activate\/|\/magic[-_]?link|\/auth\/callback|\/reset[-_]?password)/i;
  const labelActionRe = /\b(verify|verifikasi|confirm|konfirmasi|activate|aktivasi|magic\s*link|secure\s*link|sign\s*in\s*to|log\s*in\s*to|masuk\s*ke|reset\s*password|accept\s*invite|complete\s*registration)\b/i;

  const candidates = [];

  if (htmlBody) {
    const aRe = /<a\b[^>]*?\bhref\s*=\s*(?:"([^"]+)"|'([^']+)')[^>]*>([\s\S]*?)<\/a>/gi;
    let m;
    while ((m = aRe.exec(htmlBody)) !== null) {
      const rawUrl = (m[1] || m[2] || "").replace(/&amp;/g, "&").trim();
      const label = cleanHtmlToPlainText(m[3] || "");
      if (!/^https?:\/\//i.test(rawUrl) || rawUrl.length < 22) continue;
      if (skipUrlRe.test(rawUrl) || skipUrlRe.test(label)) continue;
      let uObj;
      try { uObj = new URL(rawUrl); } catch { continue; }
      const host = uObj.hostname.toLowerCase();
      if (skipHostRe.test(host) && !tokenQueryRe.test(rawUrl)) continue;
      const pathAndQuery = (uObj.pathname || "") + (uObj.search || "");
      if (pathAndQuery.length <= 6) continue;

      let score = 0;
      if (tokenQueryRe.test(rawUrl)) score += 6;
      if (labelActionRe.test(label)) score += 5;
      if (/\b(secure\s+link|confirm\s+your\s+email|verify\s+your)\b/i.test(subj) && label.length > 2) score += 3;
      if (score >= 6) {
        candidates.push({ url: rawUrl, score });
      }
    }
  }

  if (!candidates.length && textBody) {
    const uRe = /https?:\/\/[^\s"'<>)\]]+/gi;
    let m;
    while ((m = uRe.exec(textBody)) !== null) {
      const rawUrl = m[0].replace(/[.,;:'")\]>]+$/, "").replace(/&amp;/g, "&");
      if (rawUrl.length < 24 || skipUrlRe.test(rawUrl)) continue;
      let uObj;
      try { uObj = new URL(rawUrl); } catch { continue; }
      if (skipHostRe.test(uObj.hostname.toLowerCase()) && !tokenQueryRe.test(rawUrl)) continue;
      if (tokenQueryRe.test(rawUrl)) {
        candidates.push({ url: rawUrl, score: 6 });
      }
    }
  }

  if (!candidates.length) return null;
  candidates.sort((a, b) => b.score - a.score);
  return candidates[0].url;
}

const MATRIX_SERVICE_RULES = [
  { re: /anthropic\.com|claude\.com|claude\.ai/i, name: "Claude (Anthropic)" },
  { re: /openai\.com|chatgpt\.com/i, name: "OpenAI" },
  { re: /mistral\.ai/i, name: "Mistral AI" },
  { re: /qwenlm\.ai|qwen\.ai|\bqwen\b/i, name: "Qwen AI" },
  { re: /orcarouter\.ai/i, name: "OrcaRouter" },
  { re: /zenmux\.ai/i, name: "ZenMux" },
  { re: /langdock\.com/i, name: "Langdock" },
  { re: /opper\.ai/i, name: "Opper" },
  { re: /experientiallabs\.ai/i, name: "Experiential Labs" },
  { re: /mlaiworld\.com|withmlai\.com|@ml\.ai\b|ml\s*ai\s*code/i, name: "ML AI Code" },
  { re: /awsapps\.com|signin\.aws|quick\.aws\.com|amazonaws\.com|amazon\.com|\baws\b/i, name: "AWS" },
  { re: /supabase\.(io|com)/i, name: "Supabase" },
  { re: /oxylabs\.(io|us)/i, name: "Oxylabs" },
  { re: /ionos\.com|\bionos\b/i, name: "IONOS" },
  { re: /bluehost\.com/i, name: "Bluehost" },
  { re: /namecheap\.com/i, name: "Namecheap" },
  { re: /godaddy\.com/i, name: "GoDaddy" },
  { re: /share-dns\.net|\bgname\b/i, name: "GNAME" },
  { re: /playstation\.com|account\.sony\.com|\bplaystation\b|\bsony\b/i, name: "Sony PlayStation" },
  { re: /viktor\.com/i, name: "Viktor" },
  { re: /capskip\.com/i, name: "CapSkip" },
  { re: /starz\.com/i, name: "STARZ" },
  { re: /umich\.edu/i, name: "UMICH EDU" },
  { re: /cursor\.(sh|com)/i, name: "Cursor" },
  { re: /github\.com/i, name: "GitHub" },
  { re: /steampowered\.com|valvesoftware\.com|\bsteam\b/i, name: "Steam" },
  { re: /vercel\.com/i, name: "Vercel" },
  { re: /cloudflare\.com/i, name: "Cloudflare" },
  { re: /discord\.com/i, name: "Discord" },
  { re: /digitalocean\.com/i, name: "DigitalOcean" },
  { re: /railway\.app/i, name: "Railway" },
  { re: /huggingface\.co/i, name: "Hugging Face" },
  { re: /replicate\.com/i, name: "Replicate" },
  { re: /google\.com/i, name: "Google" },
  { re: /microsoft\.com/i, name: "Microsoft" },
  { re: /netflix\.com/i, name: "Netflix" },
  { re: /spotify\.com/i, name: "Spotify" },
];

function detectServiceFromEmail(fromAddr, fromName, subject) {
  const addr = String(fromAddr || "").trim().toLowerCase();
  const name = String(fromName || "").trim();
  const subj = String(subject || "").trim();
  const combined = `${addr} | ${name} | ${subj}`;
  for (const r of MATRIX_SERVICE_RULES) {
    if (r.re.test(combined)) return r.name;
  }
  if (name) {
    const fromMatch = name.match(/\bfrom\s+([A-Za-z0-9 ._-]{2,36})$/i);
    if (fromMatch) return fromMatch[1].trim();
    const cleaned = name
      .replace(/\b(customer\s+service|support|team|auth|notifications?|no-?reply|security|account|verify|mail)\b/gi, "")
      .replace(/\s+/g, " ")
      .trim();
    if (cleaned.length >= 2 && cleaned.length <= 32 && !/^[A-Z][a-z]+\s+[A-Z][a-z]+$/.test(cleaned)) {
      return cleaned;
    }
  }
  if (addr.includes("@")) {
    const host = addr.split("@")[1]
      .replace(/^(mail|email|emails|notifications?|updates?|tm|auth|account|service|login|signin|app|txn-email|email\d+)\./gi, "")
      .replace(/^(mail|app|account)\./gi, "");
    const base = host.split(".")[0] || "";
    if (base.length >= 2) {
      return base.charAt(0).toUpperCase() + base.slice(1);
    }
  }
  return null;
}

function detectStatusFromSubjects(subjects) {
  const joined = (subjects || []).join(" \n ");
  if (/\b(deactivated|suspended|terminated|banned|disabled|blocked|account\s+closed)\b/i.test(joined)) {
    return "burned";
  }
  if (/\b(action\s+needed|response\s+required|unable\s+to\s+process|did\s+not\s+go\s+through|payment\s+failed)\b/i.test(joined)) {
    return "cooldown";
  }
  if (/\b(trial|still\s+meaning\s+to\s+try|bonus\s+credits|free\s+credits?)\b/i.test(joined)) {
    return "trial";
  }
  return "active";
}

function isAutoDetectPlaceholder(svc) {
  const s = String(svc || "").trim().toLowerCase();
  return !s || s === "auto-detect" || s === "auto" || s.startsWith("auto-detect ");
}

function matchServiceFuzzy(targetSvcRaw, detectedSvcRaw, fromAddr, fromName, subject) {
  const targetSvc = String(targetSvcRaw || "").trim().toLowerCase();
  if (!targetSvc || isAutoDetectPlaceholder(targetSvc)) return false;
  const det = String(detectedSvcRaw || "").trim().toLowerCase();
  if (det && (det === targetSvc || det.includes(targetSvc) || targetSvc.includes(det))) return true;
  const hay = `${fromAddr || ""} ${fromName || ""} ${subject || ""} ${det}`.toLowerCase();
  if (targetSvc.length >= 3 && hay.includes(targetSvc)) return true;
  const stopWords = new Set(["akun", "account", "utama", "baru", "test", "testing", "pro", "vip", "free", "trial", "bot", "web", "app", "ai"]);
  const tokens = targetSvc.split(/[^a-z0-9]+/).filter((w) => w.length >= 3 && !stopWords.has(w));
  return tokens.some((tk) => hay.includes(tk));
}

async function autoRegisterMatrixFromEmail(env, userId, inboxAddr, fromAddr, fromName, subject, receivedAt = now()) {
  if (!userId || !inboxAddr) return;
  const service = detectServiceFromEmail(fromAddr, fromName, subject);
  if (!service) return;
  const { results: addrRows } = await env.DB.prepare(
    `SELECT id, service, tag, status FROM matrix_accounts WHERE user_id = ?1 AND address = ?2`
  ).bind(userId, inboxAddr).all();
  const rows = addrRows || [];

  const detStatus = detectStatusFromSubjects([subject || ""]);

  // 1. Exact or fuzzy match on existing account row for this address
  const matched = rows.find((r) =>
    String(r.service || "").toLowerCase() === service.toLowerCase() ||
    matchServiceFuzzy(r.service, service, fromAddr, fromName, subject)
  );
  if (matched) {
    if (matched.status === "archived") return;
    const nextStatus = detStatus === "burned" ? "burned" : (detStatus === "cooldown" && matched.status === "active" ? "cooldown" : matched.status);
    await env.DB.prepare(
      `UPDATE matrix_accounts SET status = ?2, updated_at = ?3 WHERE id = ?1`
    ).bind(matched.id, nextStatus, receivedAt).run();
    return;
  }

  // 2. Placeholder "Auto-Detect" row waiting for its first email -> auto-rename service to detected name
  const placeholder = rows.find((r) => r.status !== "archived" && isAutoDetectPlaceholder(r.service));
  if (placeholder) {
    const nextStatus = detStatus === "burned" ? "burned" : (detStatus === "cooldown" && placeholder.status === "active" ? "cooldown" : placeholder.status);
    await env.DB.prepare(
      `UPDATE matrix_accounts SET service = ?2, status = ?3, updated_at = ?4 WHERE id = ?1`
    ).bind(placeholder.id, service, nextStatus, receivedAt).run();
    return;
  }

  // 3. Single custom-titled manual account on a dedicated inbox -> bind incoming email to it without spawning duplicate #Auto
  const activeRows = rows.filter((r) => r.status !== "archived");
  if (activeRows.length === 1 && activeRows[0].tag !== "#Auto") {
    const only = activeRows[0];
    const nextStatus = detStatus === "burned" ? "burned" : (detStatus === "cooldown" && only.status === "active" ? "cooldown" : only.status);
    await env.DB.prepare(
      `UPDATE matrix_accounts SET status = ?2, updated_at = ?3 WHERE id = ?1`
    ).bind(only.id, nextStatus, receivedAt).run();
    return;
  }

  const localPart = inboxAddr.split("@")[0] || "user";
  const username = localPart.replace(/[._-]/g, "");
  await env.DB.prepare(
    `INSERT INTO matrix_accounts
       (id, user_id, service, tag, address, username, password, totp_secret,
        api_key, recovery_codes, opsec_note, status, expires_at, created_at, updated_at)
     VALUES (?1,?2,?3,'#Auto',?4,?5,NULL,NULL,NULL,NULL,'Auto-detected dari email masuk',?6,NULL,?7,?7)`
  ).bind(crypto.randomUUID(), userId, service, inboxAddr, username, detStatus, receivedAt).run();
}

async function syncMatrixFromInboxes(env, userId, nowMs = now()) {
  const { results: msgs } = await env.DB.prepare(
    `SELECT m.inbox, m.from_addr, m.from_name, m.subject, m.received_at, i.note
       FROM messages m
       JOIN inboxes i ON i.address = m.inbox
      WHERE i.user_id = ?1
      ORDER BY m.received_at ASC`
  ).bind(userId).all();

  const { results: existingRows } = await env.DB.prepare(
    `SELECT id, service, tag, address, status FROM matrix_accounts WHERE user_id = ?1`
  ).bind(userId).all();

  const existingList = existingRows || [];
  const existingSet = new Set(existingList.map((r) => `${r.address.toLowerCase()}||${(r.service || "").toLowerCase()}`));
  const byAddr = new Map();
  for (const r of existingList) {
    const a = r.address.toLowerCase();
    if (!byAddr.has(a)) byAddr.set(a, []);
    byAddr.get(a).push(r);
  }
  const groups = new Map();

  for (const m of msgs || []) {
    const svc = detectServiceFromEmail(m.from_addr, m.from_name, m.subject);
    if (!svc) continue;
    const key = `${m.inbox.toLowerCase()}||${svc.toLowerCase()}`;
    if (!groups.has(key)) {
      groups.set(key, {
        address: m.inbox.toLowerCase(),
        service: svc,
        first_at: m.received_at || nowMs,
        last_at: m.received_at || nowMs,
        subjects: [],
        note: m.note || null,
      });
    }
    const g = groups.get(key);
    if (m.received_at && m.received_at > g.last_at) g.last_at = m.received_at;
    if (m.subject) g.subjects.push(m.subject);
  }

  // Count how many accounts exist per service to auto-tag #Alt-1, #Alt-2 when multiple accounts share the same service
  const svcCounts = new Map();
  for (const r of existingList) {
    const k = (r.service || "").toLowerCase();
    svcCounts.set(k, (svcCounts.get(k) || 0) + 1);
  }
  const svcTotals = new Map();
  for (const g of groups.values()) {
    const k = g.service.toLowerCase();
    svcTotals.set(k, (svcTotals.get(k) || 0) + 1);
  }

  let added = 0;
  for (const [key, g] of groups.entries()) {
    if (existingSet.has(key)) continue;
    const addrRows = byAddr.get(g.address) || [];
    // Check if an Auto-Detect placeholder or fuzzy-matched custom title already exists on this address
    const placeholder = addrRows.find((r) => r.status !== "archived" && isAutoDetectPlaceholder(r.service));
    if (placeholder) {
      placeholder.service = g.service;
      existingSet.add(key);
      await env.DB.prepare(`UPDATE matrix_accounts SET service = ?2, updated_at = ?3 WHERE id = ?1`)
        .bind(placeholder.id, g.service, g.last_at).run();
      continue;
    }
    const fuzzyMatch = addrRows.find((r) => matchServiceFuzzy(r.service, g.service, "", "", g.subjects.join(" ")));
    if (fuzzyMatch) continue;
    const activeManual = addrRows.filter((r) => r.status !== "archived" && r.tag !== "#Auto");
    if (activeManual.length === 1 && addrRows.length === 1) continue;

    existingSet.add(key);
    const svcKey = g.service.toLowerCase();
    const nextIdx = (svcCounts.get(svcKey) || 0) + 1;
    svcCounts.set(svcKey, nextIdx);
    const totalForSvc = svcTotals.get(svcKey) || 1;
    const tag = totalForSvc > 1 ? `#Alt-${String(nextIdx).padStart(2, "0")}` : "#Auto";
    const status = detectStatusFromSubjects(g.subjects);
    const localPart = g.address.split("@")[0] || "user";
    const username = localPart.replace(/[._-]/g, "");

    await env.DB.prepare(
      `INSERT INTO matrix_accounts
         (id, user_id, service, tag, address, username, password, totp_secret,
          api_key, recovery_codes, opsec_note, status, expires_at, created_at, updated_at)
       VALUES (?1,?2,?3,?4,?5,?6,NULL,NULL,NULL,NULL,?7,?8,NULL,?9,?10)`
    ).bind(
      crypto.randomUUID(),
      userId,
      g.service,
      tag,
      g.address,
      username,
      g.note || "Auto-synced dari inbox menyurat.me",
      status,
      g.first_at,
      g.last_at
    ).run();
    added++;
  }
  return added;
}

async function fetchInboxMessagesForMatrix(env, address) {
  const { results } = await env.DB.prepare(
    `SELECT id, from_addr, from_name, subject, received_at,
            SUBSTR(COALESCE(text_body, ''), 1, 12000) AS text_body,
            SUBSTR(COALESCE(html_body, ''), 1, 65000) AS html_body
       FROM messages
      WHERE inbox = ?1
      ORDER BY received_at DESC LIMIT 25`
  ).bind(address).all();
  return results || [];
}

async function enrichMatrixAccount(env, row, nowMs = now(), preloadedMsgs = null, peerServicesOnAddr = null) {
  let totpCode = null;
  let totpRem  = null;
  if (row.totp_secret) {
    try {
      totpCode = await totpAt(row.totp_secret, nowMs);
      totpRem  = 30 - (Math.floor(nowMs / 1000) % 30);
    } catch {}
  }
  const allMsgs = preloadedMsgs || await fetchInboxMessagesForMatrix(env, row.address);

  // If this row was created in "Auto-Detect" mode and an email has arrived, auto-promote the service name
  let currentService = String(row.service || "").trim() || "Auto-Detect";
  if (isAutoDetectPlaceholder(currentService) && allMsgs.length > 0) {
    const firstDetected = detectServiceFromEmail(allMsgs[0].from_addr, allMsgs[0].from_name, allMsgs[0].subject);
    if (firstDetected) {
      currentService = firstDetected;
      row.service = firstDetected;
      try {
        await env.DB.prepare(`UPDATE matrix_accounts SET service = ?2, updated_at = ?3 WHERE id = ?1`)
          .bind(row.id, firstDetected, allMsgs[0].received_at || nowMs).run();
      } catch {}
    }
  }

  const svcMsgs = allMsgs.filter((m) => {
    const det = detectServiceFromEmail(m.from_addr, m.from_name, m.subject);
    return matchServiceFuzzy(currentService, det, m.from_addr, m.from_name, m.subject);
  });

  // Determine message pool:
  // - If fuzzy/exact matched messages exist, use them.
  // - If this inbox is dedicated to a single account (e.g. user entered a custom title like "Akun Kampus" or "Auto-Detect"),
  //   bind all messages in that inbox directly to this account so OTP & Magic Link always work!
  // - If shared inbox across multiple accounts, only include messages not claimed by another sibling account on the same address.
  const otherPeers = (peerServicesOnAddr || []).filter((s) => s.toLowerCase() !== currentService.toLowerCase());
  const isDedicatedInbox = otherPeers.length === 0;
  let fallbackMsgs = [];
  if (!svcMsgs.length) {
    if (isDedicatedInbox || isAutoDetectPlaceholder(currentService)) {
      fallbackMsgs = allMsgs;
    } else {
      fallbackMsgs = allMsgs.filter((m) => {
        const det = detectServiceFromEmail(m.from_addr, m.from_name, m.subject);
        return !otherPeers.some((peerSvc) => matchServiceFuzzy(peerSvc, det, m.from_addr, m.from_name, m.subject));
      });
    }
  }
  const pool = svcMsgs.length ? svcMsgs : fallbackMsgs;
  const latest = pool[0] || null;

  let emailOtp  = null;
  let magicLink = null;
  for (const m of pool.slice(0, 6)) {
    const mOtp = !emailOtp ? extractOtpServer(m.subject, m.text_body, m.html_body) : null;
    if (mOtp) emailOtp = mOtp;
    if (!magicLink) magicLink = extractMagicLinkServer(m.subject, m.text_body, m.html_body, Boolean(mOtp || emailOtp));
    if (emailOtp && magicLink) break;
  }

  return {
    id: row.id,
    service: currentService,
    tag: row.tag || null,
    address: row.address,
    username: row.username || null,
    password: row.password || null,
    totp_secret: row.totp_secret || null,
    totp_code: totpCode,
    totp_rem: totpRem,
    api_key: row.api_key || null,
    recovery_codes: row.recovery_codes || null,
    opsec_note: row.opsec_note || null,
    status: row.status || "active",
    expires_at: row.expires_at || null,
    created_at: row.created_at,
    updated_at: row.updated_at,
    message_count: pool.length,
    email_otp: emailOtp,
    magic_link: magicLink,
    latest_message_id: latest ? latest.id : null,
    latest_subject: latest ? latest.subject : null,
    latest_from: latest ? (latest.from_name || latest.from_addr) : null,
    latest_at: latest ? latest.received_at : null,
  };
}

async function enrichMatrixAccountList(env, rows, nowMs = now()) {
  const arr = rows || [];
  if (!arr.length) return [];
  const uniqueAddrs = [...new Set(arr.map((r) => r.address))];
  const peerMap = new Map();
  for (const r of arr) {
    const a = r.address;
    if (!peerMap.has(a)) peerMap.set(a, []);
    peerMap.get(a).push(String(r.service || ""));
  }
  const msgMap = new Map();
  await Promise.all(
    uniqueAddrs.map(async (addr) => {
      msgMap.set(addr, await fetchInboxMessagesForMatrix(env, addr));
    })
  );
  return Promise.all(arr.map((r) => enrichMatrixAccount(env, r, nowMs, msgMap.get(r.address), peerMap.get(r.address))));
}

async function handleMatrixApi(request, env, url, user, p, method) {
  const t = now();

  // POST /api/matrix/sync — auto-discover & import accounts from existing inboxes & messages
  if (p === "/api/matrix/sync" && method === "POST") {
    const added = await syncMatrixFromInboxes(env, user.id, t);
    const { results } = await env.DB.prepare(
      `SELECT * FROM matrix_accounts WHERE user_id = ?1 AND status != 'archived' ORDER BY updated_at DESC, created_at DESC LIMIT 300`
    ).bind(user.id).all();
    const list = await enrichMatrixAccountList(env, results || [], t);
    return json({ ok: true, added, accounts: list });
  }

  // GET /api/matrix — list all matrix accounts for the current user (auto-syncs if empty or ?sync=1)
  if (p === "/api/matrix" && method === "GET") {
    let { results } = await env.DB.prepare(
      `SELECT * FROM matrix_accounts WHERE user_id = ?1 AND status != 'archived' ORDER BY updated_at DESC, created_at DESC LIMIT 300`
    ).bind(user.id).all();
    let autoSynced = 0;
    const totalRow = (!results || results.length === 0)
      ? await env.DB.prepare(`SELECT COUNT(*) AS n FROM matrix_accounts WHERE user_id = ?1`).bind(user.id).first()
      : { n: results.length };
    if ((totalRow ? totalRow.n : 0) === 0 || url.searchParams.get("sync") === "1") {
      autoSynced = await syncMatrixFromInboxes(env, user.id, t);
      if (autoSynced > 0) {
        const res2 = await env.DB.prepare(
          `SELECT * FROM matrix_accounts WHERE user_id = ?1 AND status != 'archived' ORDER BY updated_at DESC, created_at DESC LIMIT 300`
        ).bind(user.id).all();
        results = res2.results || [];
      }
    }
    const list = await enrichMatrixAccountList(env, results || [], t);
    return json({ accounts: list, auto_synced: autoSynced });
  }

  // POST /api/matrix — 1-Click Spawn Identity or Add Account
  if (p === "/api/matrix" && method === "POST") {
    const b = await request.json().catch(() => ({}));
    const service = String(b.service || "").trim().slice(0, 60) || "Auto-Detect";
    const tag = String(b.tag || "").trim().slice(0, 40) || null;

    let fullAddress = "";
    let domainName  = "";
    let localPart   = "";

    if (b.address && String(b.address).includes("@")) {
      const parts = String(b.address).trim().toLowerCase().split("@");
      localPart = normalizeLocal(parts[0]);
      const dom = await resolveDomain(env, parts[1]);
      if (dom.error) return json(dom, 400);
      domainName = dom.domain;
      if (!validLocal(localPart)) return json({ error: "invalid_local", note: "Bagian lokal email minimal 3 karakter." }, 400);
      if (!isStaff(user) && isReservedLocal(localPart)) {
        return json({ error: "local_reserved", note: "Nama alamat ini dicadangkan sistem." }, 400);
      }
      fullAddress = `${localPart}@${domainName}`;
    } else {
      const dom = await resolveDomain(env, b.domain);
      if (dom.error) return json(dom, 400);
      domainName = dom.domain;
      if (b.local && String(b.local).trim()) {
        localPart = normalizeLocal(b.local);
        if (!validLocal(localPart)) return json({ error: "invalid_local", note: "Nama lokal minimal 3 karakter (a-z, 0-9, ., _, -)." }, 400);
        if (!isStaff(user) && isReservedLocal(localPart)) {
          return json({ error: "local_reserved", note: "Nama alamat ini dicadangkan sistem." }, 400);
        }
        fullAddress = `${localPart}@${domainName}`;
      } else {
        // Auto-spawn natural human address that isn't owned by another user
        for (let attempt = 0; attempt < 6; attempt++) {
          const candLocal = randLocal();
          const candAddr  = `${candLocal}@${domainName}`;
          const ex = await inboxRow(env, candAddr);
          if (!ex || ex.user_id === user.id || (ex.expires_at <= t && ex.pinned !== 1)) {
            localPart   = candLocal;
            fullAddress = candAddr;
            break;
          }
        }
        if (!fullAddress) {
          localPart   = `${randLocal()}${digits(2)}`;
          fullAddress = `${localPart}@${domainName}`;
        }
      }
    }

    const domInfo = await getDomain(env, domainName);
    if (domInfo && domInfo.is_premium && user.role === "member") {
      return json({ error: "domain_premium", note: "Domain ini khusus untuk pengguna VIP ke atas." }, 403);
    }
    const existingBox = await inboxRow(env, fullAddress);
    const alreadyOwnActive = existingBox && existingBox.user_id === user.id && (existingBox.expires_at > t || existingBox.pinned === 1);
    if (!alreadyOwnActive) {
      const q = await quotaCheck(env, user, domainName);
      if (q) return json(q, 429);
    }

    // Ensure & auto-pin the inbox in menyurat.me so the account's mailbox never expires
    const boxNote = tag ? `${service} (${tag})` : service;
    const ensured = await ensureInbox(env, fullAddress, domainName, user.id, ttlFor(user, null), boxNote);
    if (ensured.conflict) {
      return json({ error: "address_taken", note: "Alamat inbox sudah dipakai pengguna lain." }, 409);
    }
    if (b.auto_pin !== false && user.role !== "member") {
      await env.DB.prepare(`UPDATE inboxes SET pinned = 1 WHERE address = ?1`).bind(fullAddress).run();
    }

    const username = String(b.username || "").trim().slice(0, 80) || localPart.replace(/[._-]/g, "");
    const password = (b.password && String(b.password).trim())
      ? String(b.password).trim().slice(0, 200)
      : (b.generate_password === false ? null : generateStrongPassword(18));
    const totpSecret = parseTotpSecretInput(b.totp_secret);
    if (b.totp_secret && String(b.totp_secret).trim() && !totpSecret) {
      return json({ error: "invalid_totp_secret", note: "Format secret 2FA TOTP (Base32 / otpauth://) tidak valid." }, 400);
    }
    const apiKey        = String(b.api_key || "").trim().slice(0, 500) || null;
    const recCodes      = String(b.recovery_codes || "").trim().slice(0, 1000) || null;
    const opsecNote     = String(b.opsec_note || "").trim().slice(0, 300) || null;
    const allowedStatus = ["active", "trial", "cooldown", "burned"];
    const status        = allowedStatus.includes(b.status) ? b.status : (b.trial_days ? "trial" : "active");

    let expiresAt = null;
    if (b.expires_at && Number.isFinite(Number(b.expires_at))) {
      expiresAt = Number(b.expires_at);
    } else if (b.trial_days && Number.isFinite(Number(b.trial_days)) && Number(b.trial_days) > 0) {
      expiresAt = t + Math.min(3650, Number(b.trial_days)) * 86400_000;
    }

    const id = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO matrix_accounts
         (id, user_id, service, tag, address, username, password, totp_secret,
          api_key, recovery_codes, opsec_note, status, expires_at, created_at, updated_at)
       VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?14)`
    ).bind(
      id, user.id, service, tag, fullAddress, username, password, totpSecret,
      apiKey, recCodes, opsecNote, status, expiresAt, t
    ).run();

    await audit(env, user, "matrix.spawn", fullAddress, { id, service, tag }, request);
    const createdRow = await env.DB.prepare(`SELECT * FROM matrix_accounts WHERE id = ?1`).bind(id).first();
    return json({ ok: true, account: await enrichMatrixAccount(env, createdRow, t) }, 201);
  }

  // GET /api/matrix/:id/otp — instant live 2FA TOTP + latest email OTP/Magic-Link pull
  const mOtp = p.match(/^\/api\/matrix\/([^/]+)\/otp$/);
  if (mOtp && method === "GET") {
    const id = decodeURIComponent(mOtp[1]);
    const row = await env.DB.prepare(`SELECT * FROM matrix_accounts WHERE id = ?1`).bind(id).first();
    if (!row || (row.user_id !== user.id && user.role !== "owner")) {
      return json({ error: "not_found" }, 404);
    }
    const { results: peerRows } = await env.DB.prepare(
      `SELECT service FROM matrix_accounts WHERE user_id = ?1 AND address = ?2 AND status != 'archived'`
    ).bind(row.user_id, row.address).all();
    const peerServices = (peerRows || []).map((r) => String(r.service || ""));
    const enriched = await enrichMatrixAccount(env, row, t, null, peerServices);
    return json({
      ok: true,
      id: enriched.id,
      service: enriched.service,
      address: enriched.address,
      totp_code: enriched.totp_code,
      totp_rem: enriched.totp_rem,
      email_otp: enriched.email_otp,
      magic_link: enriched.magic_link,
      message_count: enriched.message_count,
      latest_message_id: enriched.latest_message_id,
      latest_subject: enriched.latest_subject,
      latest_from: enriched.latest_from,
      latest_at: enriched.latest_at,
    });
  }

  // PATCH or DELETE /api/matrix/:id
  const mItem = p.match(/^\/api\/matrix\/([^/]+)$/);
  if (mItem) {
    const id = decodeURIComponent(mItem[1]);
    const row = await env.DB.prepare(`SELECT * FROM matrix_accounts WHERE id = ?1`).bind(id).first();
    if (!row || (row.user_id !== user.id && user.role !== "owner")) {
      return json({ error: "not_found" }, 404);
    }

    if (method === "PATCH") {
      const b = await request.json().catch(() => ({}));
      const service = b.service !== undefined ? (String(b.service || "").trim().slice(0, 60) || row.service) : row.service;
      const tag     = b.tag !== undefined ? (String(b.tag || "").trim().slice(0, 40) || null) : row.tag;
      const username = b.username !== undefined ? (String(b.username || "").trim().slice(0, 80) || null) : row.username;
      const password = b.password !== undefined
        ? (b.password === "__GENERATE__" ? generateStrongPassword(18) : (String(b.password || "").trim().slice(0, 200) || null))
        : row.password;

      let totpSecret = row.totp_secret;
      if (b.totp_secret !== undefined) {
        const rawT = String(b.totp_secret || "").trim();
        if (!rawT) {
          totpSecret = null;
        } else {
          totpSecret = parseTotpSecretInput(rawT);
          if (!totpSecret) return json({ error: "invalid_totp_secret", note: "Secret TOTP Base32 tidak valid." }, 400);
        }
      }

      const apiKey   = b.api_key !== undefined ? (String(b.api_key || "").trim().slice(0, 500) || null) : row.api_key;
      const recCodes = b.recovery_codes !== undefined ? (String(b.recovery_codes || "").trim().slice(0, 1000) || null) : row.recovery_codes;
      const opsecNote = b.opsec_note !== undefined ? (String(b.opsec_note || "").trim().slice(0, 300) || null) : row.opsec_note;
      const allowedStatus = ["active", "trial", "cooldown", "burned", "archived"];
      const status = (b.status && allowedStatus.includes(b.status)) ? b.status : row.status;

      let expiresAt = row.expires_at;
      if (b.expires_at !== undefined) {
        expiresAt = b.expires_at ? Number(b.expires_at) : null;
      } else if (b.trial_days !== undefined) {
        const td = Number(b.trial_days);
        expiresAt = (Number.isFinite(td) && td > 0) ? (t + Math.min(3650, td) * 86400_000) : null;
      }

      await env.DB.prepare(
        `UPDATE matrix_accounts
            SET service = ?2, tag = ?3, username = ?4, password = ?5, totp_secret = ?6,
                api_key = ?7, recovery_codes = ?8, opsec_note = ?9, status = ?10,
                expires_at = ?11, updated_at = ?12
          WHERE id = ?1`
      ).bind(
        id, service, tag, username, password, totpSecret,
        apiKey, recCodes, opsecNote, status, expiresAt, t
      ).run();

      const updated = await env.DB.prepare(`SELECT * FROM matrix_accounts WHERE id = ?1`).bind(id).first();
      return json({ ok: true, account: await enrichMatrixAccount(env, updated, t) });
    }

    if (method === "DELETE") {
      if (url.searchParams.get("hard") === "1") {
        await env.DB.prepare(`DELETE FROM matrix_accounts WHERE id = ?1`).bind(id).run();
      } else {
        // Soft-tombstone so Auto-Sync and incoming newsletter hooks never re-import deleted rows
        await env.DB.prepare(`UPDATE matrix_accounts SET status = 'archived', updated_at = ?2 WHERE id = ?1`).bind(id, t).run();
      }
      if (url.searchParams.get("delete_inbox") === "1") {
        const box = await inboxRow(env, row.address);
        if (box && box.user_id === user.id) {
          await purgeInboxContents(env, row.address);
          await env.DB.prepare(`DELETE FROM inboxes WHERE address = ?1`).bind(row.address).run();
        }
      }
      await audit(env, user, "matrix.delete", row.address, { id, service: row.service }, request);
      return json({ ok: true, id });
    }
  }

  return json({ error: "not_found" }, 404);
}

/* ---------------- entry ---------------- */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      const cors = corsFor(request);
      const allowed = !!cors["access-control-allow-origin"];
      return harden(new Response(null, {
        status: allowed ? 204 : 403,
        headers: {
          ...cors,
          "access-control-allow-methods": "GET,POST,PATCH,DELETE,OPTIONS",
          "access-control-allow-headers": "content-type, authorization, x-api-key",
          "access-control-max-age": "600",
        },
      }), null);
    }

    if (url.pathname.startsWith("/api/")) {
      try {
        if (!isValidCsrfRequest(request)) {
          return harden(json({ error: "csrf_blocked", note: "Origin atau Sec-Fetch-Site tidak diizinkan." }, 403), request);
        }
        const user = await currentUser(env, request);
        return harden(await handleApi(request, env, url, user), request);
      } catch (e) {
        console.error("internal error:", e);
        return harden(json({ error: "internal" }, 500), request);
      }
    }
    if (env.ASSETS) {
      // HEAD tidak punya body, jadi res.text() kosong dan CSP jadi tanpa hash.
      // Kalau varian HEAD itu ikut ter-cache di edge, GET berikutnya bisa dapat
      // CSP tanpa hash -> inline script diblokir. Ambil GET untuk hitung CSP.
      const isHead = request.method === "HEAD";
      const res = await env.ASSETS.fetch(isHead ? new Request(url, { method: "GET", headers: request.headers }) : request);
      const ct = res.headers.get("content-type") || "";
      if (ct.includes("text/html")) {
        let html = await res.text();
        if (env.TURNSTILE_SITE_KEY) {
          const safeKey = String(env.TURNSTILE_SITE_KEY).replace(/["<>]/g, "");
          html = html.replace(
            /(<meta\s+name="turnstile-sitekey"\s+content=")[^"]*(")/i,
            `$1${safeKey}$2`
          );
        }
        const csp = await cspForHtml(html);
        const out = new Headers(res.headers);
        out.delete("content-length");
        out.delete("etag");
        out.delete("last-modified");
        // HTML tidak boleh di-cache di edge: kalau tidak, user dapat versi lama
        // (widget Turnstile hidden / showMsg hidden) walau Worker sudah di-deploy.
        out.set("cache-control", "no-store, must-revalidate");
        return harden(new Response(isHead ? null : html, { status: res.status, statusText: res.statusText, headers: out }), null, csp);
      }
      return harden(res, null);
    }
    return harden(new Response("Not found", { status: 404 }), null);
  },

  async email(message, env) {
    try { await handleEmail(message, env); }
    catch (e) { console.error("email handler error:", e); }
  },

  async scheduled(event, env) {
    const t = now();
    const { results: dead } = await env.DB.prepare(
      `SELECT id, inbox, raw_key FROM messages WHERE expires_at <= ?1 AND inbox NOT IN (SELECT address FROM inboxes WHERE pinned = 1) LIMIT 200`
    ).bind(t).all();
    const deadRows = dead || [];
    if (deadRows.length) {
      const delStmts = [];
      for (const m of deadRows) {
        if (store(env)) {
          if (m.raw_key) await fileDel(env, m.raw_key);
          const { results: atts } = await env.DB.prepare(
            `SELECT r2_key FROM attachments WHERE message_id = ?1 AND inbox = ?2`
          ).bind(m.id, m.inbox).all();
          for (const a of atts || []) if (a.r2_key) await fileDel(env, a.r2_key);
        }
        delStmts.push(env.DB.prepare(`DELETE FROM attachments WHERE message_id = ?1 AND inbox = ?2`).bind(m.id, m.inbox));
        delStmts.push(env.DB.prepare(`DELETE FROM messages WHERE id = ?1 AND inbox = ?2`).bind(m.id, m.inbox));
      }
      if (delStmts.length) await env.DB.batch(delStmts);
    }
    await env.DB.batch([
      env.DB.prepare(
        `DELETE FROM inboxes WHERE expires_at <= ?1 AND pinned = 0
         AND NOT EXISTS (SELECT 1 FROM messages m WHERE m.inbox = inboxes.address)`
      ).bind(t),
      env.DB.prepare(`DELETE FROM webhooks WHERE address NOT IN (SELECT address FROM inboxes)`),
      env.DB.prepare(`DELETE FROM password_resets WHERE (expires_at > 0 AND expires_at <= ?1) OR created_at <= ?2`).bind(t, t - 7 * 86400_000),
      env.DB.prepare(`DELETE FROM audit_log WHERE created_at <= ?1`).bind(t - 90 * 86400_000),
      env.DB.prepare(`DELETE FROM login_attempts WHERE window_start <= ?1`).bind(t - 86400_000),
      env.DB.prepare(`DELETE FROM rate_limits WHERE window_start <= ?1`).bind(t - 86400_000),
      env.DB.prepare(`DELETE FROM login_tickets WHERE expires_at <= ?1`).bind(t),
    ]);
    await purgeExpiredSessions(env);
  },
};

