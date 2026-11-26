// src/utils.js — Shared helpers, security guards, D1 inbox/domain helpers, storage, and rate limits
import { getSessionUser, sha256Hex } from "./auth.js";

export const ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";
export const now = () => Date.now();
export const isStaff = (u) => !!u && (u.role === "owner" || u.role === "admin");
export const RANK = { owner: 4, admin: 3, vip: 2, member: 1 };
export const rank = (r) => RANK[r] || 0;
export const canManage = (me, target) => !!me && !!target && rank(me.role) > rank(target.role);

// TTL default per role (detik)
export const TTL_ROLE = { member: 7 * 86400, vip: 14 * 86400, admin: 14 * 86400, owner: 14 * 86400 };
export const TTL_MAX = 365 * 86400;
export const TTL_MAX_ROLE = { member: 7 * 86400, vip: 90 * 86400, admin: 90 * 86400, owner: 365 * 86400 };
export const TTL_MIN = 3600;
export const MEMBER_QUOTA_PER_DOMAIN = 10;

export function ttlFor(user, requested) {
  const role = user ? user.role : "member";
  if (role === "member") return TTL_ROLE.member;
  if (!requested) return TTL_ROLE[role] || 14 * 86400;
  const n = parseInt(requested, 10);
  if (!Number.isFinite(n)) return TTL_ROLE[role] || 14 * 86400;
  return Math.min(Math.max(n, TTL_MIN), TTL_MAX_ROLE[role] || TTL_MAX);
}

export function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers },
  });
}

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
export const digits = (n) => String(Math.floor(Math.random() * Math.pow(10, n))).padStart(n, "0");

export function randLocal() {
  const f = pickOne(FIRST);
  const l = pickOne(LAST);
  if (f === l) return `${f}.${pickOne(LAST.filter((x) => x !== f))}`;
  const r = Math.random();
  if (r < 0.55) return `${f}.${l}`;
  if (r < 0.72) return `${f}${l}`;
  if (r < 0.86) return `${f}.${l}${digits(2)}`;
  return `${f}${digits(3)}`;
}

export function validLocal(s) {
  if (!s || s.length < 3 || s.length > 64) return false;
  if (!/^[a-z0-9._-]+$/.test(s)) return false;
  if (s.startsWith(".") || s.endsWith(".")) return false;
  if (s.includes("..")) return false;
  return true;
}

export const num = (env, key, def) => {
  const n = parseInt((env && env[key]) || "", 10);
  return Number.isFinite(n) && n > 0 ? n : def;
};
export const ttlSeconds = (env) => num(env, "INBOX_TTL_SECONDS", 1209600);
export const maxMailBytes = (env) => Math.max(1024, num(env, "MAX_MESSAGE_BYTES", 15 * 1024 * 1024));
export const rawKeepBytes = (env) => Math.max(1024, num(env, "RAW_KEEP_BYTES", 6 * 1024 * 1024));
export const BODY_MAX_CHARS = 200000;
export const clipBody = (s) => (typeof s === "string" && s.length > BODY_MAX_CHARS)
  ? s.slice(0, BODY_MAX_CHARS) + "\n\n[...isi dipotong]"
  : s;
export const normalizeLocal = (s) => (s || "").trim().toLowerCase().replace(/[^a-z0-9._-]/g, "").slice(0, 64);
export const normalizeDomain = (s) => (s || "").trim().toLowerCase().replace(/^@/, "").replace(/[^a-z0-9.-]/g, "");
export const normalizeEmail = (s) => (s || "").trim().toLowerCase();
export const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i;
export const ipOf = (request) => request.headers.get("cf-connecting-ip") || request.headers.get("x-real-ip") || "0.0.0.0";

export function safeAttachmentMime(rawMimeInput) {
  const rawMime = String(rawMimeInput || "application/octet-stream").split(";")[0].trim().toLowerCase();
  return /^(image\/(png|jpe?g|gif|webp|avif|bmp)|application\/pdf|text\/plain|audio\/(mpeg|wav|ogg|mp4)|video\/mp4)$/.test(rawMime)
    ? rawMime
    : "application/octet-stream";
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
export function crc32(bytes) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
export function zipStore(files) {
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
export function csvCell(v) {
  let s = String(v ?? "");
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

/* ---------------- hardening ---------------- */
export function allowedOriginsFor(request) {
  try {
    const u = new URL(request.url);
    const baseHost = u.hostname.toLowerCase().replace(/^www\./, "");
    return new Set([u.origin, `https://${baseHost}`, `https://www.${baseHost}`]);
  } catch {
    return new Set();
  }
}

export const SEC_HEADERS = {
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "permissions-policy": "geolocation=(), microphone=(), camera=()",
  "content-security-policy": "default-src 'self'; script-src 'self' https://challenges.cloudflare.com https://static.cloudflareinsights.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob: https:; media-src 'self' data: blob:; connect-src 'self' https://challenges.cloudflare.com https://cloudflareinsights.com; frame-src https://challenges.cloudflare.com; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
};

export function isValidCsrfRequest(request) {
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

export function corsFor(request) {
  const origin = request.headers.get("origin") || "";
  if (!allowedOriginsFor(request).has(origin)) return { vary: "Origin" };
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-credentials": "true",
    vary: "Origin",
  };
}

export async function paramsFor(request, url) {
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
    } catch {}
  }
  return p;
}

const CSP_INLINE_CACHE = { key: null, value: null };
const CSP_BASE = "default-src 'self'; script-src 'self' %HASHES% https://challenges.cloudflare.com https://static.cloudflareinsights.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob: https:; media-src 'self' data: blob:; connect-src 'self' https://challenges.cloudflare.com https://cloudflareinsights.com; frame-src https://challenges.cloudflare.com; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests";

function b64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export async function cspForHtml(html) {
  const key = String(html.length) + ":" + (html.charCodeAt(0) || 0) + ":" + (html.charCodeAt(html.length - 1) || 0);
  if (CSP_INLINE_CACHE.key === key && CSP_INLINE_CACHE.value) return CSP_INLINE_CACHE.value;
  const hashes = [];
  const re = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    let body = m[1];
    if (!body || !body.trim()) continue;
    body = body.replace(/\r\n?/g, "\n");
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body));
    hashes.push("'sha256-" + b64(digest) + "'");
  }
  const csp = CSP_BASE.replace("%HASHES%", hashes.join(" "));
  CSP_INLINE_CACHE.key = key;
  CSP_INLINE_CACHE.value = csp;
  return csp;
}

export function harden(res, request, csp) {
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

export function isReservedLocal(local) {
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
export async function verifyTurnstile(env, request, token) {
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
export async function hitRate(env, key, limit, windowMs) {
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
export async function audit(env, actor, action, target, meta, request) {
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
export async function listDomains(env, activeOnly = true) {
  const sql = activeOnly
    ? `SELECT domain, label, is_default, is_premium FROM domains WHERE is_active = 1 ORDER BY is_default DESC, domain`
    : `SELECT domain, label, is_active, is_default, is_premium FROM domains ORDER BY domain`;
  const { results } = await env.DB.prepare(sql).all();
  return results || [];
}
export async function getDomain(env, domain) {
  return env.DB.prepare(`SELECT domain, label, is_active, is_default, is_premium FROM domains WHERE domain = ?1`).bind(domain).first();
}
export async function resolveDomain(env, requested) {
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

/* ---------------- storage ---------------- */
export const store = (env) => (env && (env.BUCKET || env.FILE_KV)) || null;

export async function filePut(env, key, bytes, contentType) {
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

export async function fileGet(env, key) {
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

export async function fileDel(env, key) {
  if (env.BUCKET) { try { await env.BUCKET.delete(key); } catch {} return; }
  if (env.FILE_KV) { try { await env.FILE_KV.delete(key); } catch {} }
}

export async function streamToBytes(stream, limit = 10 * 1024 * 1024) {
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

/* ---------------- inbox ---------------- */
export const inboxRow = (env, address) =>
  env.DB.prepare(`SELECT address, domain, user_id, created_at, expires_at, pinned, note FROM inboxes WHERE address = ?1`).bind(address).first();

export async function purgeInboxContents(env, address) {
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

export async function ensureInbox(env, address, domain, userId = null, ttlSec = null, note = null) {
  const t = now();
  const exp = t + (ttlSec || ttlSeconds(env)) * 1000;
  const cleanNote = note ? String(note).trim().slice(0, 120) : null;
  const existing = await inboxRow(env, address);
  if (existing) {
    const active = existing.expires_at > t || existing.pinned === 1;
    if (active && existing.user_id !== userId) {
      return { conflict: true, address, domain };
    }
    if (existing.user_id && existing.user_id === userId) {
      const safeExp = Math.max(Number(existing.expires_at) || 0, exp);
      const nextNote = cleanNote !== null ? cleanNote : existing.note || null;
      await env.DB.prepare(
        `UPDATE inboxes SET last_seen = ?2, expires_at = ?3, note = ?4 WHERE address = ?1`
      ).bind(address, t, safeExp, nextNote).run();
      return { address, domain, created_at: existing.created_at, expires_at: safeExp, note: nextNote };
    }
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

export async function inboxRowOrRestoreFromMatrix(env, address) {
  let box = await inboxRow(env, address);
  const t = now();
  if (box && (box.expires_at > t || box.pinned === 1)) return box;
  try {
    const mx = await env.DB.prepare(
      `SELECT user_id, service, tag FROM matrix_accounts WHERE address = ?1 AND status != 'archived' ORDER BY updated_at DESC LIMIT 1`
    ).bind(address).first();
    if (!mx || !mx.user_id) return box;
    const domain = address.split("@")[1] || "";
    const u = await env.DB.prepare(`SELECT role FROM users WHERE id = ?1`).bind(mx.user_id).first();
    const role = u ? u.role : "member";
    const ttl = TTL_ROLE[role] || 14 * 86400;
    const note = (mx.tag && mx.tag !== "#Auto" && mx.tag !== "#Inbox") ? `${mx.service} (${mx.tag})` : mx.service;
    await ensureInbox(env, address, domain, mx.user_id, ttl, note);
    const newExp = t + ttl * 1000;
    if (role !== "member") {
      await env.DB.prepare(`UPDATE inboxes SET pinned = 1 WHERE address = ?1`).bind(address).run();
    } else {
      await env.DB.prepare(`UPDATE messages SET expires_at = ?2 WHERE inbox = ?1 AND expires_at < ?2`).bind(address, newExp).run();
    }
    return await inboxRow(env, address);
  } catch {
    return box;
  }
}

export async function canSee(env, user, box) {
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

export async function listMessages(env, address) {
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

export const getMessage = (env, address, id) =>
  env.DB.prepare(
    `SELECT m.* FROM messages m
       LEFT JOIN inboxes i ON i.address = m.inbox
      WHERE m.id = ?1 AND m.inbox = ?2 AND (m.expires_at > ?3 OR i.pinned = 1)`
  ).bind(id, address, now()).first();

export async function quotaCheck(env, user, domain) {
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

/* ---------------- auth & login lockout helpers ---------------- */
export async function userFromApiKey(env, request) {
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

export async function currentUser(env, request) {
  return (await getSessionUser(env, request)) || (await userFromApiKey(env, request));
}

export async function hitLogin(env, ip, email) {
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

export async function failLogin(env, key, row) {
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

export const clearLogin = (env, key) =>
  env.DB.prepare(`DELETE FROM login_attempts WHERE rl_key = ?1`).bind(key).run();
