// src/auth.js — password hashing, session, cookie helpers (WebCrypto only)

const enc = new TextEncoder();
const ITER = 100000; // batas WebCrypto Workers
export const SESSION_TTL = 7 * 24 * 3600; // detik

/* ---------- base64 ---------- */
export function b64(bytes) {
  let s = "";
  const u = new Uint8Array(bytes);
  for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s);
}
export function unb64(str) {
  const bin = atob(str);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
export function b64url(bytes) {
  return b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/* ---------- random ---------- */
export function randomToken(n = 32) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b64url(b);
}

export async function sha256Hex(str) {
  const d = await crypto.subtle.digest("SHA-256", enc.encode(str));
  return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/* ---------- password ---------- */
export async function hashPassword(password) {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const bits = await derive(password, salt, ITER);
  return `pbkdf2$${ITER}$${b64(salt)}$${b64(bits)}`;
}

export async function verifyPassword(password, stored) {
  try {
    const parts = String(stored || "").split("$");
    if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
    const iter = parseInt(parts[1], 10);
    const salt = unb64(parts[2]);
    const expected = unb64(parts[3]);
    const got = new Uint8Array(await derive(password, salt, iter));
    if (got.length !== expected.length) return false;
    let diff = 0;
    for (let i = 0; i < got.length; i++) diff |= got[i] ^ expected[i];
    return diff === 0;
  } catch {
    return false;
  }
}

async function derive(password, salt, iterations) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  return crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    key,
    256
  );
}

/* ---------- cookies ---------- */
export const COOKIE = "mn_session";

export function parseCookies(request) {
  const out = {};
  const raw = request.headers.get("cookie") || "";
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k) {
      try { out[k] = decodeURIComponent(v); }
      catch { out[k] = v; }
    }
  }
  return out;
}

export function sessionCookie(token, maxAge = SESSION_TTL) {
  return `${COOKIE}=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}
export function clearCookie() {
  return `${COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

/* ---------- session store ---------- */
export async function createSession(env, userId, request) {
  const token = randomToken(32);
  const tokenHash = await sha256Hex(token);
  const t = Date.now();
  const ua = (request.headers.get("user-agent") || "").slice(0, 200);
  await env.DB.prepare(
    `INSERT INTO sessions (token_hash, user_id, created_at, expires_at, user_agent)
     VALUES (?1, ?2, ?3, ?4, ?5)`
  ).bind(tokenHash, userId, t, t + SESSION_TTL * 1000, ua).run();
  return token;
}

export async function destroySession(env, request) {
  const token = parseCookies(request)[COOKIE];
  if (!token) return;
  const tokenHash = await sha256Hex(token);
  await env.DB.prepare(`DELETE FROM sessions WHERE token_hash = ?1`).bind(tokenHash).run();
}

export async function getSessionUser(env, request) {
  const token = parseCookies(request)[COOKIE];
  if (!token) return null;
  const tokenHash = await sha256Hex(token);
  const row = await env.DB.prepare(
    `SELECT u.id, u.email, u.name, u.role, u.status, u.totp_enabled, s.expires_at
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?1 AND s.expires_at > ?2
      LIMIT 1`
  ).bind(tokenHash, Date.now()).first();
  if (!row) return null;
  if (row.status !== "approved") return null;
  return { ...row, authType: "session" };
}

export async function getUserById(env, id) {
  return env.DB.prepare(
    `SELECT id, email, name, role, status, created_at, approved_at, approved_by
       FROM users WHERE id = ?1`
  ).bind(id).first();
}

export async function listUsers(env, status) {
  const sql = status
    ? `SELECT id, email, name, role, status, created_at, approved_at FROM users WHERE status = ?1 ORDER BY created_at DESC`
    : `SELECT id, email, name, role, status, created_at, approved_at FROM users ORDER BY created_at DESC`;
  const stmt = env.DB.prepare(sql);
  const { results } = status ? await stmt.bind(status).all() : await stmt.all();
  return results || [];
}

export async function countUsers(env, status) {
  const row = status
    ? await env.DB.prepare(`SELECT COUNT(*) AS n FROM users WHERE status = ?1`).bind(status).first()
    : await env.DB.prepare(`SELECT COUNT(*) AS n FROM users`).first();
  return row ? row.n : 0;
}

export async function purgeExpiredSessions(env) {
  await env.DB.prepare(`DELETE FROM sessions WHERE expires_at <= ?1`).bind(Date.now()).run();
}
