// src/routes/auth.js — Authentication routes: me, register, login, 2FA, logout, forgot, reset, password
import {
  hashPassword, verifyPassword, createSession, destroySession,
  sessionCookie, clearCookie, countUsers, randomToken, sha256Hex
} from "../auth.js";
import { newSecret, verifyTotp, otpauthUri, recoveryCodes } from "../totp.js";
import {
  now, isStaff, json, normalizeEmail, EMAIL_RE, ipOf,
  verifyTurnstile, hitRate, audit, currentUser, hitLogin, failLogin, clearLogin
} from "../utils.js";

export async function handleAuth(request, env, url) {
  const p = url.pathname, method = request.method;

  if (p === "/api/auth/me" && method === "GET") {
    const user = await currentUser(env, request);
    if (!user) return json({ user: null }, 200);
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
