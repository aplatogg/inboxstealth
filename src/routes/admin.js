// src/routes/admin.js — Admin & Owner management routes: users, resets, inject, inboxes, domains, audit, stats, announcements
import { hashPassword, listUsers, getUserById, countUsers, randomToken, sha256Hex } from "../auth.js";
import { ingest } from "../email-handler.js";
import {
  now, isStaff, canManage, json, maxMailBytes, normalizeDomain, normalizeEmail,
  EMAIL_RE, audit, listDomains, getDomain, inboxRow, ensureInbox, fileDel
} from "../utils.js";

export async function handleAdmin(request, env, url, user) {
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
      env.DB.prepare(`DELETE FROM matrix_accounts WHERE user_id = ?1`).bind(id),
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

  if (p === "/api/admin/stats" && method === "GET") {
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
