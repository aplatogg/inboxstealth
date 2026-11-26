// src/cron.js — Scheduled 10-minute cleanup for expired messages, attachments, inboxes, and sessions
import { purgeExpiredSessions } from "./auth.js";
import { now, store, fileDel } from "./utils.js";

export async function handleScheduled(event, env) {
  const t = now();
  const { results: dead } = await env.DB.prepare(
    `SELECT id, inbox, raw_key FROM messages
      WHERE expires_at <= ?1
        AND inbox NOT IN (SELECT address FROM inboxes WHERE pinned = 1)
        AND inbox NOT IN (SELECT address FROM matrix_accounts WHERE status != 'archived')
      LIMIT 200`
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
       AND NOT EXISTS (SELECT 1 FROM messages m WHERE m.inbox = inboxes.address)
       AND address NOT IN (SELECT address FROM matrix_accounts WHERE status != 'archived')`
    ).bind(t),
    env.DB.prepare(`DELETE FROM webhooks WHERE address NOT IN (SELECT address FROM inboxes)`),
    env.DB.prepare(`DELETE FROM password_resets WHERE (expires_at > 0 AND expires_at <= ?1) OR created_at <= ?2`).bind(t, t - 7 * 86400_000),
    env.DB.prepare(`DELETE FROM audit_log WHERE created_at <= ?1`).bind(t - 90 * 86400_000),
    env.DB.prepare(`DELETE FROM login_attempts WHERE window_start <= ?1`).bind(t - 86400_000),
    env.DB.prepare(`DELETE FROM rate_limits WHERE window_start <= ?1`).bind(t - 86400_000),
    env.DB.prepare(`DELETE FROM login_tickets WHERE expires_at <= ?1`).bind(t),
  ]);
  await purgeExpiredSessions(env);
}
