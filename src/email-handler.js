// src/email-handler.js — Cloudflare Email Routing handler & MIME ingestion pipeline
import { parseEmail } from "./mime.js";
import { sha256Hex } from "./auth.js";
import { fireWebhook } from "./routes/webhooks.js";
import { autoRegisterMatrixFromEmail } from "./routes/inbox.js";
import {
  now, ttlSeconds, maxMailBytes, rawKeepBytes, clipBody,
  getDomain, inboxRow, inboxRowOrRestoreFromMatrix, store, filePut, streamToBytes
} from "./utils.js";

export async function ingest(env, to, bytes, preloadedBox = null) {
  const box = preloadedBox || await inboxRow(env, to);
  if (!box) return null;
  const t = now();
  if (box.expires_at <= t && !box.pinned) return null;

  const raw = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const parsed = parseEmail(raw);
  parsed.to = to;

  const msgId = parsed.messageId ? await sha256Hex(parsed.messageId) : crypto.randomUUID();

  const existingMsg = await env.DB.prepare(`SELECT id FROM messages WHERE inbox = ?1 AND id = ?2`).bind(to, msgId).first();
  if (existingMsg) return msgId;

  let rawKey = null;
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

export async function handleEmail(message, env) {
  const to = (message.to || "").trim().toLowerCase();
  if (!to.includes("@")) return;
  const row = await getDomain(env, to.split("@")[1]);
  if (!row || !row.is_active) return;
  const box = await inboxRowOrRestoreFromMatrix(env, to);
  if (!box || (box.expires_at <= now() && !box.pinned)) return;
  const maxBytes = maxMailBytes(env);
  const bytes = await streamToBytes(message.raw, maxBytes + 1);
  if (bytes.length > maxBytes) return;
  await ingest(env, to, bytes, box);
}
