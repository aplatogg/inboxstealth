// src/routes/webhooks.js — Webhook SSRF guard, HMAC signing, dispatch, and CRUD routes
import { randomToken } from "../auth.js";
import { now, json, rank, audit, inboxRowOrRestoreFromMatrix } from "../utils.js";

// Tolak URL tujuan internal/loopback/self-domain (SSRF & loop protection).
export function isSafeWebhookUrl(u, selfHost = "") {
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

export async function hmacHex(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function fireWebhook(env, address, msg) {
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
      } catch {
        await env.DB.prepare(`UPDATE webhooks SET last_status = -1, last_at = ?2 WHERE id = ?1`)
          .bind(h.id, now()).run();
      } finally { clearTimeout(to); }
    }
  } catch (e) { console.error("webhook error:", e); }
}

export async function handleWebhookRoutes(request, env, url, user, address) {
  const method = request.method;
  const box = await inboxRowOrRestoreFromMatrix(env, address);
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
  return json({ error: "not_found" }, 404);
}
