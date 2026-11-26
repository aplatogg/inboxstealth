// src/index.js — Main router for menyurat (Cloudflare Workers + D1 + KV)
import { APP_SHELL_HTML } from "./app-shell.js";
import { handleAuth } from "./routes/auth.js";
import { handleAdmin } from "./routes/admin.js";
import {
  handleInboxRoutes, extractOtpServer, extractMagicLinkServer, detectServiceFromEmail
} from "./routes/inbox.js";
import { isSafeWebhookUrl } from "./routes/webhooks.js";
import { handleEmail, ingest } from "./email-handler.js";
import { handleScheduled } from "./cron.js";
import {
  now, json, corsFor, isValidCsrfRequest, currentUser,
  cspForHtml, harden, hitLogin, failLogin, clearLogin, safeAttachmentMime
} from "./utils.js";

export {
  isValidCsrfRequest, isSafeWebhookUrl, safeAttachmentMime,
  hitLogin, failLogin, clearLogin,
  extractOtpServer, extractMagicLinkServer, detectServiceFromEmail, ingest
};

async function handleApi(request, env, url, user) {
  const p = url.pathname, method = request.method;

  if (p === "/api/health" && method === "GET") {
    return json({ ok: true, time: now() });
  }
  if (p.startsWith("/api/auth/")) return handleAuth(request, env, url);
  if (p.startsWith("/api/admin/")) return handleAdmin(request, env, url, user);

  // Semua endpoint di bawah ini wajib login (termasuk /api/app-shell & /api/announcement)
  if (!user) return json({ error: "unauthorized" }, 401);

  if (p === "/api/app-shell" && method === "GET") {
    return new Response(APP_SHELL_HTML, {
      status: 200,
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
      },
    });
  }

  if (p === "/api/announcement" && method === "GET") {
    const row = await env.DB.prepare(
      `SELECT id, message, level, created_at FROM announcements WHERE active = 1 ORDER BY created_at DESC LIMIT 1`
    ).first();
    return json({ announcement: row || null });
  }

  return handleInboxRoutes(request, env, url, user);
}

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
      const assetUrl = new URL(request.url);
      if (assetUrl.pathname === "/privacy") assetUrl.pathname = "/privacy.html";
      else if (assetUrl.pathname === "/terms") assetUrl.pathname = "/terms.html";

      const isHead = request.method === "HEAD";
      const assetReq = new Request(assetUrl, {
        method: isHead ? "GET" : request.method,
        headers: request.headers,
      });
      const res = await env.ASSETS.fetch(assetReq);
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
    await handleScheduled(event, env);
  },
};
