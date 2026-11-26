// src/routes/inbox.js — Inbox, messages, attachments, API keys, SSE events, and AccountMatrix routes
import { randomToken, sha256Hex } from "../auth.js";
import { totpAt, b32decode } from "../totp.js";
import { handleWebhookRoutes } from "./webhooks.js";
import {
  now, isStaff, rank, TTL_ROLE, TTL_MAX, TTL_MAX_ROLE, TTL_MIN, ttlFor,
  json, randLocal, digits, validLocal, normalizeLocal, ipOf,
  zipStore, csvCell, paramsFor, isReservedLocal, hitRate, audit,
  listDomains, getDomain, resolveDomain, inboxRow, purgeInboxContents,
  ensureInbox, inboxRowOrRestoreFromMatrix, canSee, listMessages, getMessage,
  quotaCheck, store, fileGet, fileDel, safeAttachmentMime,
  encryptVaultField, decryptVaultField
} from "../utils.js";

/* ---------------- SSE ---------------- */
export async function handleEvents(request, env, url, user) {
  const rl = await hitRate(env, "sse|" + ipOf(request), 60, 5 * 60_000);
  if (!rl.ok) return json({ error: "too_many_requests", retry_after: rl.retry }, 429);
  const address = (url.searchParams.get("address") || "").toLowerCase();
  const box = await inboxRowOrRestoreFromMatrix(env, address);
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

/* ---------------- AccountMatrix helpers & router ---------------- */
export function parseTotpSecretInput(raw) {
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

export function generateStrongPassword(len = 18) {
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

export function cleanHtmlToPlainText(html) {
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

export function extractOtpServer(subject, textBody, htmlBody) {
  const subj = String(subject || "").trim();
  const cleanHtml = htmlBody ? cleanHtmlToPlainText(htmlBody) : "";
  const rawTxt = String(textBody || "");
  const cssPolluted = /@font-face|\bbox-sizing\s*:|mso-table-lspace|\bmargin\s*:\s*0/i.test(rawTxt);
  const body = ((cssPolluted && cleanHtml) ? cleanHtml : (rawTxt || cleanHtml))
    .replace(/#[0-9a-fA-F]{3,8}\b/g, " ")
    .replace(/https?:\/\/\S+/gi, " ")
    .slice(0, 12000);
  const combined = `${subj} \n ${body}`;
  const hasCtx = /\b(otp|kode|code|pin|verifikasi|verification|verify|passcode|token|authenticat|masuk|login|sign[\s-]?in|confirm|konfirmasi|sandi|password|security|aktivasi|activate)\b/i.test(combined);
  if (!hasCtx) return null;

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

  const beforeRe = /\b(\d{4,8})\b[^0-9A-Za-z\n]{0,24}\b(?:adalah\s+kode|is\s+your\s+(?:verification|security|login|sign[-\s]?in|confirmation|one-time|temporary)?\s*(?:code|otp|pin))\b/i.exec(combined);
  if (beforeRe) return beforeRe[1];

  const sixSubj = /\b(\d{6})\b/.exec(subj);
  if (sixSubj && !/^(19\d\d|20[2-3]\d|000000)$/.test(sixSubj[1])) return sixSubj[1];
  const sixRe = /\b([0-9]{6})\b/g;
  while ((m = sixRe.exec(body)) !== null) {
    const c = m[1];
    if (!/^(19\d\d|20[2-3]\d|000000)$/.test(c)) return c;
  }
  return null;
}

export function extractMagicLinkServer(subject, textBody, htmlBody, hasExtractedOtp = false) {
  const subj = String(subject || "");
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

export function detectServiceFromEmail(fromAddr, fromName, subject) {
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

export function detectStatusFromSubjects(subjects) {
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

export function isAutoDetectPlaceholder(svc) {
  const s = String(svc || "").trim().toLowerCase();
  return !s || s === "auto-detect" || s === "auto" || s.startsWith("auto-detect ");
}

export function matchServiceFuzzy(targetSvcRaw, detectedSvcRaw, fromAddr, fromName, subject) {
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

export async function ensureMatrixForInbox(env, userId, address, note = null, nowMs = now()) {
  if (!userId || !address) return;
  try {
    const existing = await env.DB.prepare(
      `SELECT id FROM matrix_accounts WHERE user_id = ?1 AND address = ?2 AND status != 'archived' LIMIT 1`
    ).bind(userId, address).first();
    if (existing) return;
    const cleanSvc = (note && String(note).trim()) ? String(note).trim().slice(0, 60) : "Auto-Detect";
    const localPart = address.split("@")[0] || "user";
    const username = localPart.replace(/[._-]/g, "");
    const encPw = await encryptVaultField(env, generateStrongPassword(18));
    await env.DB.prepare(
      `INSERT INTO matrix_accounts
         (id, user_id, service, tag, address, username, password, totp_secret,
          api_key, recovery_codes, opsec_note, status, expires_at, created_at, updated_at)
       VALUES (?1,?2,?3,'#Inbox',?4,?5,?6,NULL,NULL,NULL,'Dibuat dari Inbox menyurat.me','active',NULL,?7,?7)`
    ).bind(crypto.randomUUID(), userId, cleanSvc, address, username, encPw, nowMs).run();
  } catch {}
}

export async function autoRegisterMatrixFromEmail(env, userId, inboxAddr, fromAddr, fromName, subject, receivedAt = now()) {
  if (!userId || !inboxAddr) return;
  const service = detectServiceFromEmail(fromAddr, fromName, subject);
  if (!service) return;
  const { results: addrRows } = await env.DB.prepare(
    `SELECT id, service, tag, status FROM matrix_accounts WHERE user_id = ?1 AND address = ?2`
  ).bind(userId, inboxAddr).all();
  const rows = addrRows || [];

  const detStatus = detectStatusFromSubjects([subject || ""]);

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

  const placeholder = rows.find((r) => r.status !== "archived" && isAutoDetectPlaceholder(r.service));
  if (placeholder) {
    const nextStatus = detStatus === "burned" ? "burned" : (detStatus === "cooldown" && placeholder.status === "active" ? "cooldown" : placeholder.status);
    await env.DB.batch([
      env.DB.prepare(`UPDATE matrix_accounts SET service = ?2, status = ?3, updated_at = ?4 WHERE id = ?1`)
        .bind(placeholder.id, service, nextStatus, receivedAt),
      env.DB.prepare(`UPDATE inboxes SET note = ?2 WHERE address = ?1 AND (note IS NULL OR note = '' OR LOWER(note) LIKE 'auto-detect%')`)
        .bind(inboxAddr, service),
    ]);
    return;
  }

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
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO matrix_accounts
         (id, user_id, service, tag, address, username, password, totp_secret,
          api_key, recovery_codes, opsec_note, status, expires_at, created_at, updated_at)
       VALUES (?1,?2,?3,'#Auto',?4,?5,NULL,NULL,NULL,NULL,'Auto-detected dari email masuk',?6,NULL,?7,?7)`
    ).bind(crypto.randomUUID(), userId, service, inboxAddr, username, detStatus, receivedAt),
    env.DB.prepare(`UPDATE inboxes SET note = ?2 WHERE address = ?1 AND (note IS NULL OR note = '')`)
      .bind(inboxAddr, service),
  ]);
}

export async function syncMatrixFromInboxes(env, userId, nowMs = now()) {
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
    byAddr.set(g.address, (byAddr.get(g.address) || []).concat([{ address: g.address, service: g.service, tag, status }]));
    added++;
  }

  const { results: activeBoxes } = await env.DB.prepare(
    `SELECT address, note, created_at FROM inboxes WHERE user_id = ?1 AND (expires_at > ?2 OR pinned = 1)`
  ).bind(userId, nowMs).all();
  for (const b of activeBoxes || []) {
    const addr = b.address.toLowerCase();
    if (byAddr.has(addr)) continue;
    const svc = (b.note && String(b.note).trim()) ? String(b.note).trim().slice(0, 60) : "Auto-Detect";
    const localPart = addr.split("@")[0] || "user";
    const username = localPart.replace(/[._-]/g, "");
    const t = b.created_at || nowMs;
    const encPw = await encryptVaultField(env, generateStrongPassword(18));
    await env.DB.prepare(
      `INSERT INTO matrix_accounts
         (id, user_id, service, tag, address, username, password, totp_secret,
          api_key, recovery_codes, opsec_note, status, expires_at, created_at, updated_at)
       VALUES (?1,?2,?3,'#Inbox',?4,?5,?6,NULL,NULL,NULL,'Auto-synced dari daftar alamat menyurat.me','active',NULL,?7,?7)`
    ).bind(crypto.randomUUID(), userId, svc, addr, username, encPw, t).run();
    byAddr.set(addr, [{ address: addr, service: svc, tag: "#Inbox", status: "active" }]);
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
  // Decrypt sensitive vault fields (and auto-migrate legacy plaintext rows in D1 to AES-256-GCM)
  const needsEncryptMigration =
    (row.password && !String(row.password).startsWith("enc:v1:")) ||
    (row.totp_secret && !String(row.totp_secret).startsWith("enc:v1:")) ||
    (row.api_key && !String(row.api_key).startsWith("enc:v1:")) ||
    (row.recovery_codes && !String(row.recovery_codes).startsWith("enc:v1:"));

  const [plainPassword, plainTotpSecret, plainApiKey, plainRecovery] = await Promise.all([
    decryptVaultField(env, row.password),
    decryptVaultField(env, row.totp_secret),
    decryptVaultField(env, row.api_key),
    decryptVaultField(env, row.recovery_codes),
  ]);

  if (needsEncryptMigration) {
    try {
      const [ePw, eTotp, eKey, eRec] = await Promise.all([
        encryptVaultField(env, plainPassword),
        encryptVaultField(env, plainTotpSecret),
        encryptVaultField(env, plainApiKey),
        encryptVaultField(env, plainRecovery),
      ]);
      await env.DB.prepare(
        `UPDATE matrix_accounts SET password = ?2, totp_secret = ?3, api_key = ?4, recovery_codes = ?5 WHERE id = ?1`
      ).bind(row.id, ePw, eTotp, eKey, eRec).run();
    } catch {}
  }

  let totpCode = null;
  let totpRem  = null;
  if (plainTotpSecret) {
    try {
      totpCode = await totpAt(plainTotpSecret, nowMs);
      totpRem  = 30 - (Math.floor(nowMs / 1000) % 30);
    } catch {}
  }
  const allMsgs = preloadedMsgs || await fetchInboxMessagesForMatrix(env, row.address);

  let currentService = String(row.service || "").trim() || "Auto-Detect";
  if (isAutoDetectPlaceholder(currentService) && allMsgs.length > 0) {
    const firstDetected = detectServiceFromEmail(allMsgs[0].from_addr, allMsgs[0].from_name, allMsgs[0].subject);
    if (firstDetected) {
      currentService = firstDetected;
      row.service = firstDetected;
      try {
        await env.DB.batch([
          env.DB.prepare(`UPDATE matrix_accounts SET service = ?2, updated_at = ?3 WHERE id = ?1`)
            .bind(row.id, firstDetected, allMsgs[0].received_at || nowMs),
          env.DB.prepare(`UPDATE inboxes SET note = ?2 WHERE address = ?1 AND (note IS NULL OR note = '' OR LOWER(note) LIKE 'auto-detect%')`)
            .bind(row.address, firstDetected),
        ]);
      } catch {}
    }
  }

  const svcMsgs = allMsgs.filter((m) => {
    const det = detectServiceFromEmail(m.from_addr, m.from_name, m.subject);
    return matchServiceFuzzy(currentService, det, m.from_addr, m.from_name, m.subject);
  });

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
    password: plainPassword || null,
    totp_secret: plainTotpSecret || null,
    totp_code: totpCode,
    totp_rem: totpRem,
    api_key: plainApiKey || null,
    recovery_codes: plainRecovery || null,
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

  if (p === "/api/matrix/sync" && method === "POST") {
    const added = await syncMatrixFromInboxes(env, user.id, t);
    const { results } = await env.DB.prepare(
      `SELECT * FROM matrix_accounts WHERE user_id = ?1 AND status != 'archived' ORDER BY updated_at DESC, created_at DESC LIMIT 300`
    ).bind(user.id).all();
    const list = await enrichMatrixAccountList(env, results || [], t);
    return json({ ok: true, added, accounts: list });
  }

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

    const [encPassword, encTotp, encApiKey, encRecCodes] = await Promise.all([
      encryptVaultField(env, password),
      encryptVaultField(env, totpSecret),
      encryptVaultField(env, apiKey),
      encryptVaultField(env, recCodes),
    ]);

    const id = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO matrix_accounts
         (id, user_id, service, tag, address, username, password, totp_secret,
          api_key, recovery_codes, opsec_note, status, expires_at, created_at, updated_at)
       VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?14)`
    ).bind(
      id, user.id, service, tag, fullAddress, username, encPassword, encTotp,
      encApiKey, encRecCodes, opsecNote, status, expiresAt, t
    ).run();

    await audit(env, user, "matrix.spawn", fullAddress, { id, service, tag }, request);
    const createdRow = await env.DB.prepare(`SELECT * FROM matrix_accounts WHERE id = ?1`).bind(id).first();
    return json({ ok: true, account: await enrichMatrixAccount(env, createdRow, t) }, 201);
  }

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

      const [encPassword, encTotp, encApiKey, encRecCodes] = await Promise.all([
        encryptVaultField(env, password),
        encryptVaultField(env, totpSecret),
        encryptVaultField(env, apiKey),
        encryptVaultField(env, recCodes),
      ]);

      await env.DB.prepare(
        `UPDATE matrix_accounts
            SET service = ?2, tag = ?3, username = ?4, password = ?5, totp_secret = ?6,
                api_key = ?7, recovery_codes = ?8, opsec_note = ?9, status = ?10,
                expires_at = ?11, updated_at = ?12
          WHERE id = ?1`
      ).bind(
        id, service, tag, username, encPassword, encTotp,
        encApiKey, encRecCodes, opsecNote, status, expiresAt, t
      ).run();

      if (b.service !== undefined || b.tag !== undefined) {
        try {
          const boxNote = (tag && tag !== "#Auto" && tag !== "#Inbox") ? `${service} (${tag})` : service;
          await env.DB.prepare(`UPDATE inboxes SET note = ?2 WHERE address = ?1 AND user_id = ?3`)
            .bind(row.address, boxNote.slice(0, 120), row.user_id).run();
        } catch {}
      }

      const updated = await env.DB.prepare(`SELECT * FROM matrix_accounts WHERE id = ?1`).bind(id).first();
      return json({ ok: true, account: await enrichMatrixAccount(env, updated, t) });
    }

    if (method === "DELETE") {
      if (url.searchParams.get("hard") === "1") {
        await env.DB.prepare(`DELETE FROM matrix_accounts WHERE id = ?1`).bind(id).run();
      } else {
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

/* ---------------- main member/inbox router ---------------- */
export async function handleInboxRoutes(request, env, url, user) {
  const p = url.pathname, method = request.method;

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

  /* --- inbox creation & listing --- */
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
    await ensureMatrixForInbox(env, user.id, info.address, note);
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
    const note = qp.get("note") || null;
    const info = await ensureInbox(env, address, r.domain, user.id, ttlFor(user, qp.get("ttl")), note);
    if (info.conflict) {
      return json({ error: "address_taken", note: "Alamat ini sedang digunakan oleh pengguna lain." }, 409);
    }
    await ensureMatrixForInbox(env, user.id, address, note);
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

  const mClearMsgs = p.match(/^\/api\/inbox\/([^/]+)\/messages$/);
  if (mClearMsgs && method === "DELETE") {
    const address = decodeURIComponent(mClearMsgs[1]).toLowerCase();
    const box = await inboxRow(env, address);
    if (!box) return json({ error: "inbox_not_found" }, 404);
    // Prinsip Owner = Dewa: Admin hanya boleh mengosongkan inbox miliknya sendiri atau member/vip
    if (!(await canSee(env, user, box))) return json({ error: "forbidden" }, 403);
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

  const mExport = p.match(/^\/api\/inbox\/([^/]+)\/export$/);
  if (mExport && method === "GET") {
    const address = decodeURIComponent(mExport[1]).toLowerCase();
    const box = await inboxRowOrRestoreFromMatrix(env, address);
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
    return handleWebhookRoutes(request, env, url, user, address);
  }

  const mInbox = p.match(/^\/api\/inbox\/([^/]+)$/);
  if (mInbox && method === "GET") {
    const address = decodeURIComponent(mInbox[1]).toLowerCase();
    const box = await inboxRowOrRestoreFromMatrix(env, address);
    if (!box) return json({ error: "inbox_not_found", address }, 404);
    if (!(await canSee(env, user, box))) return json({ error: "not_found" }, 404);
    return json({ address, domain: box.domain, expires_at: box.expires_at, pinned: box.pinned, note: box.note || null, messages: await listMessages(env, address) });
  }

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
    try {
      await env.DB.prepare(
        `UPDATE matrix_accounts SET status = 'archived', updated_at = ?2
          WHERE address = ?1 AND (tag = '#Auto' OR tag = '#Inbox')
            AND totp_secret IS NULL AND api_key IS NULL AND recovery_codes IS NULL`
      ).bind(address, now()).run();
    } catch {}
    await audit(env, user, "inbox.delete", address, { owner: box.user_id }, request);
    return json({ ok: true, address });
  }

  if (mInbox && method === "PATCH") {
    const address = decodeURIComponent(mInbox[1]).toLowerCase();
    const box = await inboxRowOrRestoreFromMatrix(env, address);
    if (!box) return json({ error: "inbox_not_found" }, 404);
    // Prinsip Owner = Dewa: Admin tidak boleh mengubah label, pin, atau TTL inbox milik Owner/Admin lain
    if (!(await canSee(env, user, box))) return json({ error: "forbidden" }, 403);
    const body = await request.json().catch(() => ({}));

    if (body && body.note !== undefined) {
      const cleanNote = String(body.note || "").trim().slice(0, 120) || null;
      await env.DB.prepare(`UPDATE inboxes SET note = ?2 WHERE address = ?1`).bind(address, cleanNote).run();
      if (cleanNote && box.user_id) {
        try {
          const { results: mxRows } = await env.DB.prepare(
            `SELECT id, service FROM matrix_accounts WHERE user_id = ?1 AND address = ?2 AND status != 'archived'`
          ).bind(box.user_id, address).all();
          const list = mxRows || [];
          const targetRow = list.find((r) => isAutoDetectPlaceholder(r.service)) || (list.length === 1 ? list[0] : null);
          if (targetRow) {
            await env.DB.prepare(`UPDATE matrix_accounts SET service = ?2, updated_at = ?3 WHERE id = ?1`)
              .bind(targetRow.id, cleanNote.slice(0, 60), now()).run();
          }
        } catch {}
      }
      await audit(env, user, "inbox.note", address, { note: cleanNote }, request);
      if (body.ttl === undefined && body.days === undefined && body.pinned === undefined) {
        return json({ ok: true, address, note: cleanNote });
      }
    }

    const wasActive = box.expires_at > now() || box.pinned === 1;
    if (!wasActive && (body.ttl !== undefined || body.days !== undefined || body.pinned)) {
      const q = await quotaCheck(env, user, box.domain);
      if (q) return json(q, 429);
    }

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
    const box = await inboxRowOrRestoreFromMatrix(env, address);
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
    const box = await inboxRowOrRestoreFromMatrix(env, address);
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
    const box = await inboxRowOrRestoreFromMatrix(env, address);
    if (!box) return json({ error: "inbox_not_found" }, 404);
    if (!(await canSee(env, user, box))) return json({ error: "not_found" }, 404);
    const att = await env.DB.prepare(
      `SELECT * FROM attachments WHERE id = ?1 AND message_id = ?2 AND inbox = ?3`
    ).bind(attId, messageId, address).first();
    if (!att) return json({ error: "attachment_not_found" }, 404);
    const obj = await fileGet(env, att.r2_key);
    if (!obj) return json({ error: "attachment_not_found" }, 404);
    const safe = String(att.filename || "lampiran").replace(/["\\\r\n]/g, "_");
    const safeMime = safeAttachmentMime(att.mime);
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
