// src/mime.js — parser MIME (tanpa dependency), dengan ekstraksi attachment.
// parseEmail(raw) -> { messageId, subject, from, to, date, text, html, attachments[] }
// attachments: [{ filename, mime, bytes: Uint8Array }]

/* ---------- header ---------- */
function splitHeaders(text) {
  const m = text.match(/\r?\n\r?\n/);
  if (!m) return { headerText: text, body: "" };
  return { headerText: text.slice(0, m.index), body: text.slice(m.index + m[0].length) };
}

function parseHeaders(headerText) {
  const unfolded = headerText.replace(/\r?\n[ \t]+/g, " ");
  const out = {};
  for (const line of unfolded.split(/\r?\n/)) {
    const i = line.indexOf(":");
    if (i <= 0) continue;
    const k = line.slice(0, i).trim().toLowerCase();
    const v = line.slice(i + 1).trim();
    out[k] = out[k] ? out[k] + ", " + v : v;
  }
  return out;
}

function param(str, name) {
  if (!str) return "";
  // RFC 5987 ext-value: name*=UTF-8''percent-encoded
  const extRe = new RegExp("(?:^|;\\s*)" + name + "\\*\\s*=\\s*(?:\"([^\"]*)\"|([^;\\s]+))", "i");
  const extM = extRe.exec(str);
  if (extM) {
    const raw = (extM[1] !== undefined ? extM[1] : extM[2]).trim();
    const parts = raw.split("'");
    if (parts.length >= 3) {
      const charset = parts[0] || "utf-8";
      const encoded = parts.slice(2).join("'");
      try {
        const bytes = [];
        for (let i = 0; i < encoded.length; i++) {
          if (encoded[i] === "%" && /^[0-9A-Fa-f]{2}$/.test(encoded.slice(i + 1, i + 3))) {
            bytes.push(parseInt(encoded.slice(i + 1, i + 3), 16));
            i += 2;
          } else {
            bytes.push(encoded.charCodeAt(i));
          }
        }
        return bytesToText(new Uint8Array(bytes), charset);
      } catch {}
    }
  }
  const re = new RegExp("(?:^|;\\s*)" + name + '\\s*=\\s*(?:"([^"]*)"|([^;\\s]+))', "i");
  const m = re.exec(str);
  if (!m) return "";
  return m[1] !== undefined ? m[1] : m[2];
}

/* ---------- encoding ---------- */
function b64ToBytes(input) {
  const clean = String(input).replace(/[^A-Za-z0-9+/=]/g, "");
  try {
    const bin = atob(clean);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return new Uint8Array(0);
  }
}

function bytesToB64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function qpToBytes(input) {
  const s = String(input).replace(/=\r?\n/g, "");
  const tmp = [];
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "=" && /^[0-9A-Fa-f]{2}$/.test(s.slice(i + 1, i + 3))) {
      tmp.push(parseInt(s.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      const code = s.charCodeAt(i);
      if (code < 128) tmp.push(code);
      else {
        for (const b of new TextEncoder().encode(s[i])) tmp.push(b);
      }
    }
  }
  return new Uint8Array(tmp);
}

function decodeToBytes(body, cte) {
  const enc = (cte || "").toLowerCase().trim();
  if (enc === "base64") return b64ToBytes(body);
  if (enc === "quoted-printable") return qpToBytes(body);
  return new TextEncoder().encode(body);
}

function bytesToText(bytes, charset) {
  try { return new TextDecoder(charset || "utf-8", { fatal: false }).decode(bytes); }
  catch { return new TextDecoder("utf-8", { fatal: false }).decode(bytes); }
}

function decodeWord(input) {
  if (!input) return "";
  // Merge adjacent RFC 2047 encoded-words separated only by linear whitespace
  const joined = String(input).replace(/\?=\s+=\?/g, "?==?");
  return joined.replace(/=\?([^?]+)\?([BbQq])\?([^?]+)\?=/g, (_, charset, enc, text) => {
    try {
      if (enc.toUpperCase() === "B") return bytesToText(b64ToBytes(text), charset);
      const q = text.replace(/_/g, " ");
      const bytes = [];
      for (let i = 0; i < q.length; i++) {
        if (q[i] === "=" && /^[0-9A-Fa-f]{2}$/.test(q.slice(i + 1, i + 3))) {
          bytes.push(parseInt(q.slice(i + 1, i + 3), 16));
          i += 2;
        } else {
          const code = q.charCodeAt(i);
          if (code < 128) bytes.push(code);
          else {
            for (const b of new TextEncoder().encode(q[i])) bytes.push(b);
          }
        }
      }
      return bytesToText(new Uint8Array(bytes), charset);
    } catch { return text; }
  });
}

/* ---------- multipart ---------- */
function boundaryOf(contentType) {
  const b = param(contentType || "", "boundary");
  return b || null;
}

function splitParts(body, boundary) {
  const delim = "--" + boundary;
  const endDelim = delim + "--";
  const parts = [];
  let cur = null;
  for (const line of body.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed === delim || trimmed === endDelim) {
      if (trimmed === endDelim) { if (cur) parts.push(cur.join("\n")); cur = null; break; }
      if (cur) parts.push(cur.join("\n"));
      cur = [];
    } else if (cur) cur.push(line);
  }
  if (cur) parts.push(cur.join("\n"));
  return parts;
}

function parseAddress(input) {
  const s = (input || "").trim();
  const m = /^\s*"?([^"<]*)"?\s*<([^>]+)>/.exec(s);
  if (m) return { name: m[1].trim(), address: m[2].trim() };
  return { name: "", address: s };
}

/* ---------- walk ---------- */
function walk(headerText, body, out, depth) {
  const h = parseHeaders(headerText);
  const ct = h["content-type"] || "text/plain; charset=utf-8";
  const type = ct.split(";")[0].trim().toLowerCase();
  const boundary = boundaryOf(ct);

  if (boundary && depth < 5) {
    for (const part of splitParts(body, boundary)) {
      const sp = splitHeaders(part);
      walk(sp.headerText, sp.body, out, depth + 1);
    }
    return;
  }

  const disp = h["content-disposition"] || "";
  const isAttachment = /^\s*attachment\b/i.test(disp);
  const filename = decodeWord(param(disp, "filename") || param(ct, "name") || "");
  const cid = (h["content-id"] || "").trim().replace(/^<|>$/g, "");
  const cte = h["content-transfer-encoding"] || "7bit";
  const charset = param(ct, "charset") || "utf-8";
  const bytes = decodeToBytes(body, cte);

  if (cid && /^image\//i.test(type) && bytes.length > 0 && bytes.length <= 1024 * 1024) {
    const dataUri = `data:${type};base64,${bytesToB64(bytes)}`;
    out.cids[cid] = dataUri;
    const shortCid = cid.split("@")[0];
    if (shortCid) out.cids[shortCid] = dataUri;
    if (filename) out.cids[filename] = dataUri;
  }

  if (!isAttachment && type === "text/plain" && out.text === null) {
    out.text = bytesToText(bytes, charset);
    return;
  }
  if (!isAttachment && type === "text/html" && out.html === null) {
    out.html = bytesToText(bytes, charset);
    return;
  }
  if (isAttachment || filename) {
    if (bytes.length) {
      out.attachments.push({ filename: filename || "lampiran", mime: type || "application/octet-stream", bytes });
    }
    return;
  }
  if (type === "text/plain" && out.text === null) out.text = bytesToText(bytes, charset);
  else if (type === "text/html" && out.html === null) out.html = bytesToText(bytes, charset);
}

export function parseEmail(raw) {
  const { headerText, body } = splitHeaders(raw);
  const h = parseHeaders(headerText);

  const out = {
    messageId: (h["message-id"] || "").trim() || null,
    subject: decodeWord(h["subject"] || ""),
    from: parseAddress(decodeWord(h["from"] || "")),
    to: decodeWord(h["to"] || ""),
    date: h["date"] || null,
    text: null,
    html: null,
    attachments: [],
    cids: {},
  };

  walk(headerText, body, out, 0);

  if (out.html && Object.keys(out.cids).length) {
    out.html = out.html.replace(/\b(src\s*=\s*["'])cid:([^"'>\s]+)(["'])/gi, (full, pre, rawCid, post) => {
      let clean = rawCid.trim().replace(/^<|>$/g, "");
      try { clean = decodeURIComponent(clean); } catch {}
      const dataUri = out.cids[clean] || out.cids[clean.split("@")[0]];
      return dataUri ? (pre + dataUri + post) : full;
    });
  }

  if (!out.text && out.html) {
    out.text = out.html
      .replace(/<!--[\s\S]*?-->/g, " ")
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<script[\s\S]*?<\/script>/gi, " ")
      .replace(/<head[\s\S]*?<\/head>/gi, " ")
      .replace(/<[^>]+>/g, " ")
      .replace(/&nbsp;/gi, " ")
      .replace(/&amp;/gi, "&")
      .replace(/&lt;/gi, "<")
      .replace(/&gt;/gi, ">")
      .replace(/&quot;/gi, '"')
      .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
      .replace(/\s+/g, " ")
      .trim();
  }
  if (out.text === null) out.text = "";
  return out;
}
