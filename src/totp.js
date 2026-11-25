// src/totp.js — TOTP RFC 6238 (SHA-1, 6 digit, 30 detik) tanpa dependency

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function b32encode(bytes) {
  let bits = 0, value = 0, out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function b32decode(str) {
  const clean = String(str || "").toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function newSecret(bytes = 20) {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return b32encode(b);
}

async function hotp(secretBytes, counter, digits = 6) {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter % 0x100000000);

  const key = await crypto.subtle.importKey("raw", secretBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, buf));

  const offset = mac[mac.length - 1] & 0x0f;
  const code =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);

  return String(code % Math.pow(10, digits)).padStart(digits, "0");
}

export async function totpAt(secretB32, atMs = Date.now(), step = 30, digits = 6) {
  const counter = Math.floor(atMs / 1000 / step);
  return hotp(b32decode(secretB32), counter, digits);
}

// terima ±1 langkah (30 detik) untuk toleransi jam
export async function verifyTotp(secretB32, code, window = 1) {
  const clean = String(code || "").replace(/\D/g, "");
  if (clean.length !== 6) return false;
  const secretBytes = b32decode(secretB32);
  if (!secretBytes.length) return false;
  const step = 30, now = Date.now();
  const base = Math.floor(now / 1000 / step);
  for (let d = -window; d <= window; d++) {
    const candidate = await hotp(secretBytes, base + d, 6);
    let diff = 0;
    for (let i = 0; i < 6; i++) diff |= candidate.charCodeAt(i) ^ clean.charCodeAt(i);
    if (diff === 0) return true;
  }
  return false;
}

export function otpauthUri(secretB32, account, issuer = "menyurat") {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({
    secret: secretB32,
    issuer,
    algorithm: "SHA1",
    digits: "6",
    period: "30",
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

export function recoveryCodes(n = 8) {
  const out = [];
  for (let i = 0; i < n; i++) {
    const b = new Uint8Array(5);
    crypto.getRandomValues(b);
    const hex = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
    out.push(hex.slice(0, 4) + "-" + hex.slice(4, 8));
  }
  return out;
}
