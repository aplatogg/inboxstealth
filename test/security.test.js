// test/security.test.js — Security & regression test suite: Login Lockout, CSRF Guard, Webhook SSRF, MIME Sanitization, and Guest HTML Isolation
import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import worker, {
  isValidCsrfRequest,
  isSafeWebhookUrl,
  resolveAndValidateWebhookHost,
  safeAttachmentMime,
  hitLogin,
  failLogin,
  clearLogin,
  canSee,
  encryptVaultField,
  decryptVaultField,
  extractOtpServer,
} from "../src/index.js";
import { parseEmail } from "../src/mime.js";
import { hashPassword, sha256Hex } from "../src/auth.js";

// Lightweight in-memory D1 mock for auth/lockout integration tests
function createMockEnv() {
  const loginAttempts = new Map();
  const rateLimits = new Map();
  const users = new Map();

  const db = {
    prepare(sql) {
      return {
        _args: [],
        bind(...args) {
          this._args = args;
          return this;
        },
        async first() {
          if (sql.includes("FROM login_attempts WHERE rl_key")) {
            return loginAttempts.get(this._args[0]) || null;
          }
          if (sql.includes("FROM rate_limits WHERE rl_key")) {
            return rateLimits.get(this._args[0]) || null;
          }
          if (sql.includes("FROM users WHERE email")) {
            return users.get(this._args[0]) || null;
          }
          return null;
        },
        async run() {
          if (sql.includes("INSERT INTO login_attempts")) {
            const [key, t] = this._args;
            loginAttempts.set(key, { count: 1, window_start: t, locked_until: 0 });
            return { success: true };
          }
          if (sql.includes("UPDATE login_attempts SET count")) {
            const [key, count, locked] = this._args;
            const prev = loginAttempts.get(key) || { window_start: Date.now() };
            loginAttempts.set(key, { count, window_start: prev.window_start, locked_until: locked });
            return { success: true };
          }
          if (sql.includes("DELETE FROM login_attempts")) {
            loginAttempts.delete(this._args[0]);
            return { success: true };
          }
          if (sql.includes("INSERT INTO rate_limits")) {
            const [key, t] = this._args;
            rateLimits.set(key, { count: 1, window_start: t });
            return { success: true };
          }
          if (sql.includes("UPDATE rate_limits SET count = count + 1")) {
            const [key] = this._args;
            const prev = rateLimits.get(key);
            if (prev) prev.count += 1;
            return { success: true };
          }
          return { success: true };
        },
        async all() {
          return { results: [] };
        },
      };
    },
    async batch(stmts) {
      for (const s of stmts) await s.run();
    },
  };

  return { DB: db, _users: users, _loginAttempts: loginAttempts };
}

describe("1. Login + Lockout & Guest /api/auth/me", () => {
  it("returns 200 { user: null } on GET /api/auth/me for unauthenticated guests", async () => {
    const env = createMockEnv();
    const req = new Request("https://menyurat.me/api/auth/me", { method: "GET" });
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toEqual({ user: null });
  });

  it("blocks unauthenticated guests from /api/app-shell and /api/announcement with 401", async () => {
    const env = createMockEnv();
    const resShell = await worker.fetch(new Request("https://menyurat.me/api/app-shell"), env);
    expect(resShell.status).toBe(401);

    const resAnn = await worker.fetch(new Request("https://menyurat.me/api/announcement"), env);
    expect(resAnn.status).toBe(401);
  });

  it("locks account for 15 minutes after 5 failed login attempts and clears on clearLogin", async () => {
    const env = createMockEnv();
    const ip = "203.0.113.42";
    const email = "user@example.com";

    for (let i = 1; i <= 4; i++) {
      const state = await hitLogin(env, ip, email);
      expect(state.blocked).toBe(false);
      const res = await failLogin(env, state.key, state.row);
      expect(res.remaining).toBe(5 - i);
    }

    // 5th failure triggers 15-minute lockout (900 seconds)
    const fifth = await hitLogin(env, ip, email);
    expect(fifth.blocked).toBe(false);
    const lockRes = await failLogin(env, fifth.key, fifth.row);
    expect(lockRes.locked_for).toBe(900);

    // Subsequent check must be blocked
    const blockedState = await hitLogin(env, ip, email);
    expect(blockedState.blocked).toBe(true);
    expect(blockedState.retry).toBeGreaterThan(800);

    // Full end-to-end POST /api/auth/login while locked returns 429 too_many_attempts
    const loginReq = new Request("https://menyurat.me/api/auth/login", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "origin": "https://menyurat.me",
        "cf-connecting-ip": ip,
      },
      body: JSON.stringify({ email, password: "wrongpassword" }),
    });
    const loginRes = await worker.fetch(loginReq, env);
    expect(loginRes.status).toBe(429);
    const loginJson = await loginRes.json();
    expect(loginJson.error).toBe("too_many_attempts");

    // Clearing login resets lockout
    await clearLogin(env, fifth.key);
    const afterClear = await hitLogin(env, ip, email);
    expect(afterClear.blocked).toBe(false);
  });
});

describe("2. CSRF Guard (isValidCsrfRequest)", () => {
  it("allows safe read methods (GET, HEAD, OPTIONS)", () => {
    const req = new Request("https://menyurat.me/api/domains", {
      method: "GET",
      headers: { "sec-fetch-site": "cross-site" },
    });
    expect(isValidCsrfRequest(req)).toBe(true);
  });

  it("blocks cross-site state-changing requests (Sec-Fetch-Site: cross-site)", () => {
    const req = new Request("https://menyurat.me/api/new", {
      method: "POST",
      headers: { "sec-fetch-site": "cross-site" },
    });
    expect(isValidCsrfRequest(req)).toBe(false);
  });

  it("blocks state-changing requests from untrusted Origin", () => {
    const req = new Request("https://menyurat.me/api/new", {
      method: "POST",
      headers: { "origin": "https://evil-attacker.com" },
    });
    expect(isValidCsrfRequest(req)).toBe(false);
  });

  it("allows state-changing requests from same origin or www subdomain", () => {
    const req1 = new Request("https://menyurat.me/api/new", {
      method: "POST",
      headers: { "origin": "https://menyurat.me", "sec-fetch-site": "same-origin" },
    });
    const req2 = new Request("https://menyurat.me/api/new", {
      method: "POST",
      headers: { "origin": "https://www.menyurat.me" },
    });
    expect(isValidCsrfRequest(req1)).toBe(true);
    expect(isValidCsrfRequest(req2)).toBe(true);
  });

  it("allows state-changing requests authenticated via x-api-key or Bearer mn_ token", () => {
    const reqKey = new Request("https://menyurat.me/api/new", {
      method: "POST",
      headers: { "x-api-key": "mn_testkey123", "sec-fetch-site": "cross-site" },
    });
    const reqBearer = new Request("https://menyurat.me/api/new", {
      method: "POST",
      headers: { "authorization": "Bearer mn_testkey123", "origin": "https://cli.example.com" },
    });
    expect(isValidCsrfRequest(reqKey)).toBe(true);
    expect(isValidCsrfRequest(reqBearer)).toBe(true);
  });
});

describe("3. Webhook SSRF Filter (isSafeWebhookUrl)", () => {
  it("blocks loopback, private RFC1918, link-local metadata, CGNAT, IPv6, and integer IP encodings", () => {
    const blockedUrls = [
      "http://127.0.0.1:8080/hook",
      "http://localhost/hook",
      "https://sub.localhost/hook",
      "http://internal.local/hook",
      "http://service.internal/hook",
      "http://169.254.169.254/latest/meta-data/",
      "http://10.0.0.1/hook",
      "http://172.16.0.1/hook",
      "http://172.31.255.255/hook",
      "http://192.168.1.1/hook",
      "http://100.64.0.1/hook",
      "http://0.0.0.0/hook",
      "http://224.0.0.1/hook",
      "http://[::1]/hook",
      "http://[fe80::1]/hook",
      "http://[fc00::1]/hook",
      "http://0x7f000001/hook",
      "http://2130706433/hook",
      "https://my-worker.workers.dev/hook",
      "https://menyurat.me/api/webhook",
      "https://sub.menyurat.me/hook",
      "ftp://example.com/hook",
      "https://user:pass@example.com/hook",
    ];
    for (const u of blockedUrls) {
      expect(isSafeWebhookUrl(u, "menyurat.me")).toBe(false);
    }
  });

  it("allows valid public HTTP/HTTPS webhook destinations", () => {
    expect(isSafeWebhookUrl("https://hooks.slack.com/services/T00/B00/X00", "menyurat.me")).toBe(true);
    expect(isSafeWebhookUrl("https://discord.com/api/webhooks/123456/abcdef", "menyurat.me")).toBe(true);
    expect(isSafeWebhookUrl("https://8.8.8.8/webhook", "menyurat.me")).toBe(true);
  });

  it("blocks DNS rebinding domains that resolve to private/loopback IPs via DoH", async () => {
    const mockRebindFetch = async () => new Response(JSON.stringify({
      Status: 0,
      Answer: [{ type: 1, data: "127.0.0.1" }],
    }), { status: 200 });
    const mockMetaFetch = async () => new Response(JSON.stringify({
      Status: 0,
      Answer: [{ type: 1, data: "169.254.169.254" }],
    }), { status: 200 });
    const mockPublicFetch = async () => new Response(JSON.stringify({
      Status: 0,
      Answer: [{ type: 1, data: "93.184.216.34" }],
    }), { status: 200 });

    expect(await resolveAndValidateWebhookHost("https://rebind.attacker.com/hook", "menyurat.me", mockRebindFetch)).toBe(false);
    expect(await resolveAndValidateWebhookHost("https://meta.attacker.com/hook", "menyurat.me", mockMetaFetch)).toBe(false);
    expect(await resolveAndValidateWebhookHost("https://webhook.example.com/hook", "menyurat.me", mockPublicFetch)).toBe(true);
  });
});

describe("4. Owner vs Admin Hierarchy & AES-256-GCM Vault Encryption", () => {
  it("prevents Admin from seeing or modifying Owner or fellow Admin inboxes (canSee)", async () => {
    const env = {
      DB: {
        prepare() {
          return {
            _id: null,
            bind(id) { this._id = id; return this; },
            async first() {
              if (this._id === "owner-1") return { role: "owner" };
              if (this._id === "admin-2") return { role: "admin" };
              if (this._id === "vip-1") return { role: "vip" };
              return { role: "member" };
            },
          };
        },
      },
    };
    const adminUser = { id: "admin-1", role: "admin" };
    const ownerUser = { id: "owner-1", role: "owner" };

    // Admin CANNOT see or touch Owner's inbox or another Admin's inbox
    expect(await canSee(env, adminUser, { address: "god@menyurat.me", user_id: "owner-1" })).toBe(false);
    expect(await canSee(env, adminUser, { address: "peer@menyurat.me", user_id: "admin-2" })).toBe(false);
    // Admin CAN see VIP/Member or their own inbox
    expect(await canSee(env, adminUser, { address: "vip@menyurat.me", user_id: "vip-1" })).toBe(true);
    expect(await canSee(env, adminUser, { address: "own@menyurat.me", user_id: "admin-1" })).toBe(true);
    // Owner CAN see everything
    expect(await canSee(env, ownerUser, { address: "peer@menyurat.me", user_id: "admin-2" })).toBe(true);
  });

  it("encrypts and decrypts AccountMatrix vault fields with AES-256-GCM (enc:v1:...)", async () => {
    const env = { VAULT_SECRET: "unit-test-vault-secret-key-2026" };
    const rawPass = "K9#mP2$vL8@xQ4!zR7";
    const cipher = await encryptVaultField(env, rawPass);
    expect(cipher).toMatch(/^enc:v1:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$/);
    expect(cipher).not.toContain(rawPass);

    const decrypted = await decryptVaultField(env, cipher);
    expect(decrypted).toBe(rawPass);

    // Backward compatibility with legacy plaintext
    expect(await decryptVaultField(env, "legacy-plain")).toBe("legacy-plain");
  });

  it("prevents email enumeration on /api/auth/register by returning 201 generic pending message", async () => {
    const env = createMockEnv();
    env._users.set("existing@menyurat.me", { id: "u-1", email: "existing@menyurat.me" });

    const req = new Request("https://menyurat.me/api/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json", "origin": "https://menyurat.me" },
      body: JSON.stringify({ email: "existing@menyurat.me", password: "ValidPassword123!" }),
    });
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.status).toBe("pending");
  });
});

describe("5. MIME & Attachment Sanitization", () => {
  it("strips <style>, <script>, and comments from HTML-only emails and extracts real OTP instead of CSS hex codes", () => {
    const rawEmail = [
      "From: IONOS Customer Service <customer@ionos.com>",
      "To: test.user@example.com",
      "Subject: Temporary password request",
      "Content-Type: text/html; charset=utf-8",
      "",
      "<!doctype html><html><head><style>body{color:#333333;background:#001a3c}</style></head>",
      "<body><!-- comment 123456 --><script>var x = 999999;</script>",
      "<p>544654 is your verification code for IONOS.</p></body></html>",
    ].join("\r\n");

    const parsed = parseEmail(rawEmail);
    expect(parsed.text).not.toContain("#333333");
    expect(parsed.text).not.toContain("999999");
    expect(parsed.text).toContain("544654 is your verification code");

    const otp = extractOtpServer(parsed.subject, parsed.text, parsed.html);
    expect(otp).toBe("544654");
  });

  it("downgrades dangerous attachment MIME types (HTML, SVG, JS) to application/octet-stream", () => {
    expect(safeAttachmentMime("text/html; charset=utf-8")).toBe("application/octet-stream");
    expect(safeAttachmentMime("image/svg+xml")).toBe("application/octet-stream");
    expect(safeAttachmentMime("application/javascript")).toBe("application/octet-stream");
    expect(safeAttachmentMime("application/xhtml+xml")).toBe("application/octet-stream");

    expect(safeAttachmentMime("image/png")).toBe("image/png");
    expect(safeAttachmentMime("application/pdf")).toBe("application/pdf");
    expect(safeAttachmentMime("text/plain; charset=utf-8")).toBe("text/plain");
  });
});

describe("5. Guest Landing HTML Isolation ([P1])", () => {
  it("ensures public/index.html contains no dashboard modals, endpoint lists, or dashboard shell markup", () => {
    const indexHtml = fs.readFileSync(path.resolve("public/index.html"), "utf8");
    expect(indexHtml).not.toContain('id="appShell"');
    expect(indexHtml).not.toContain("<dialog");
    expect(indexHtml).not.toContain("/api/new");
    expect(indexHtml).not.toContain("/api/custom");
    expect(indexHtml).not.toContain("/api/inbox/:alamat");
    expect(indexHtml).toContain('href="/privacy"');
    expect(indexHtml).toContain('href="/terms"');
    expect(indexHtml).toContain('id="mobileLoginJump"');
  });
});
