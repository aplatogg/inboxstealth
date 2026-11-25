-- Temp Mail multi-domain schema (Cloudflare D1 / SQLite)
-- Jalankan: wrangler d1 execute tempmail_db --file=./schema.sql --remote

-- Domain yang terdaftar. Inbox hanya boleh dibuat di domain terdaftar.
CREATE TABLE IF NOT EXISTS domains (
  domain      TEXT PRIMARY KEY,     -- contoh: kotakposku.com
  is_active   INTEGER NOT NULL DEFAULT 1,  -- 1 aktif, 0 nonaktif
  is_default  INTEGER NOT NULL DEFAULT 0,  -- domain default kalau user gak pilih
  label       TEXT,                 -- nama tampilan opsional
  created_at  INTEGER NOT NULL
);

-- Inbox: alamat lengkap <local>@<domain>
CREATE TABLE IF NOT EXISTS inboxes (
  address     TEXT PRIMARY KEY,
  local_part  TEXT NOT NULL,
  domain      TEXT NOT NULL,        -- FK ke domains.domain
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL,
  user_id     TEXT,
  note        TEXT
);

CREATE TABLE IF NOT EXISTS messages (
  id          TEXT NOT NULL,
  inbox       TEXT NOT NULL,
  from_addr   TEXT,
  from_name   TEXT,
  to_addr     TEXT,
  subject     TEXT,
  text_body   TEXT,
  html_body   TEXT,
  raw_size    INTEGER,
  received_at INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  raw_key     TEXT,
  attach_count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (inbox, id)
);

CREATE INDEX IF NOT EXISTS idx_messages_inbox
  ON messages(inbox, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_expiry
  ON messages(expires_at);
CREATE INDEX IF NOT EXISTS idx_inboxes_expiry
  ON inboxes(expires_at);
CREATE INDEX IF NOT EXISTS idx_inboxes_domain
  ON inboxes(domain);

-- Seed domain dipisah ke seed.sql (dibuat otomatis oleh deploy.ps1 / diisi manual).

-- ---------- auth ----------
CREATE TABLE IF NOT EXISTS users (
  id          TEXT PRIMARY KEY,
  email       TEXT NOT NULL UNIQUE,
  name        TEXT,
  pass_hash   TEXT NOT NULL,
  role        TEXT NOT NULL DEFAULT 'member',    -- owner | admin | member
  status      TEXT NOT NULL DEFAULT 'pending',   -- pending | approved | rejected | suspended
  created_at  INTEGER NOT NULL,
  approved_at INTEGER,
  approved_by TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash  TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  user_agent  TEXT
);

CREATE INDEX IF NOT EXISTS idx_users_status   ON users(status);
CREATE INDEX IF NOT EXISTS idx_sessions_user  ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS password_resets (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  token_hash TEXT,
  source     TEXT NOT NULL DEFAULT 'self',  -- self | admin
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_resets_user  ON password_resets(user_id);
CREATE INDEX IF NOT EXISTS idx_resets_token ON password_resets(token_hash);

-- ---------- rate limit login ----------
CREATE TABLE IF NOT EXISTS login_attempts (
  rl_key       TEXT PRIMARY KEY,   -- sha256(ip|email)
  count        INTEGER NOT NULL,
  window_start INTEGER NOT NULL,
  locked_until INTEGER NOT NULL DEFAULT 0
);

-- ---------- api keys ----------
CREATE TABLE IF NOT EXISTS api_keys (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  name       TEXT,
  key_hash   TEXT NOT NULL UNIQUE,
  prefix     TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used  INTEGER,
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_keys_user ON api_keys(user_id);

-- ---------- audit log ----------
CREATE TABLE IF NOT EXISTS audit_log (
  id          TEXT PRIMARY KEY,
  actor_id    TEXT,
  actor_email TEXT,
  action      TEXT NOT NULL,
  target      TEXT,
  meta        TEXT,
  ip          TEXT,
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(created_at DESC);

-- ---------- attachments ----------
CREATE TABLE IF NOT EXISTS attachments (
  id         TEXT PRIMARY KEY,
  message_id TEXT NOT NULL,
  inbox      TEXT NOT NULL,
  filename   TEXT,
  mime       TEXT,
  size       INTEGER,
  r2_key     TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_att_message ON attachments(message_id);
CREATE INDEX IF NOT EXISTS idx_att_inbox ON attachments(inbox);
CREATE INDEX IF NOT EXISTS idx_att_expiry ON attachments(expires_at);

-- ---------- ledger inbox (log pesan masuk) ----------
CREATE TABLE IF NOT EXISTS inbox_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  inbox      TEXT NOT NULL,
  domain     TEXT,
  peer       TEXT,
  peer_name  TEXT,
  subject    TEXT,
  message_id TEXT,
  first_at   INTEGER NOT NULL,
  UNIQUE(inbox, message_id)
);
CREATE INDEX IF NOT EXISTS idx_inbox_log_inbox ON inbox_log(inbox, first_at DESC);
CREATE INDEX IF NOT EXISTS idx_inbox_log_peer ON inbox_log(peer);

-- ---------- rate limit generik (per IP) ----------
CREATE TABLE IF NOT EXISTS rate_limits (
  rl_key       TEXT PRIMARY KEY,
  count        INTEGER NOT NULL,
  window_start INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_window ON rate_limits(window_start);

-- ---------- AccountMatrix (Multi-Account, Trial & Domain Vault) ----------
CREATE TABLE IF NOT EXISTS matrix_accounts (
  id             TEXT PRIMARY KEY,
  user_id        TEXT NOT NULL,
  service        TEXT NOT NULL,
  tag            TEXT,
  address        TEXT NOT NULL,
  username       TEXT,
  password       TEXT,
  totp_secret    TEXT,
  api_key        TEXT,
  recovery_codes TEXT,
  opsec_note     TEXT,
  status         TEXT NOT NULL DEFAULT 'active',
  expires_at     INTEGER,
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_matrix_user ON matrix_accounts(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_matrix_address ON matrix_accounts(address);

