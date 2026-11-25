ALTER TABLE users ADD COLUMN totp_secret TEXT;
ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS recovery_codes (
  id        TEXT PRIMARY KEY,
  user_id   TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  used_at   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_rec_user ON recovery_codes(user_id);

CREATE TABLE IF NOT EXISTS login_tickets (
  token_hash TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_ticket_exp ON login_tickets(expires_at);
