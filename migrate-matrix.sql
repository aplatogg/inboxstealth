-- migrate-matrix.sql — AccountMatrix (Multi-Account, Trial & Domain Vault terintegrasi menyurat.me)
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
  status         TEXT NOT NULL DEFAULT 'active',  -- active | trial | cooldown | burned
  expires_at     INTEGER,
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_matrix_user ON matrix_accounts(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_matrix_address ON matrix_accounts(address);
