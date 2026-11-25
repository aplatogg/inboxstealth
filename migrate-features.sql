-- Fitur: webhook per-inbox + pengumuman (banner)
CREATE TABLE IF NOT EXISTS webhooks (
  id TEXT PRIMARY KEY,
  address TEXT NOT NULL,
  url TEXT NOT NULL,
  secret TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  last_status INTEGER,
  last_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_webhooks_address ON webhooks(address);

CREATE TABLE IF NOT EXISTS announcements (
  id TEXT PRIMARY KEY,
  message TEXT NOT NULL,
  level TEXT NOT NULL DEFAULT 'info',
  active INTEGER NOT NULL DEFAULT 1,
  created_by TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_announcements_active ON announcements(active, created_at);

-- Fitur: catatan / label per inbox
-- ALTER TABLE inboxes ADD COLUMN note TEXT;
