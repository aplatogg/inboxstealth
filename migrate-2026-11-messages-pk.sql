-- Migrasi: PK messages -> komposit (inbox,id); kolom raw_key/attach_count; ledger inbox_log
CREATE TABLE IF NOT EXISTS messages_new (
  id           TEXT NOT NULL,
  inbox        TEXT NOT NULL,
  from_addr    TEXT,
  from_name    TEXT,
  to_addr      TEXT,
  subject      TEXT,
  text_body    TEXT,
  html_body    TEXT,
  raw_size     INTEGER,
  received_at  INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  raw_key      TEXT,
  attach_count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (inbox, id)
);
INSERT OR IGNORE INTO messages_new
  (id,inbox,from_addr,from_name,to_addr,subject,text_body,html_body,raw_size,received_at,expires_at,raw_key,attach_count)
  SELECT id,inbox,from_addr,from_name,to_addr,subject,text_body,html_body,raw_size,received_at,expires_at,raw_key,attach_count FROM messages;
DROP TABLE messages;
ALTER TABLE messages_new RENAME TO messages;
CREATE INDEX IF NOT EXISTS idx_messages_inbox ON messages(inbox, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_expiry ON messages(expires_at);

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
