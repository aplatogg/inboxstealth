-- migrate-auth.sql — sekali jalan untuk DB yang sudah ada.
-- Aman kalau diulang: error "duplicate column name" berarti sudah pernah.
ALTER TABLE inboxes ADD COLUMN user_id TEXT;
CREATE INDEX IF NOT EXISTS idx_inboxes_user ON inboxes(user_id);
