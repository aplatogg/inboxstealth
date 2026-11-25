-- Seed domain temp mail. Jalankan setelah schema.sql.
-- Edit daftar ini sesuai domain kamu, lalu:
--   npx wrangler d1 execute tempmail_db --file=./seed.sql --remote

DELETE FROM domains;

INSERT OR IGNORE INTO domains (domain, is_active, is_default, label, created_at) VALUES
  ('mail.example.com',  1, 1, 'Primary Mail', 0),
  ('inbox.example.org', 1, 0, 'Secondary',    0);
