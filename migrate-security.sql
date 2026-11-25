CREATE TABLE IF NOT EXISTS rate_limits (
  rl_key       TEXT PRIMARY KEY,
  count        INTEGER NOT NULL,
  window_start INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_window ON rate_limits(window_start);
