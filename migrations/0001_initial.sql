CREATE TABLE IF NOT EXISTS licenses (
  id TEXT PRIMARY KEY,
  key_hash TEXT NOT NULL UNIQUE,
  key_prefix TEXT NOT NULL,
  key_last4 TEXT NOT NULL,
  tier TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  license_type TEXT NOT NULL DEFAULT 'premium',
  discord_id TEXT,
  stripe_session_id TEXT,
  stripe_customer_id TEXT,
  device_limit INTEGER NOT NULL DEFAULT 1,
  issued_at INTEGER NOT NULL,
  expires_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  revoked_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_licenses_discord_id ON licenses(discord_id);
CREATE INDEX IF NOT EXISTS idx_licenses_stripe_customer ON licenses(stripe_customer_id);
CREATE INDEX IF NOT EXISTS idx_licenses_status ON licenses(status);

CREATE TABLE IF NOT EXISTS license_devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  license_id TEXT NOT NULL,
  hwid_hash TEXT NOT NULL,
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE CASCADE,
  UNIQUE (license_id, hwid_hash)
);

CREATE INDEX IF NOT EXISTS idx_license_devices_license ON license_devices(license_id);

CREATE TABLE IF NOT EXISTS license_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  license_id TEXT,
  event_type TEXT NOT NULL,
  outcome TEXT NOT NULL,
  reason TEXT,
  ip_hash TEXT,
  hwid_hash TEXT,
  created_at INTEGER NOT NULL,
  details_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_license_events_license ON license_events(license_id);
CREATE INDEX IF NOT EXISTS idx_license_events_created ON license_events(created_at);

CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY,
  license_id TEXT,
  provider TEXT NOT NULL,
  provider_session_id TEXT,
  provider_customer_id TEXT,
  plan TEXT,
  amount_cents INTEGER,
  currency TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_provider_session ON orders(provider, provider_session_id);

CREATE TABLE IF NOT EXISTS app_config (
  config_key TEXT PRIMARY KEY,
  config_value TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

INSERT OR IGNORE INTO app_config (config_key, config_value, updated_at)
VALUES ('maintenance_enabled', 'false', strftime('%s','now') * 1000);

INSERT OR IGNORE INTO app_config (config_key, config_value, updated_at)
VALUES ('maintenance_message', 'App is currently under maintenance. Please try again later.', strftime('%s','now') * 1000);
