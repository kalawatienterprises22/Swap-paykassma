-- Paykassma merchant Android APK presence monitoring.
-- Online means a heartbeat was received in the last 3 minutes.
CREATE TABLE IF NOT EXISTS sp_merchant_devices (
  merchant_id UUID PRIMARY KEY REFERENCES sp_users(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  device_model TEXT NOT NULL DEFAULT '',
  app_version TEXT NOT NULL DEFAULT '',
  source_package TEXT,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_ip TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sp_merchant_devices_last_seen_idx
  ON sp_merchant_devices(last_seen_at DESC);
