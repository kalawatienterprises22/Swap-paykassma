CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS sp_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE,
  password_hash TEXT NOT NULL,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('SUPER_ADMIN','ADMIN','STAFF','MERCHANT')),
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','SUSPENDED')),
  belongs_to TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sp_permissions (
  user_id UUID NOT NULL REFERENCES sp_users(id) ON DELETE CASCADE,
  permission TEXT NOT NULL,
  PRIMARY KEY (user_id, permission)
);

CREATE TABLE IF NOT EXISTS sp_provider_configs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_key TEXT NOT NULL,
  config JSONB NOT NULL DEFAULT '{"fields":[]}'::jsonb,
  updated_by UUID REFERENCES sp_users(id),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(provider_key)
);

CREATE TABLE IF NOT EXISTS sp_staff_verifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  staff_user_id TEXT UNIQUE NOT NULL,
  belongs_to TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','REVOKED')),
  created_by UUID REFERENCES sp_users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sp_settings (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL,
  updated_by UUID REFERENCES sp_users(id),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sp_notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES sp_users(id),
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'GENERAL',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  read_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS sp_deposits (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  merchant_id UUID NOT NULL REFERENCES sp_users(id),
  provider TEXT NOT NULL,
  provider_transaction_id TEXT NOT NULL,
  original_amount NUMERIC(20,6) NOT NULL CHECK (original_amount > 0),
  original_currency CHAR(3) NOT NULL,
  inr_amount NUMERIC(20,2) NOT NULL CHECK (inr_amount > 0),
  exchange_rate NUMERIC(20,8) NOT NULL CHECK (exchange_rate > 0),
  status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','SUCCESSFUL','FAILED')),
  verified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(provider, provider_transaction_id)
);

CREATE TABLE IF NOT EXISTS sp_ledger (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  merchant_id UUID NOT NULL REFERENCES sp_users(id),
  reference TEXT NOT NULL UNIQUE,
  entry_type TEXT NOT NULL CHECK (entry_type IN ('DEPOSIT','PAYMENT','MANUAL_CREDIT','MANUAL_DEBIT','COMMISSION','CHARGE')),
  amount_inr NUMERIC(20,2) NOT NULL CHECK (amount_inr <> 0),
  description TEXT NOT NULL,
  created_by UUID REFERENCES sp_users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sp_audit_logs (
  id BIGSERIAL PRIMARY KEY,
  actor_id UUID REFERENCES sp_users(id),
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sp_notifications_user_created_idx ON sp_notifications(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS sp_ledger_merchant_created_idx ON sp_ledger(merchant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS sp_deposits_merchant_created_idx ON sp_deposits(merchant_id, created_at DESC);

-- Defaults are safe: maintenance OFF, commission held, full commission to merchant OFF.
INSERT INTO sp_settings(key,value) VALUES
 ('maintenance', '{"enabled":false,"message":""}'::jsonb),
 ('commission', '{"mode":"HOLD","full_to_merchant":false}'::jsonb)
ON CONFLICT(key) DO NOTHING;

-- Per-user account app / bank options controlled by Super Admin.
CREATE TABLE IF NOT EXISTS sp_user_account_options (
  user_id UUID PRIMARY KEY REFERENCES sp_users(id) ON DELETE CASCADE,
  options JSONB NOT NULL DEFAULT '[]'::jsonb,
  updated_by UUID REFERENCES sp_users(id),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
