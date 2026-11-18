-- Run once in Neon SQL Editor.
-- Merchant-submitted settlement/payment accounts require Super Admin approval.
CREATE TABLE IF NOT EXISTS sp_merchant_accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  merchant_id UUID NOT NULL REFERENCES sp_users(id) ON DELETE CASCADE,
  account_name TEXT NOT NULL,
  provider_key TEXT NOT NULL,
  provider_label TEXT NOT NULL,
  account_details JSONB NOT NULL DEFAULT '{}'::jsonb,
  status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','APPROVED','REJECTED')),
  submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  reviewed_by UUID REFERENCES sp_users(id),
  reviewed_at TIMESTAMPTZ,
  review_note TEXT
);
CREATE INDEX IF NOT EXISTS sp_merchant_accounts_merchant_idx
  ON sp_merchant_accounts(merchant_id, submitted_at DESC);
CREATE INDEX IF NOT EXISTS sp_merchant_accounts_status_idx
  ON sp_merchant_accounts(status, submitted_at DESC);
