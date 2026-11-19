-- SuperPay Telegram-backed Merchant signup and approval.
-- Run once in Neon SQL Editor before enabling the Telegram bot.
CREATE TABLE IF NOT EXISTS sp_merchant_onboarding (
  merchant_id UUID PRIMARY KEY REFERENCES sp_users(id) ON DELETE CASCADE,
  phone TEXT NOT NULL,
  full_address TEXT NOT NULL,
  review_status TEXT NOT NULL DEFAULT 'PENDING' CHECK (review_status IN ('PENDING','APPROVED','REJECTED')),
  telegram_chat_id TEXT UNIQUE,
  telegram_username TEXT,
  telegram_verified_at TIMESTAMPTZ,
  telegram_link_token_hash TEXT,
  telegram_link_expires_at TIMESTAMPTZ,
  setup_token_hash TEXT,
  setup_expires_at TIMESTAMPTZ,
  setup_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sp_merchant_onboarding_pending_idx
  ON sp_merchant_onboarding(telegram_verified_at, created_at DESC);

-- Encrypted KYC fields for referral-based Merchant registrations.
ALTER TABLE sp_merchant_onboarding ADD COLUMN IF NOT EXISTS pan_number_encrypted TEXT;
ALTER TABLE sp_merchant_onboarding ADD COLUMN IF NOT EXISTS aadhaar_number_encrypted TEXT;

-- Prevent duplicate Merchant registrations by normalized mobile number and PAN fingerprint.
ALTER TABLE sp_merchant_onboarding ADD COLUMN IF NOT EXISTS phone_normalized TEXT;
ALTER TABLE sp_merchant_onboarding ADD COLUMN IF NOT EXISTS pan_fingerprint TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS sp_merchant_onboarding_phone_unique
  ON sp_merchant_onboarding(phone_normalized) WHERE phone_normalized IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS sp_merchant_onboarding_pan_unique
  ON sp_merchant_onboarding(pan_fingerprint) WHERE pan_fingerprint IS NOT NULL;
-- telegram_chat_id already has a UNIQUE constraint in the original table definition.
