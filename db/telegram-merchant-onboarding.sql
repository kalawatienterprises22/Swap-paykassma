-- SuperPay Telegram-backed Merchant signup and approval.
-- Run once in Neon SQL Editor before enabling the Telegram bot.
CREATE TABLE IF NOT EXISTS sp_merchant_onboarding (
  merchant_id UUID PRIMARY KEY REFERENCES sp_users(id) ON DELETE CASCADE,
  phone TEXT NOT NULL,
  full_address TEXT NOT NULL,
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
