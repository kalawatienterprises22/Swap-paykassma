-- Run once in Neon SQL Editor.
-- One explicitly selected payment-notification source per merchant.
CREATE TABLE IF NOT EXISTS sp_merchant_notification_sources (
  merchant_id UUID PRIMARY KEY REFERENCES sp_users(id) ON DELETE CASCADE,
  source_package TEXT NOT NULL CHECK (source_package IN (
    'com.google.android.apps.nbu.paisa.user',
    'com.phonepe.app',
    'com.bharatpe.app',
    'com.paytm.business'
  )),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by UUID REFERENCES sp_users(id)
);
