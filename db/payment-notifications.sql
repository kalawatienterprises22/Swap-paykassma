-- Run this file once in the Neon SQL Editor.
-- Notifications are evidence candidates only; do not deduct balances until statement verification.
CREATE TABLE IF NOT EXISTS sp_payment_notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  merchant_id UUID NOT NULL REFERENCES sp_users(id) ON DELETE CASCADE,
  source_package TEXT NOT NULL,
  notification_key TEXT NOT NULL,
  notification_title TEXT NOT NULL DEFAULT '',
  notification_text TEXT NOT NULL,
  posted_at TIMESTAMPTZ,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  status TEXT NOT NULL DEFAULT 'PENDING'
    CHECK (status IN ('PENDING','MATCHED','VERIFIED','REJECTED')),
  UNIQUE (merchant_id, notification_key)
);
CREATE INDEX IF NOT EXISTS sp_payment_notifications_merchant_received_idx
  ON sp_payment_notifications(merchant_id, received_at DESC);
CREATE INDEX IF NOT EXISTS sp_payment_notifications_status_idx
  ON sp_payment_notifications(status, received_at DESC);
