-- Paykassma-only: durable storage for selected Android payment-app notifications.
-- Notifications are evidence candidates; do not credit/debit balances until statement verification.
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

ALTER TABLE sp_payment_notifications
  ADD COLUMN IF NOT EXISTS reviewed_by UUID REFERENCES sp_users(id),
  ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS review_note TEXT,
  ADD COLUMN IF NOT EXISTS matched_deposit_id UUID REFERENCES sp_deposits(id);

CREATE INDEX IF NOT EXISTS sp_payment_notifications_merchant_received_idx
  ON sp_payment_notifications(merchant_id, received_at DESC);
CREATE INDEX IF NOT EXISTS sp_payment_notifications_status_idx
  ON sp_payment_notifications(status, received_at DESC);
