-- Store only merchant-consented, payment-filtered SMS evidence.
CREATE TABLE IF NOT EXISTS sp_payment_sms (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  merchant_id UUID NOT NULL REFERENCES sp_users(id) ON DELETE CASCADE,
  sender TEXT NOT NULL,
  message_text TEXT NOT NULL,
  message_hash TEXT NOT NULL,
  received_at TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','MATCHED','REVIEWED','REJECTED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(merchant_id,message_hash)
);
CREATE INDEX IF NOT EXISTS sp_payment_sms_merchant_received_idx
  ON sp_payment_sms(merchant_id,received_at DESC);
CREATE INDEX IF NOT EXISTS sp_payment_sms_received_idx
  ON sp_payment_sms(received_at DESC);
