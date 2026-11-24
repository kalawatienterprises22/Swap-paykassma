-- Paykassma withdrawal requests. This records requests and reservations only;
-- no bank transfer is initiated by this schema.
CREATE TABLE IF NOT EXISTS sp_withdrawal_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  merchant_id UUID NOT NULL REFERENCES sp_users(id),
  account_id UUID NOT NULL REFERENCES sp_merchant_accounts(id),
  amount_inr NUMERIC(20,2) NOT NULL CHECK (amount_inr > 0),
  status TEXT NOT NULL DEFAULT 'PENDING'
    CHECK (status IN ('PENDING','APPROVED','REJECTED','PAID')),
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  reviewed_by UUID REFERENCES sp_users(id),
  reviewed_at TIMESTAMPTZ,
  review_note TEXT,
  payout_reference TEXT,
  paid_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS sp_withdrawal_requests_merchant_status_idx
  ON sp_withdrawal_requests(merchant_id, status, requested_at DESC);
CREATE INDEX IF NOT EXISTS sp_withdrawal_requests_status_idx
  ON sp_withdrawal_requests(status, requested_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS sp_withdrawal_requests_payout_ref_uidx
  ON sp_withdrawal_requests(payout_reference)
  WHERE payout_reference IS NOT NULL;
