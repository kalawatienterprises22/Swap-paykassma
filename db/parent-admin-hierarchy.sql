-- SuperPay parent-admin ownership and referral registration.
-- Run once in Neon SQL Editor before using the new Admin hierarchy.

ALTER TABLE sp_users
  ADD COLUMN IF NOT EXISTS parent_admin_id UUID REFERENCES sp_users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS sp_users_parent_admin_role_idx
  ON sp_users(parent_admin_id, role, created_at DESC);

-- Migrate legacy belongs_to values only when they exactly identify an existing Admin.
UPDATE sp_users AS merchant
SET parent_admin_id = admin.id
FROM sp_users AS admin
WHERE merchant.role = 'MERCHANT'
  AND admin.role = 'ADMIN'
  AND merchant.parent_admin_id IS NULL
  AND (merchant.belongs_to = admin.id::text OR merchant.belongs_to = admin.user_id);

CREATE TABLE IF NOT EXISTS sp_admin_referrals (
  admin_id UUID PRIMARY KEY REFERENCES sp_users(id) ON DELETE CASCADE,
  code TEXT NOT NULL UNIQUE,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sp_admin_referrals_code_idx ON sp_admin_referrals(code) WHERE active=TRUE;
