-- SuperPay parent-admin hierarchy and secure merchant ownership.
-- Run once in the Neon SQL Editor before deploying the matching API changes.
ALTER TABLE sp_users
  ADD COLUMN IF NOT EXISTS parent_admin_id UUID REFERENCES sp_users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS sp_users_parent_admin_role_idx
  ON sp_users(parent_admin_id, role, created_at DESC);

-- Safely migrate legacy belongs_to values only when they exactly match
-- an existing Admin UUID or Admin user_id. Unmatched values remain untouched.
UPDATE sp_users AS merchant
SET parent_admin_id = admin.id
FROM sp_users AS admin
WHERE merchant.role = 'MERCHANT'
  AND admin.role = 'ADMIN'
  AND merchant.parent_admin_id IS NULL
  AND (
    merchant.belongs_to = admin.id::text
    OR merchant.belongs_to = admin.user_id
  );

-- Audit records for ownership transfers are written to existing sp_audit_logs.
