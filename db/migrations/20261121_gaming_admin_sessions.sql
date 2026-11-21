-- ParixBet Gaming Admin status and session revocation.
-- Apply manually to the intended PostgreSQL database before deploying this branch.
CREATE TABLE IF NOT EXISTS sp_gaming_admins (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL DEFAULT 'ParixBet Admin',
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','SUSPENDED')),
  token_version INTEGER NOT NULL DEFAULT 1 CHECK (token_version >= 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS sp_gaming_admins_status_idx
  ON sp_gaming_admins(status);
