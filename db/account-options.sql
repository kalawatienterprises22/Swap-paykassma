CREATE TABLE IF NOT EXISTS sp_user_account_options (
  user_id UUID PRIMARY KEY REFERENCES sp_users(id) ON DELETE CASCADE,
  options JSONB NOT NULL DEFAULT '[]'::jsonb,
  updated_by UUID REFERENCES sp_users(id),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
