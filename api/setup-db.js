const { Client } = require("pg");

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).json({
      ok: false,
      message: "POST method required"
    });
  }

  if (
    !process.env.SETUP_SECRET ||
    req.headers.authorization !==
      `Bearer ${process.env.SETUP_SECRET}`
  ) {
    return res.status(401).json({
      ok: false,
      message: "Unauthorized"
    });
  }

  if (!process.env.DATABASE_URL) {
    return res.status(500).json({
      ok: false,
      message: "DATABASE_URL is missing"
    });
  }

  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });

  try {
    await client.connect();

    await client.query(`
      CREATE TABLE IF NOT EXISTS merchants (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        business_name TEXT NOT NULL,
        owner_name TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        login_id TEXT UNIQUE NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending'
          CHECK (status IN ('pending','approved','rejected','suspended')),
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        merchant_id UUID REFERENCES merchants(id) ON DELETE CASCADE,
        role TEXT NOT NULL CHECK (role IN ('admin','merchant','staff')),
        email TEXT,
        login_id TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS sessions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL UNIQUE,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS merchant_accounts (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
        account_type TEXT NOT NULL,
        account_name TEXT,
        account_number TEXT,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS customers (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
        name TEXT,
        email TEXT,
        phone TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS transactions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
        customer_id UUID REFERENCES customers(id) ON DELETE SET NULL,
        transaction_type TEXT NOT NULL,
        amount NUMERIC(14,2) NOT NULL DEFAULT 0,
        commission NUMERIC(14,2) DEFAULT 0,
        status TEXT DEFAULT 'pending',
        reference TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS withdrawals (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
        amount NUMERIC(14,2) NOT NULL,
        status TEXT DEFAULT 'pending',
        reference TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS payment_links (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
        title TEXT,
        amount NUMERIC(14,2),
        link_url TEXT,
        status TEXT DEFAULT 'active',
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS settlements (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
        amount NUMERIC(14,2) NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS fee_settings (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        merchant_id UUID REFERENCES merchants(id) ON DELETE CASCADE,
        fee_type TEXT NOT NULL,
        fee_value NUMERIC(14,4) NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS staff (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        merchant_id UUID REFERENCES merchants(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        login_id TEXT UNIQUE,
        active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE SET NULL,
        merchant_id UUID REFERENCES merchants(id) ON DELETE SET NULL,
        action TEXT NOT NULL,
        details JSONB DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS platform_settings (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        setting_key TEXT NOT NULL UNIQUE,
        setting_value JSONB NOT NULL DEFAULT '{}'::jsonb,
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS referrals (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
        referred_merchant_id UUID REFERENCES merchants(id) ON DELETE SET NULL,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_transactions_merchant
        ON transactions(merchant_id);

      CREATE INDEX IF NOT EXISTS idx_withdrawals_merchant
        ON withdrawals(merchant_id);

      CREATE INDEX IF NOT EXISTS idx_customers_merchant
        ON customers(merchant_id);

      CREATE INDEX IF NOT EXISTS idx_sessions_user
        ON sessions(user_id);
    `);

    return res.status(200).json({
      ok: true,
      message: "SuperPay database tables created successfully"
    });
  } catch (error) {
    console.error("Database setup error:", error.message);
    return res.status(500).json({
      ok: false,
      message: "Database setup failed"
    });
  } finally {
    await client.end().catch(() => {});
  }
};
