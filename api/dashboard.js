const { getPool } = require("./_lib/db");
const { sendJson, allowMethods } = require("./_lib/http");
const { verifyToken } = require("./_lib/auth");

module.exports = async (req, res) => {
  if (!allowMethods(req, res, ["GET"])) return;

  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (!token) {
    return sendJson(res, 401, { ok: false, message: "Authentication required" });
  }

  let decoded;
  try {
    decoded = verifyToken(token);
  } catch {
    return sendJson(res, 401, { ok: false, message: "Invalid or expired session" });
  }

  if (decoded.role !== "SUPER_ADMIN") {
    return sendJson(res, 403, { ok: false, message: "Access denied" });
  }

  try {
    const pool = getPool();
    const [merchants, transactions, deposits, payments, pendingAccounts] = await Promise.all([
      pool.query("SELECT COUNT(*)::int AS total FROM sp_users WHERE role = 'MERCHANT'"),
      pool.query("SELECT COUNT(*)::int AS total FROM sp_ledger"),
      pool.query("SELECT COUNT(*)::int AS total FROM sp_deposits"),
      pool.query("SELECT COUNT(*)::int AS total FROM sp_ledger WHERE entry_type IN ('PAYMENT','MANUAL_DEBIT','CHARGE')"),
      pool.query("SELECT COUNT(*)::int AS total FROM sp_merchant_accounts WHERE status = 'PENDING'")
    ]);

    return sendJson(res, 200, {
      ok: true,
      stats: {
        merchants: merchants.rows[0].total,
        transactions: transactions.rows[0].total,
        deposits: deposits.rows[0].total,
        payments_debits: payments.rows[0].total,
        pending_account_requests: pendingAccounts.rows[0].total
      }
    });
  } catch (error) {
    console.error("Dashboard API error:", error.message);
    return sendJson(res, 500, {
      ok: false,
      message: error.code === "42P01"
        ? "A required SuperPay database table is missing. Run the latest database SQL files in Neon."
        : "Dashboard data unavailable"
    });
  }
};
