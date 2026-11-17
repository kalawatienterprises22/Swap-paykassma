const { getPool } = require("../_lib/db");
const { sendJson, allowMethods } = require("../_lib/http");
const { verifyToken } = require("../_lib/auth");

function getAdmin(req, res) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) {
    sendJson(res, 401, { ok: false, message: "Authentication required" });
    return null;
  }
  try {
    const user = verifyToken(token);
    if (user.role !== "SUPER_ADMIN") {
      sendJson(res, 403, { ok: false, message: "Super Admin access required" });
      return null;
    }
    return user;
  } catch {
    sendJson(res, 401, { ok: false, message: "Invalid or expired session" });
    return null;
  }
}

module.exports = async (req, res) => {
  if (!allowMethods(req, res, ["GET", "POST"])) return;
  const admin = getAdmin(req, res);
  if (!admin) return;

  try {
    const pool = getPool();
    if (req.method === "GET") {
      const [current, history] = await Promise.all([
        pool.query("SELECT value, updated_at FROM sp_settings WHERE key = 'exchange_rates'"),
        pool.query(
          `SELECT id, details, created_at FROM sp_audit_logs
           WHERE action = 'EXCHANGE_RATES_UPDATED'
           ORDER BY created_at DESC LIMIT 50`
        )
      ]);
      return sendJson(res, 200, {
        ok: true,
        rates: current.rows[0]?.value?.rates || [],
        updated_at: current.rows[0]?.updated_at || null,
        history: history.rows
      });
    }

    const rates = req.body?.rates;
    if (!Array.isArray(rates) || rates.length < 1 || rates.length > 30) {
      return sendJson(res, 400, { ok: false, message: "Add between 1 and 30 currency rates" });
    }
    const seen = new Set();
    const cleanRates = [];
    for (const item of rates) {
      const currency = typeof item?.currency === "string" ? item.currency.trim().toUpperCase() : "";
      const rate = Number(item?.rate);
      if (!/^[A-Z]{3}$/.test(currency) || currency === "INR" || seen.has(currency)) {
        return sendJson(res, 400, { ok: false, message: "Currency codes must be unique 3-letter codes (INR is the base currency)" });
      }
      if (!Number.isFinite(rate) || rate <= 0 || rate > 1000000000000) {
        return sendJson(res, 400, { ok: false, message: "Every exchange rate must be a positive number" });
      }
      seen.add(currency);
      cleanRates.push({ currency, rate });
    }

    const previous = await pool.query("SELECT value FROM sp_settings WHERE key = 'exchange_rates'");
    const oldRates = previous.rows[0]?.value?.rates || [];
    const saved = await pool.query(
      `INSERT INTO sp_settings (key, value, updated_by, updated_at)
       VALUES ('exchange_rates', $1::jsonb, $2, now())
       ON CONFLICT (key) DO UPDATE
       SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = now()
       RETURNING value, updated_at`,
      [JSON.stringify({ base_currency: "INR", rates: cleanRates }), admin.sub]
    );
    await pool.query(
      `INSERT INTO sp_audit_logs (actor_id, action, target_type, target_id, details)
       VALUES ($1, 'EXCHANGE_RATES_UPDATED', 'SETTINGS', 'exchange_rates', $2::jsonb)`,
      [admin.sub, JSON.stringify({ old_rates: oldRates, new_rates: cleanRates })]
    );
    return sendJson(res, 200, { ok: true, rates: saved.rows[0].value.rates, updated_at: saved.rows[0].updated_at });
  } catch (error) {
    console.error("Exchange rates API error:", error.message);
    return sendJson(res, 500, { ok: false, message: "Unable to process exchange rates" });
  }
};
