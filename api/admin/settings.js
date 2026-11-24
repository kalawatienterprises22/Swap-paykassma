const { getPool } = require("../_lib/db");
const { sendJson, allowMethods } = require("../_lib/http");
const { verifyToken } = require("../_lib/auth");

function authenticate(req, res) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) {
    sendJson(res, 401, { ok: false, message: "Authentication required" });
    return null;
  }
  try {
    const actor = verifyToken(token);
    if (actor.role !== "SUPER_ADMIN") {
      sendJson(res, 403, { ok: false, message: "Super Admin access required" });
      return null;
    }
    return actor;
  } catch {
    sendJson(res, 401, { ok: false, message: "Invalid or expired session" });
    return null;
  }
}

module.exports = async (req, res) => {
  if (!allowMethods(req, res, ["GET", "PUT"])) return;
  const actor = authenticate(req, res);
  if (!actor) return;

  const pool = getPool();
  try {
    if (req.method === "GET") {
      const result = await pool.query(
        "SELECT key, value, updated_at FROM sp_settings ORDER BY key"
      );
      return sendJson(res, 200, { ok: true, settings: result.rows });
    }

    const { key, value } = req.body || {};
    if (!["maintenance", "commission"].includes(key) ||
        !value || typeof value !== "object" || Array.isArray(value)) {
      return sendJson(res, 400, { ok: false, message: "Unsupported setting" });
    }
    if (key === "maintenance" &&
        (typeof value.enabled !== "boolean" ||
         typeof value.message !== "string" || value.message.length > 500)) {
      return sendJson(res, 400, { ok: false, message: "Invalid maintenance setting" });
    }
    if (key === "commission" &&
        !["HOLD", "CUSTOM", "FULL_TO_MERCHANT"].includes(value.mode)) {
      return sendJson(res, 400, { ok: false, message: "Invalid commission mode" });
    }
    if (key === "commission" && value.mode === "CUSTOM") {
      const pct = Number(value.percentage);
      if (!Number.isFinite(pct) || pct < 0 || pct > 100) {
        return sendJson(res, 400, { ok: false, message: "Custom commission percentage must be between 0 and 100" });
      }
    }

    const saved = await pool.query(
      `INSERT INTO sp_settings(key, value, updated_by)
       VALUES($1, $2::jsonb, $3)
       ON CONFLICT(key) DO UPDATE
       SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = now()
       RETURNING key, value, updated_at`,
      [key, JSON.stringify(value), actor.sub]
    );
    await pool.query(
      `INSERT INTO sp_audit_logs(actor_id, action, target_type, target_id, details)
       VALUES($1, 'SETTING_UPDATED', 'SETTING', $2, $3::jsonb)`,
      [actor.sub, key, JSON.stringify(value)]
    );
    return sendJson(res, 200, { ok: true, setting: saved.rows[0] });
  } catch (error) {
    console.error("Admin settings API error:", error.message);
    return sendJson(res, 500, { ok: false, message: "Unable to process Paykassma settings" });
  }
};
