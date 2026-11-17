const bcrypt = require("bcryptjs");
const crypto = require("crypto");
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
  if (!allowMethods(req, res, ["GET", "POST", "PATCH"])) return;
  const admin = getAdmin(req, res);
  if (!admin) return;

  try {
    const pool = getPool();

    if (req.method === "GET") {
      const search = String(req.query?.q || "").trim();
      const result = await pool.query(
        `SELECT id, user_id, email, display_name, status, created_at
         FROM sp_users
         WHERE role = 'MERCHANT'
           AND ($1 = '' OR user_id ILIKE $2 OR display_name ILIKE $2 OR COALESCE(email,'') ILIKE $2)
         ORDER BY created_at DESC
         LIMIT 200`,
        [search, `%${search}%`]
      );
      return sendJson(res, 200, { ok: true, merchants: result.rows });
    }

    if (req.method === "POST") {
      const { user_id, display_name, email, password } = req.body || {};
      const merchantId = typeof user_id === "string" ? user_id.trim() : "";
      const name = typeof display_name === "string" ? display_name.trim() : "";
      const merchantEmail = typeof email === "string" && email.trim() ? email.trim().toLowerCase() : null;

      if (!/^[a-zA-Z0-9_-]{4,32}$/.test(merchantId)) {
        return sendJson(res, 400, { ok: false, message: "User ID must be 4-32 characters (letters, numbers, _ or -)" });
      }
      if (name.length < 2 || name.length > 80) {
        return sendJson(res, 400, { ok: false, message: "Merchant name must be 2-80 characters" });
      }
      if (merchantEmail && (merchantEmail.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(merchantEmail))) {
        return sendJson(res, 400, { ok: false, message: "Enter a valid email address" });
      }
      if (typeof password !== "string" || password.length < 12 || password.length > 72) {
        return sendJson(res, 400, { ok: false, message: "Password must be 12-72 characters" });
      }

      const passwordHash = await bcrypt.hash(password, 12);
      const result = await pool.query(
        `INSERT INTO sp_users (id, user_id, email, password_hash, display_name, role, status)
         VALUES ($1, $2, $3, $4, $5, 'MERCHANT', 'ACTIVE')
         RETURNING id, user_id, email, display_name, role, status, created_at`,
        [crypto.randomUUID(), merchantId, merchantEmail, passwordHash, name]
      );
      await pool.query(
        `INSERT INTO sp_audit_logs (actor_id, action, target_type, target_id, details)
         VALUES ($1, 'MERCHANT_CREATED', 'MERCHANT', $2, $3)`,
        [admin.sub, result.rows[0].id, JSON.stringify({ user_id: merchantId, display_name: name })]
      );
      return sendJson(res, 201, { ok: true, merchant: result.rows[0] });
    }

    const { id, status } = req.body || {};
    if (typeof id !== "string" || !/^[0-9a-f-]{36}$/i.test(id) || !["ACTIVE", "SUSPENDED"].includes(status)) {
      return sendJson(res, 400, { ok: false, message: "Invalid merchant or status" });
    }
    const result = await pool.query(
      `UPDATE sp_users SET status = $1, updated_at = now()
       WHERE id = $2 AND role = 'MERCHANT'
       RETURNING id, user_id, email, display_name, status, created_at`,
      [status, id]
    );
    if (!result.rows.length) {
      return sendJson(res, 404, { ok: false, message: "Merchant not found" });
    }
    await pool.query(
      `INSERT INTO sp_audit_logs (actor_id, action, target_type, target_id, details)
       VALUES ($1, 'MERCHANT_STATUS_CHANGED', 'MERCHANT', $2, $3)`,
      [admin.sub, id, JSON.stringify({ status })]
    );
    return sendJson(res, 200, { ok: true, merchant: result.rows[0] });
  } catch (error) {
    if (error.code === "23505") {
      return sendJson(res, 409, { ok: false, message: "User ID or email already exists" });
    }
    console.error("Merchant API error:", error.message);
    return sendJson(res, 500, { ok: false, message: "Merchant operation failed" });
  }
};
