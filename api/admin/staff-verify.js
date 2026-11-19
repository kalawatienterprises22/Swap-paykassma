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
    if (!["SUPER_ADMIN", "ADMIN"].includes(actor.role)) {
      sendJson(res, 403, { ok: false, message: "Access denied" });
      return null;
    }
    return actor;
  } catch {
    sendJson(res, 401, { ok: false, message: "Invalid or expired session" });
    return null;
  }
}

module.exports = async (req, res) => {
  if (!allowMethods(req, res, ["GET", "POST"])) return;
  const actor = authenticate(req, res);
  if (!actor) return;

  try {
    const pool = getPool();

    if (req.method === "GET") {
      const id = String(req.query?.userId || "").trim();
      if (id) {
        const values = actor.role === "SUPER_ADMIN" ? [id] : [id, actor.sub];
        const scope = actor.role === "SUPER_ADMIN" ? "" : " AND created_by=$2";
        const result = await pool.query(
          `SELECT staff_user_id, belongs_to, status
           FROM sp_staff_verifications
           WHERE staff_user_id=$1${scope}
           LIMIT 1`,
          values
        );
        return sendJson(res, 200, { ok: true, verification: result.rows[0] || null });
      }

      const values = actor.role === "SUPER_ADMIN" ? [] : [actor.sub];
      const scope = actor.role === "SUPER_ADMIN" ? "" : " WHERE created_by=$1";
      const result = await pool.query(
        `SELECT staff_user_id, belongs_to, status, created_at
         FROM sp_staff_verifications${scope}
         ORDER BY created_at DESC LIMIT 300`,
        values
      );
      return sendJson(res, 200, { ok: true, verifications: result.rows });
    }

    const staffUserId = String(req.body?.staffUserId || "").trim();
    const belongsTo = String(req.body?.belongsTo || "").trim();
    const status = String(req.body?.status || "ACTIVE").toUpperCase();
    if (!staffUserId || staffUserId.length > 120 ||
        !belongsTo || belongsTo.length > 120 ||
        !["ACTIVE", "REVOKED"].includes(status)) {
      return sendJson(res, 400, {
        ok: false,
        message: "Enter a valid Staff User ID, Belongs To name and verification status"
      });
    }

    const result = await pool.query(
      `INSERT INTO sp_staff_verifications
         (staff_user_id, belongs_to, status, created_by)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (staff_user_id) DO UPDATE
         SET belongs_to=EXCLUDED.belongs_to,
             status=EXCLUDED.status
       WHERE sp_staff_verifications.created_by=$4
          OR $5='SUPER_ADMIN'
       RETURNING staff_user_id, belongs_to, status`,
      [staffUserId, belongsTo, status, actor.sub, actor.role]
    );

    if (!result.rowCount) {
      return sendJson(res, 409, {
        ok: false,
        message: "This Staff User ID is already managed by another Admin"
      });
    }

    await pool.query(
      `INSERT INTO sp_audit_logs
         (actor_id, action, target_type, target_id, details)
       VALUES ($1, 'STAFF_VERIFICATION_UPSERT', 'STAFF_VERIFICATION', $2, $3)`,
      [actor.sub, staffUserId, JSON.stringify({ belongsTo, status })]
    );

    return sendJson(res, 200, { ok: true, verification: result.rows[0] });
  } catch (error) {
    console.error("Staff verification API error:", error.message);
    return sendJson(res, 500, {
      ok: false,
      message: error.code === "42P01"
        ? "Staff verification database table is missing. Run the Paykassma schema SQL in Neon."
        : error.code === "42703"
          ? "Staff verification database columns are missing. Update the Neon schema."
          : "Staff verification request failed"
    });
  }
};
