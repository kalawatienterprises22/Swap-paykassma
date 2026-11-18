const { getPool } = require("../_lib/db");
const { sendJson, allowMethods } = require("../_lib/http");
const { verifyToken } = require("../_lib/auth");

module.exports = async (req, res) => {
  if (!allowMethods(req, res, ["GET"])) return;
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return sendJson(res, 401, { ok: false, message: "Authentication required" });

  let actor;
  try { actor = verifyToken(token); }
  catch { return sendJson(res, 401, { ok: false, message: "Invalid or expired session" }); }
  if (!["MERCHANT", "ADMIN", "SUPER_ADMIN"].includes(actor.role)) {
    return sendJson(res, 403, { ok: false, message: "Access denied" });
  }

  try {
    const pool = getPool();
    let result;
    if (actor.role === "SUPER_ADMIN") {
      result = await pool.query(
        "SELECT id,user_id,title,message,category,created_at,read_at FROM sp_notifications ORDER BY created_at DESC LIMIT 300"
      );
    } else if (actor.role === "ADMIN") {
      result = await pool.query(
        `SELECT n.id,n.user_id,n.title,n.message,n.category,n.created_at,n.read_at
         FROM sp_notifications n
         WHERE n.user_id=$1 OR n.user_id IN (
           SELECT id FROM sp_users WHERE role='MERCHANT' AND parent_admin_id=$1
         ) OR n.user_id IS NULL
         ORDER BY n.created_at DESC LIMIT 300`,
        [actor.sub]
      );
    } else {
      result = await pool.query(
        "SELECT id,user_id,title,message,category,created_at,read_at FROM sp_notifications WHERE user_id=$1 OR user_id IS NULL ORDER BY created_at DESC LIMIT 100",
        [actor.sub]
      );
    }
    return sendJson(res, 200, { ok: true, notifications: result.rows });
  } catch (error) {
    console.error("Notification read error:", error.message);
    return sendJson(res, 500, { ok: false, message: "Notifications unavailable" });
  }
};
