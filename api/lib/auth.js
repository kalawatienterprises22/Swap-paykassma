const jwt = require("jsonwebtoken");
const { query } = require("./db");
const { send } = require("./http");

async function requireUser(req, res, roles = []) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!token || !process.env.JWT_SECRET) {
    send(res, 401, { ok:false, error:"Authentication required" }); return null;
  }
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const result = await query(
      "SELECT id,user_id,display_name,role,status FROM sp_users WHERE id=$1",
      [payload.sub]
    );
    const user = result.rows[0];
    if (!user || user.status !== "ACTIVE" || (roles.length && !roles.includes(user.role))) {
      send(res, 403, { ok:false, error:"Access denied" }); return null;
    }
    return user;
  } catch {
    send(res, 401, { ok:false, error:"Invalid or expired session" }); return null;
  }
}
async function audit(actorId, action, targetType, targetId, details = {}) {
  await query(
    "INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,$2,$3,$4,$5)",
    [actorId, action, targetType || null, targetId || null, JSON.stringify(details)]
  );
}
module.exports = { requireUser, audit };
