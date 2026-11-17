const { query } = require("../_lib/db");
const { requireUser, audit } = require("../_lib/auth");
const { send, method } = require("../_lib/http");
module.exports = async (req,res) => {
  if (!method(req,res,["GET","POST"])) return;
  const actor = await requireUser(req,res,["SUPER_ADMIN","ADMIN"]);
  if (!actor) return;
  if (req.method === "GET") {
    const id = String(req.query.userId || "").trim();
    if (!id) return send(res,400,{ok:false,error:"userId is required"});
    const r = await query("SELECT staff_user_id,belongs_to,status FROM sp_staff_verifications WHERE staff_user_id=$1",[id]);
    return send(res,200,{ok:true,verification:r.rows[0] || null});
  }
  if (actor.role !== "SUPER_ADMIN" && actor.role !== "ADMIN") return send(res,403,{ok:false,error:"Access denied"});
  const { staffUserId, belongsTo, status = "ACTIVE" } = req.body || {};
  if (!staffUserId || !belongsTo || !["ACTIVE","REVOKED"].includes(status)) return send(res,400,{ok:false,error:"staffUserId, belongsTo and valid status are required"});
  const r = await query(
    `INSERT INTO sp_staff_verifications(staff_user_id,belongs_to,status,created_by)
     VALUES($1,$2,$3,$4)
     ON CONFLICT(staff_user_id) DO UPDATE SET belongs_to=EXCLUDED.belongs_to,status=EXCLUDED.status
     RETURNING staff_user_id,belongs_to,status`,
    [String(staffUserId).trim(),String(belongsTo).trim(),status,actor.id]
  );
  await audit(actor.id,"STAFF_VERIFICATION_UPSERT","staff_verification",staffUserId,{belongsTo,status});
  return send(res,200,{ok:true,verification:r.rows[0]});
};
