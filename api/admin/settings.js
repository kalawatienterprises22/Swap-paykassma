const { query } = require("../_lib/db");
const { requireUser, audit } = require("../_lib/auth");
const { send, method } = require("../_lib/http");
module.exports = async (req,res) => {
  if (!method(req,res,["GET","PUT"])) return;
  const actor = await requireUser(req,res,["SUPER_ADMIN"]);
  if (!actor) return;
  if (req.method === "GET") {
    const r = await query("SELECT key,value,updated_at FROM sp_settings ORDER BY key");
    return send(res,200,{ok:true,settings:r.rows});
  }
  const { key,value } = req.body || {};
  if (!["maintenance","commission"].includes(key) || !value || typeof value !== "object") {
    return send(res,400,{ok:false,error:"Unsupported setting"});
  }
  if (key === "maintenance" && (typeof value.enabled !== "boolean" || typeof value.message !== "string")) {
    return send(res,400,{ok:false,error:"Invalid maintenance setting"});
  }
  if (key === "commission" && (!["HOLD","CUSTOM","FULL_TO_MERCHANT"].includes(value.mode))) {
    return send(res,400,{ok:false,error:"Invalid commission mode"});
  }
  const r = await query(
    `INSERT INTO sp_settings(key,value,updated_by) VALUES($1,$2,$3)
     ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_by=EXCLUDED.updated_by,updated_at=now()
     RETURNING key,value,updated_at`,
    [key,JSON.stringify(value),actor.id]
  );
  await audit(actor.id,"SETTING_UPDATED",key,key,value);
  return send(res,200,{ok:true,setting:r.rows[0]});
};
