const { query } = require("../_lib/db");
const { send, method } = require("../_lib/http");
module.exports = async (req,res) => {
  if (!method(req,res,["GET"])) return;
  const id = String(req.query.userId || "").trim();
  if (!id) return send(res,400,{ok:false,error:"userId is required"});
  try {
    const r = await query("SELECT belongs_to FROM sp_staff_verifications WHERE staff_user_id=$1 AND status='ACTIVE'",[id]);
    if (!r.rows[0]) return send(res,404,{ok:true,verified:false,message:"Staff not verified"});
    return send(res,200,{ok:true,verified:true,message:"Staff Verified",belongsTo:r.rows[0].belongs_to});
  } catch(e) {
    console.error("staff check error",e.message);
    return send(res,500,{ok:false,error:"Verification unavailable"});
  }
};
