const { query } = require("../_lib/db");
const { requireUser } = require("../_lib/auth");
const { send, method } = require("../_lib/http");
module.exports = async (req,res) => {
  if (!method(req,res,["GET"])) return;
  const user = await requireUser(req,res);
  if (!user) return;
  const r = await query(
    "SELECT id,title,message,category,created_at,read_at FROM sp_notifications WHERE user_id=$1 OR user_id IS NULL ORDER BY created_at DESC LIMIT 100",
    [user.id]
  );
  return send(res,200,{ok:true,notifications:r.rows});
};
