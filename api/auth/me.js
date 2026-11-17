const { requireUser } = require("../_lib/auth");
const { send, method } = require("../_lib/http");
module.exports = async (req,res) => {
  if (!method(req,res,["GET"])) return;
  const user = await requireUser(req,res);
  if (user) return send(res,200,{ok:true,user});
};
