const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { query } = require("../_lib/db");
const { send, method } = require("../_lib/http");

module.exports = async (req,res) => {
  if (!method(req,res,["POST"])) return;
  const { login, password } = req.body || {};
  if (!login || !password || !process.env.JWT_SECRET) {
    return send(res,400,{ok:false,error:"Login, password and JWT_SECRET are required"});
  }
  try {
    const r = await query(
      "SELECT id,user_id,email,password_hash,display_name,role,status FROM sp_users WHERE user_id=$1 OR email=$1 LIMIT 1",
      [String(login).trim()]
    );
    const u = r.rows[0];
    if (!u || u.status !== "ACTIVE" || !(await bcrypt.compare(String(password),u.password_hash))) {
      return send(res,401,{ok:false,error:"Invalid login or password"});
    }
    const token = jwt.sign({sub:u.id},process.env.JWT_SECRET,{expiresIn:"8h",issuer:"superpay"});
    return send(res,200,{ok:true,token,expiresIn:28800,user:{
      id:u.id,userId:u.user_id,name:u.display_name,role:u.role
    }});
  } catch(e) {
    console.error("login error",e.message);
    return send(res,500,{ok:false,error:"Unable to sign in"});
  }
};
