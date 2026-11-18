const { getPool } = require("../_lib/db");
const { sendJson, allowMethods } = require("../_lib/http");
const { verifyToken } = require("../_lib/auth");

function admin(req,res,write){
 const h=req.headers.authorization||"",t=h.startsWith("Bearer ")?h.slice(7):"";
 if(!t){sendJson(res,401,{ok:false,message:"Authentication required"});return false;}
 try{const u=verifyToken(t);req._adminId=u.sub;req._role=u.role;if(write && u.role!=="SUPER_ADMIN"){sendJson(res,403,{ok:false,message:"Super Admin access required"});return false;}if(!["SUPER_ADMIN","ADMIN","MERCHANT"].includes(u.role)){sendJson(res,403,{ok:false,message:"Access denied"});return false;}return true;}
 catch{sendJson(res,401,{ok:false,message:"Invalid or expired session"});return false;}
}
const forbidden=/password|passcode|otp|pin|cvv|security.?code|net.?banking.?login/i;
module.exports=async(req,res)=>{
 if(!allowMethods(req,res,["GET","POST"]))return;
 if(!admin(req,res,req.method==="POST"))return;
 try{
  const pool=getPool();
  if(req.method==="GET"){
   const r=await pool.query("SELECT provider_key, config, updated_at FROM sp_provider_configs ORDER BY provider_key");
   if(req._role==="SUPER_ADMIN"){
    const users=await pool.query("SELECT u.id,u.user_id,u.display_name,u.role,COALESCE(a.options,'[]'::jsonb) AS options FROM sp_users u LEFT JOIN sp_user_account_options a ON a.user_id=u.id WHERE u.role IN ('ADMIN','MERCHANT') AND u.status='ACTIVE' ORDER BY u.role,u.display_name");
    return sendJson(res,200,{ok:true,providers:r.rows,users:users.rows});
   }
   const a=await pool.query("SELECT options FROM sp_user_account_options WHERE user_id=$1",[req._adminId]);
   return sendJson(res,200,{ok:true,providers:r.rows,allowed_options:a.rows[0]?.options||[]});
  }
  const body=req.body||{};
  if(body.action==="assign_options"){
   const userId=String(body.user_id||"");
   const options=Array.isArray(body.options)?[...new Set(body.options.map(String))]:null;
   if(!/^[0-9a-f-]{36}$/i.test(userId)||!options||options.length>200)return sendJson(res,400,{ok:false,message:"Choose a valid user and options"});
   const valid=await pool.query("SELECT id FROM sp_users WHERE id=$1 AND role IN ('ADMIN','MERCHANT') AND status='ACTIVE'",[userId]);
   if(!valid.rowCount)return sendJson(res,404,{ok:false,message:"Active Admin or Merchant not found"});
   await pool.query(`INSERT INTO sp_user_account_options(user_id,options,updated_by,updated_at) VALUES($1,$2::jsonb,$3,now()) ON CONFLICT(user_id) DO UPDATE SET options=EXCLUDED.options,updated_by=EXCLUDED.updated_by,updated_at=now()`,[userId,JSON.stringify(options),req._adminId]);
   return sendJson(res,200,{ok:true,message:"Account options assigned",options});
  }
  const {provider_key,fields}=body;
  if(!["UPI","BANK","WALLET","OTHER"].includes(provider_key))return sendJson(res,400,{ok:false,message:"Invalid account type"});
  if(!Array.isArray(fields)||fields.length>30)return sendJson(res,400,{ok:false,message:"Add up to 30 fields"});
  const clean=[],seen=new Set();
  for(const f of fields){
   const key=String(f.key||"").trim().toLowerCase(),label=String(f.label||"").trim(),type=String(f.type||"text").toLowerCase();
   if(!/^[a-z][a-z0-9_]{1,39}$/.test(key)||!label||label.length>60||!["text","number","email","tel","date"].includes(type)||seen.has(key))return sendJson(res,400,{ok:false,message:"Check field name, label and type"});
   if(forbidden.test(key+" "+label))return sendJson(res,400,{ok:false,message:"Authentication secrets such as passwords, PINs and OTPs cannot be collected"});
   seen.add(key);clean.push({key,label,type,required:!!f.required});
  }
  await pool.query(`INSERT INTO sp_provider_configs(provider_key,config,updated_by,updated_at) VALUES($1,$2::jsonb,$3,now()) ON CONFLICT(provider_key) DO UPDATE SET config=EXCLUDED.config,updated_by=EXCLUDED.updated_by,updated_at=now()`,[provider_key,JSON.stringify({fields:clean}),req._adminId||null]);
  return sendJson(res,200,{ok:true,message:"Fields saved",provider_key,fields:clean});
 }catch(e){console.error("Provider fields API:",e.message);return sendJson(res,500,{ok:false,message:e.code==="42P01"?"Run db/account-options.sql once in Neon SQL Editor":"Could not save account configuration"});}
};