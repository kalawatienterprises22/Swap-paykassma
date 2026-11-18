const { getPool } = require("../_lib/db");
const { sendJson, allowMethods } = require("../_lib/http");
const { verifyToken } = require("../_lib/auth");

const forbidden=/password|passcode|otp|pin|cvv|security.?code|net.?banking.?login/i;
function auth(req,res){
 const h=req.headers.authorization||"",t=h.startsWith("Bearer ")?h.slice(7):"";
 if(!t){sendJson(res,401,{ok:false,message:"Authentication required"});return null;}
 try{
  const u=verifyToken(t);
  if(!["SUPER_ADMIN","ADMIN","MERCHANT"].includes(u.role)){sendJson(res,403,{ok:false,message:"Access denied"});return null;}
  return u;
 }catch{sendJson(res,401,{ok:false,message:"Invalid or expired session"});return null;}
}
module.exports=async(req,res)=>{
 if(!allowMethods(req,res,["GET","POST","PATCH"]))return;
 const actor=auth(req,res);if(!actor)return;
 try{
  const pool=getPool();
  if(req.method==="GET"){
   const r=await pool.query("SELECT provider_key, config, updated_at FROM sp_provider_configs ORDER BY provider_key");
   if(actor.role==="SUPER_ADMIN"){
    const users=await pool.query("SELECT u.id,u.user_id,u.display_name,u.role,COALESCE(a.options,'[]'::jsonb) AS options FROM sp_users u LEFT JOIN sp_user_account_options a ON a.user_id=u.id WHERE u.role IN ('ADMIN','MERCHANT') AND u.status='ACTIVE' ORDER BY u.role,u.display_name");
    const accounts=await pool.query(`SELECT a.id,a.merchant_id,a.account_name,a.provider_key,a.provider_label,a.account_details,a.status,a.submitted_at,a.review_note,u.user_id,u.display_name
      FROM sp_merchant_accounts a JOIN sp_users u ON u.id=a.merchant_id
      ORDER BY CASE a.status WHEN 'PENDING' THEN 0 ELSE 1 END,a.submitted_at DESC LIMIT 500`);
    return sendJson(res,200,{ok:true,providers:r.rows,users:users.rows,accounts:accounts.rows});
   }
   const a=await pool.query("SELECT options FROM sp_user_account_options WHERE user_id=$1",[actor.sub]);
   const accounts=await pool.query("SELECT id,account_name,provider_key,provider_label,account_details,status,submitted_at,review_note FROM sp_merchant_accounts WHERE merchant_id=$1 ORDER BY submitted_at DESC",[actor.sub]);
   return sendJson(res,200,{ok:true,providers:r.rows,allowed_options:a.rows[0]?.options||[],accounts:accounts.rows});
  }

  if(req.method==="PATCH"){
   if(actor.role!=="SUPER_ADMIN")return sendJson(res,403,{ok:false,message:"Super Admin approval required"});
   const {id,status,review_note}=req.body||{};
   if(!/^[0-9a-f-]{36}$/i.test(String(id||""))||!["APPROVED","REJECTED"].includes(status))return sendJson(res,400,{ok:false,message:"Choose a valid account and approval status"});
   const result=await pool.query(`UPDATE sp_merchant_accounts SET status=$1,reviewed_by=$2,reviewed_at=now(),review_note=$3
      WHERE id=$4 AND status='PENDING'
      RETURNING id,merchant_id,account_name,status`,[status,actor.sub,String(review_note||"").slice(0,500),id]);
   if(!result.rowCount)return sendJson(res,404,{ok:false,message:"Pending account request not found"});
   const a=result.rows[0];
   await pool.query("INSERT INTO sp_notifications(user_id,title,message,category) VALUES($1,$2,$3,'ACCOUNT_APPROVAL')",
    [a.merchant_id,status==="APPROVED"?"Account approved":"Account request rejected",`Your account "${a.account_name}" was ${status.toLowerCase()} by Super Admin.`]);
   await pool.query("INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,$2,'MERCHANT_ACCOUNT',$3,$4)",
    [actor.sub,"MERCHANT_ACCOUNT_"+status,a.id,JSON.stringify({merchant_id:a.merchant_id,review_note:String(review_note||"").slice(0,500)})]);
   return sendJson(res,200,{ok:true,account:a});
  }

  const body=req.body||{};
  if(body.action==="submit_account"){
   if(!["MERCHANT","ADMIN"].includes(actor.role))return sendJson(res,403,{ok:false,message:"Only Merchant or Admin accounts can submit account requests"});
   const name=String(body.account_name||"").trim(),key=String(body.provider_key||"").trim(),label=String(body.provider_label||"").trim();
   const details=body.account_details&&typeof body.account_details==="object"&&!Array.isArray(body.account_details)?body.account_details:{};
   if(name.length<2||name.length>100||!key||key.length>80||!label||label.length>120)return sendJson(res,400,{ok:false,message:"Enter a valid account name and provider"});
   const serialized=JSON.stringify(details);
   if(serialized.length>12000||forbidden.test(serialized))return sendJson(res,400,{ok:false,message:"Invalid account details. Password, PIN and OTP must not be submitted."});
   const allowed=await pool.query("SELECT options FROM sp_user_account_options WHERE user_id=$1",[actor.sub]);
   const options=allowed.rows[0]?.options||[];
   if(!options.includes(key))return sendJson(res,403,{ok:false,message:"This bank or payment app has not been enabled for your account by Super Admin"});
   const result=await pool.query(`INSERT INTO sp_merchant_accounts(merchant_id,account_name,provider_key,provider_label,account_details)
      VALUES($1,$2,$3,$4,$5::jsonb)
      RETURNING id,account_name,provider_key,provider_label,account_details,status,submitted_at`,
      [actor.sub,name,key,label,serialized]);
   await pool.query("INSERT INTO sp_notifications(user_id,title,message,category) SELECT id,'New account approval request',$1,'ACCOUNT_APPROVAL' FROM sp_users WHERE role='SUPER_ADMIN' AND status='ACTIVE'",
      [`Merchant ${actor.user_id||actor.sub} submitted "${name}" for approval.`]);
   await pool.query("INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,'MERCHANT_ACCOUNT_SUBMITTED','MERCHANT_ACCOUNT',$2,$3)",
      [actor.sub,result.rows[0].id,JSON.stringify({account_name:name,provider_key:key})]);
   return sendJson(res,201,{ok:true,account:result.rows[0],message:"Account request sent to Super Admin for approval"});
  }

  if(actor.role!=="SUPER_ADMIN")return sendJson(res,403,{ok:false,message:"Super Admin access required"});
  if(body.action==="assign_options"){
   const userId=String(body.user_id||"");
   const options=Array.isArray(body.options)?[...new Set(body.options.map(String))]:null;
   if(!/^[0-9a-f-]{36}$/i.test(userId)||!options||options.length>200)return sendJson(res,400,{ok:false,message:"Choose a valid user and options"});
   const valid=await pool.query("SELECT id FROM sp_users WHERE id=$1 AND role IN ('ADMIN','MERCHANT') AND status='ACTIVE'",[userId]);
   if(!valid.rowCount)return sendJson(res,404,{ok:false,message:"Active Admin or Merchant not found"});
   await pool.query(`INSERT INTO sp_user_account_options(user_id,options,updated_by,updated_at) VALUES($1,$2::jsonb,$3,now()) ON CONFLICT(user_id) DO UPDATE SET options=EXCLUDED.options,updated_by=EXCLUDED.updated_by,updated_at=now()`,[userId,JSON.stringify(options),actor.sub]);
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
  await pool.query(`INSERT INTO sp_provider_configs(provider_key,config,updated_by,updated_at) VALUES($1,$2::jsonb,$3,now()) ON CONFLICT(provider_key) DO UPDATE SET config=EXCLUDED.config,updated_by=EXCLUDED.updated_by,updated_at=now()`,[provider_key,JSON.stringify({fields:clean}),actor.sub]);
  return sendJson(res,200,{ok:true,message:"Fields saved",provider_key,fields:clean});
 }catch(e){
  console.error("Provider/account API:",e.message);
  return sendJson(res,500,{ok:false,message:e.code==="42P01"?"Run db/account-options.sql and db/merchant-account-approvals.sql once in Neon SQL Editor":"Could not process account request"});
 }
};
