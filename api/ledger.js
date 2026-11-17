const { getPool } = require("../_lib/db");
const { sendJson, allowMethods } = require("../_lib/http");
const { verifyToken } = require("../_lib/auth");

function authenticate(req,res) {
  const h=req.headers.authorization||"";
  const token=h.startsWith("Bearer ")?h.slice(7):"";
  if(!token){sendJson(res,401,{ok:false,message:"Authentication required"});return null;}
  try{return verifyToken(token);}catch{sendJson(res,401,{ok:false,message:"Invalid or expired session"});return null;}
}

module.exports = async (req,res) => {
  if(!allowMethods(req,res,["GET","POST"])) return;
  const actor=authenticate(req,res);
  if(!actor) return;
  if(!["SUPER_ADMIN","ADMIN","MERCHANT"].includes(actor.role)){
    return sendJson(res,403,{ok:false,message:"Access denied"});
  }
  const pool=getPool();

  if(req.method==="GET"){
    try{
      const isMerchant=actor.role==="MERCHANT";
      const values=isMerchant?[actor.sub]:[];
      const where=isMerchant?"WHERE u.id=$1":"";
      const [summary,entries]=await Promise.all([
        pool.query(
          `SELECT u.id AS merchant_id,u.user_id,u.display_name,
             COALESCE(SUM(l.amount_inr),0)::numeric(20,2) AS balance_inr,
             COALESCE(SUM(l.amount_inr) FILTER (WHERE l.amount_inr>0),0)::numeric(20,2) AS total_credited,
             COALESCE(-SUM(l.amount_inr) FILTER (WHERE l.amount_inr<0),0)::numeric(20,2) AS total_debited
           FROM sp_users u LEFT JOIN sp_ledger l ON l.merchant_id=u.id
           ${where} ${isMerchant?"AND u.role='MERCHANT'":"WHERE u.role='MERCHANT'"}
           GROUP BY u.id,u.user_id,u.display_name ORDER BY u.display_name`,
          values
        ),
        pool.query(
          `SELECT l.id,l.merchant_id,u.user_id,u.display_name,l.reference,l.entry_type,
             l.amount_inr,l.description,l.created_at
           FROM sp_ledger l JOIN sp_users u ON u.id=l.merchant_id
           ${isMerchant?"WHERE l.merchant_id=$1":""}
           ORDER BY l.created_at DESC LIMIT 300`,
          values
        )
      ]);
      const totals=summary.rows.reduce((a,r)=>({
        deposited:a.deposited+Number(r.total_credited),
        paid:a.paid+Number(r.total_debited),
        balance:a.balance+Number(r.balance_inr)
      }),{deposited:0,paid:0,balance:0});
      return sendJson(res,200,{ok:true,merchants:summary.rows,entries:entries.rows,totals});
    }catch(e){
      console.error("Balance read error:",e.message);
      return sendJson(res,500,{ok:false,message:"Balance data unavailable"});
    }
  }

  if(actor.role==="MERCHANT") return sendJson(res,403,{ok:false,message:"Merchant payment entries require a verified payment notification; manual balance changes are disabled"});
  const {merchant_id,type,amount,reference,description}=req.body||{};
  const allowed=["DEPOSIT","PAYMENT","MANUAL_CREDIT","MANUAL_DEBIT"];
  const value=Number(amount);
  if(!allowed.includes(type)||!Number.isFinite(value)||value<=0||value>100000000000||
     typeof reference!=="string"||reference.trim().length<4||reference.trim().length>120){
    return sendJson(res,400,{ok:false,message:"Enter a valid type, amount and unique reference (at least 4 characters)"});
  }
  const target=merchant_id;
  if(typeof target!=="string"||!/^[0-9a-f-]{36}$/i.test(target)){
    return sendJson(res,400,{ok:false,message:"Select a valid merchant"});
  }
  if(type==="PAYMENT" && (!description||String(description).trim().length<2)){
    return sendJson(res,400,{ok:false,message:"Payment description is required"});
  }

  const signedAmount=["DEPOSIT","MANUAL_CREDIT"].includes(type)?value:-value;
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    const merchant=await client.query(
      "SELECT id,user_id FROM sp_users WHERE id=$1 AND role='MERCHANT' AND status='ACTIVE' FOR UPDATE",
      [target]
    );
    if(!merchant.rows.length){await client.query("ROLLBACK");return sendJson(res,404,{ok:false,message:"Active merchant not found"});}
    if(signedAmount<0){
      const bal=await client.query("SELECT COALESCE(SUM(amount_inr),0)::numeric AS balance FROM sp_ledger WHERE merchant_id=$1",[target]);
      if(Number(bal.rows[0].balance)+signedAmount < -0.000001){
        await client.query("ROLLBACK");
        return sendJson(res,409,{ok:false,message:"Insufficient merchant balance"});
      }
    }
    const inserted=await client.query(
      `INSERT INTO sp_ledger(merchant_id,reference,entry_type,amount_inr,description,created_by)
       VALUES($1,$2,$3,$4,$5,$6)
       RETURNING id,merchant_id,reference,entry_type,amount_inr,description,created_at`,
      [target,reference.trim(),type,signedAmount,String(description||type).trim().slice(0,240),actor.sub]
    );
    await client.query(
      `INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details)
       VALUES($1,'BALANCE_LEDGER_ENTRY','MERCHANT',$2,$3)`,
      [actor.sub,target,JSON.stringify({type,amount:value,reference:reference.trim()})]
    );
    await client.query("COMMIT");
    return sendJson(res,201,{ok:true,entry:inserted.rows[0]});
  }catch(e){
    await client.query("ROLLBACK");
    if(e.code==="23505") return sendJson(res,409,{ok:false,message:"This reference number has already been used"});
    console.error("Balance entry error:",e.message);
    return sendJson(res,500,{ok:false,message:"Unable to save balance entry"});
  }finally{client.release();}
};
