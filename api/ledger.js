const { getPool } = require("./_lib/db");
const { sendJson, allowMethods } = require("./_lib/http");
const { verifyToken } = require("./_lib/auth");

function authenticate(req,res) {
  const h=req.headers.authorization||"", token=h.startsWith("Bearer ")?h.slice(7):"";
  if(!token){sendJson(res,401,{ok:false,message:"Authentication required"});return null;}
  try{return verifyToken(token);}catch{sendJson(res,401,{ok:false,message:"Invalid or expired session"});return null;}
}

module.exports = async (req,res) => {
  if(!allowMethods(req,res,["GET","POST","PATCH"])) return;
  const actor=authenticate(req,res);
  if(!actor) return;
  if(!["SUPER_ADMIN","ADMIN","MERCHANT"].includes(actor.role)) return sendJson(res,403,{ok:false,message:"Access denied"});
  const pool=getPool();

  if (String(req.query?.resource || "") === "withdrawals") {
    if (req.method === "GET") {
      const scope = actor.role === "MERCHANT" ? "w.merchant_id=$1" : actor.role === "ADMIN" ? "u.parent_admin_id=$1" : "TRUE";
      const values = actor.role === "SUPER_ADMIN" ? [] : [actor.sub];
      const result = await pool.query(
        `SELECT w.id,w.merchant_id,u.user_id,u.display_name,w.account_id,
                a.account_name,a.provider_label,a.account_details,w.amount_inr,
                w.status,w.requested_at,w.reviewed_at,w.review_note,w.payout_reference,w.paid_at
         FROM sp_withdrawal_requests w
         JOIN sp_users u ON u.id=w.merchant_id
         JOIN sp_merchant_accounts a ON a.id=w.account_id
         WHERE ${scope}
         ORDER BY w.requested_at DESC LIMIT 300`,
        values
      );
      return sendJson(res,200,{ok:true,requests:result.rows});
    }

    if (req.method === "POST") {
      if (actor.role !== "MERCHANT") return sendJson(res,403,{ok:false,message:"Only Merchants can request withdrawals"});
      const accountId=String(req.body?.account_id||"");
      const amount=Number(req.body?.amount_inr);
      if(!/^[0-9a-f-]{36}$/i.test(accountId)||!Number.isFinite(amount)||amount<=0||amount>100000000000)
        return sendJson(res,400,{ok:false,message:"Select an approved account and enter a valid amount"});
      const client=await pool.connect();
      try {
        await client.query("BEGIN");
        const account=await client.query("SELECT id FROM sp_merchant_accounts WHERE id=$1 AND merchant_id=$2 AND status='APPROVED' FOR UPDATE",[accountId,actor.sub]);
        if(!account.rowCount){await client.query("ROLLBACK");return sendJson(res,400,{ok:false,message:"Choose an approved withdrawal account"});}
        const merchant=await client.query("SELECT id FROM sp_users WHERE id=$1 AND role='MERCHANT' AND status='ACTIVE' FOR UPDATE",[actor.sub]);
        if(!merchant.rowCount){await client.query("ROLLBACK");return sendJson(res,403,{ok:false,message:"Active Merchant account required"});}
        const balance=await client.query("SELECT COALESCE(SUM(amount_inr),0)::numeric AS balance FROM sp_ledger WHERE merchant_id=$1",[actor.sub]);
        const reserved=await client.query("SELECT COALESCE(SUM(amount_inr),0)::numeric AS reserved FROM sp_withdrawal_requests WHERE merchant_id=$1 AND status IN ('PENDING','APPROVED')",[actor.sub]);
        const available=Number(balance.rows[0].balance)-Number(reserved.rows[0].reserved);
        if(amount>available+0.000001){await client.query("ROLLBACK");return sendJson(res,409,{ok:false,message:"Insufficient available balance after pending withdrawal reservations",available_inr:Math.max(0,available)});}
        const saved=await client.query("INSERT INTO sp_withdrawal_requests(merchant_id,account_id,amount_inr) VALUES($1,$2,$3) RETURNING id,amount_inr,status,requested_at",[actor.sub,accountId,amount.toFixed(2)]);
        await client.query("INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,'WITHDRAWAL_REQUESTED','WITHDRAWAL',$2,$3)",[actor.sub,saved.rows[0].id,JSON.stringify({account_id:accountId,amount_inr:amount})]);
        await client.query("COMMIT");
        return sendJson(res,201,{ok:true,request:saved.rows[0],message:"Withdrawal request submitted for Admin review. No money has been transferred."});
      } catch(e) { await client.query("ROLLBACK"); throw e; }
      finally { client.release(); }
    }

    if(actor.role==="MERCHANT") return sendJson(res,403,{ok:false,message:"Admin review required"});
    const id=String(req.body?.id||""), action=String(req.body?.action||""), note=String(req.body?.review_note||"").trim().slice(0,500);
    if(!/^[0-9a-f-]{36}$/i.test(id)||!["approve","reject","mark_paid"].includes(action))
      return sendJson(res,400,{ok:false,message:"Invalid withdrawal review action"});
    const client=await pool.connect();
    try {
      await client.query("BEGIN");
      const q=await client.query(
        `SELECT w.*,u.parent_admin_id FROM sp_withdrawal_requests w
         JOIN sp_users u ON u.id=w.merchant_id
         WHERE w.id=$1 AND ($2='SUPER_ADMIN' OR ($2='ADMIN' AND u.parent_admin_id=$3))
         FOR UPDATE OF w,u`,
        [id,actor.role,actor.sub]
      );
      if(!q.rowCount){await client.query("ROLLBACK");return sendJson(res,404,{ok:false,message:"Withdrawal request not found in your assigned scope"});}
      const w=q.rows[0];
      if(action==="approve"||action==="reject"){
        if(w.status!=="PENDING"){await client.query("ROLLBACK");return sendJson(res,409,{ok:false,message:"Only pending requests can be approved or rejected"});}
        const next=action==="approve"?"APPROVED":"REJECTED";
        const saved=await client.query("UPDATE sp_withdrawal_requests SET status=$1,reviewed_by=$2,reviewed_at=now(),review_note=$3 WHERE id=$4 RETURNING id,status,amount_inr",[next,actor.sub,note,id]);
        await client.query("INSERT INTO sp_notifications(user_id,title,message,category) VALUES($1,$2,$3,'WITHDRAWAL')",[w.merchant_id,next==="APPROVED"?"Withdrawal approved":"Withdrawal rejected",next==="APPROVED"?"Your withdrawal request was approved. Payout is not yet confirmed.":"Your withdrawal request was rejected. "+note]);
        await client.query("INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,$2,'WITHDRAWAL',$3,$4)",[actor.sub,"WITHDRAWAL_"+next,id,JSON.stringify({amount_inr:w.amount_inr,review_note:note})]);
        await client.query("COMMIT");
        return sendJson(res,200,{ok:true,request:saved.rows[0]});
      }
      if(w.status!=="APPROVED"){await client.query("ROLLBACK");return sendJson(res,409,{ok:false,message:"Only approved requests can be marked paid"});}
      const payoutReference=String(req.body?.payout_reference||"").trim();
      if(payoutReference.length<4||payoutReference.length>120){await client.query("ROLLBACK");return sendJson(res,400,{ok:false,message:"Enter the external bank / UPI transfer reference after completing the transfer"});}
      await client.query("SELECT id FROM sp_users WHERE id=$1 FOR UPDATE",[w.merchant_id]);
      const balance=await client.query("SELECT COALESCE(SUM(amount_inr),0)::numeric AS balance FROM sp_ledger WHERE merchant_id=$1",[w.merchant_id]);
      const reserved=await client.query("SELECT COALESCE(SUM(amount_inr),0)::numeric AS reserved FROM sp_withdrawal_requests WHERE merchant_id=$1 AND status IN ('PENDING','APPROVED') AND id<>$2",[w.merchant_id,id]);
      if(Number(balance.rows[0].balance)-Number(reserved.rows[0].reserved)<Number(w.amount_inr)-0.000001){await client.query("ROLLBACK");return sendJson(res,409,{ok:false,message:"Available balance is no longer sufficient to complete this payout"});}
      const ledgerReference="WITHDRAWAL-"+id;
      await client.query("INSERT INTO sp_ledger(merchant_id,reference,entry_type,amount_inr,description,created_by) VALUES($1,$2,'PAYMENT',$3,$4,$5)",[w.merchant_id,ledgerReference,-Number(w.amount_inr),"Withdrawal payout · "+payoutReference,actor.sub]);
      const saved=await client.query("UPDATE sp_withdrawal_requests SET status='PAID',reviewed_by=$1,reviewed_at=COALESCE(reviewed_at,now()),payout_reference=$2,paid_at=now(),review_note=$3 WHERE id=$4 RETURNING id,status,amount_inr,payout_reference,paid_at",[actor.sub,payoutReference,note,id]);
      await client.query("INSERT INTO sp_notifications(user_id,title,message,category) VALUES($1,'Withdrawal paid',$2,'WITHDRAWAL')",[w.merchant_id,"Your withdrawal of INR "+Number(w.amount_inr).toFixed(2)+" was marked paid. Reference: "+payoutReference]);
      await client.query("INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,'WITHDRAWAL_PAID','WITHDRAWAL',$2,$3)",[actor.sub,id,JSON.stringify({amount_inr:w.amount_inr,payout_reference:payoutReference,ledger_reference:ledgerReference})]);
      await client.query("COMMIT");
      return sendJson(res,200,{ok:true,request:saved.rows[0],message:"Payout recorded. This endpoint does not initiate a bank transfer."});
    } catch(e) {
      await client.query("ROLLBACK");
      if(e.code==="23505") return sendJson(res,409,{ok:false,message:"This payout reference or ledger entry has already been used"});
      throw e;
    } finally { client.release(); }
  }

  if(req.method==="GET"){
    if(String(req.query?.portal||"")==="merchant" && actor.role!=="MERCHANT") return sendJson(res,403,{ok:false,message:"Merchant dashboard access is only available to Merchant accounts. Please use your role dashboard."});
    try{
      const scope = actor.role==="MERCHANT" ? "u.id=$1" : actor.role==="ADMIN" ? "u.parent_admin_id=$1" : "TRUE";
      const values=actor.role==="SUPER_ADMIN"?[]:[actor.sub];
      const [summary,entries]=await Promise.all([
        pool.query(
          `SELECT u.id AS merchant_id,u.user_id,u.display_name,
             COALESCE(SUM(l.amount_inr),0)::numeric(20,2) AS balance_inr,
             COALESCE(SUM(l.amount_inr) FILTER (WHERE l.amount_inr>0),0)::numeric(20,2) AS total_credited,
             COALESCE(-SUM(l.amount_inr) FILTER (WHERE l.amount_inr<0),0)::numeric(20,2) AS total_debited,
             COALESCE(-SUM(l.amount_inr) FILTER (WHERE l.entry_type='COMMISSION' AND l.amount_inr<0),0)::numeric(20,2) AS total_commission,
             COALESCE(-SUM(l.amount_inr) FILTER (WHERE l.entry_type='CHARGE' AND l.amount_inr<0),0)::numeric(20,2) AS total_charges
           FROM sp_users u LEFT JOIN sp_ledger l ON l.merchant_id=u.id
           WHERE ${scope} AND u.role='MERCHANT'
           GROUP BY u.id,u.user_id,u.display_name ORDER BY u.display_name`,
          values
        ),
        pool.query(
          `SELECT l.id,l.merchant_id,u.user_id,u.display_name,l.reference,l.entry_type,
             l.amount_inr,l.description,l.created_at
           FROM sp_ledger l JOIN sp_users u ON u.id=l.merchant_id
           WHERE ${scope}
           ORDER BY l.created_at DESC LIMIT 300`,
          values
        )
      ]);
      const totals=summary.rows.reduce((a,r)=>({
        deposited:a.deposited+Number(r.total_credited),
        paid:a.paid+Number(r.total_debited),
        commission:a.commission+Number(r.total_commission),
        charges:a.charges+Number(r.total_charges),
        balance:a.balance+Number(r.balance_inr)
      }),{deposited:0,paid:0,commission:0,charges:0,balance:0});
      if(actor.role==="MERCHANT"){
        const reserved=await pool.query("SELECT COALESCE(SUM(amount_inr),0)::numeric AS reserved FROM sp_withdrawal_requests WHERE merchant_id=$1 AND status IN ('PENDING','APPROVED')",[actor.sub]);
        totals.reserved=Number(reserved.rows[0].reserved);
        totals.balance-=totals.reserved;
      }
      return sendJson(res,200,{ok:true,merchants:summary.rows,entries:entries.rows,totals});
    }catch(e){
      console.error("Balance read error:",e.message);
      return sendJson(res,500,{ok:false,message:e.code==="42703"?"Run the latest parent-admin migration in Neon SQL Editor first.":"Balance data unavailable"});
    }
  }

  if(actor.role==="MERCHANT") return sendJson(res,403,{ok:false,message:"Merchant payment entries require a verified payment notification; manual balance changes are disabled"});
  const {merchant_id,type,amount,reference,description}=req.body||{};
  const allowed=["DEPOSIT","PAYMENT","MANUAL_CREDIT","MANUAL_DEBIT","COMMISSION","CHARGE"];
  const value=Number(amount);
  if(!allowed.includes(type)||!Number.isFinite(value)||value<=0||value>100000000000||
     typeof reference!=="string"||reference.trim().length<4||reference.trim().length>120){
    return sendJson(res,400,{ok:false,message:"Enter a valid type, amount and unique reference (at least 4 characters)"});
  }
  if(typeof merchant_id!=="string"||!/^[0-9a-f-]{36}$/i.test(merchant_id)) return sendJson(res,400,{ok:false,message:"Select a valid merchant"});
  if(type==="PAYMENT" && (!description||String(description).trim().length<2)) return sendJson(res,400,{ok:false,message:"Payment description is required"});

  const signedAmount=["DEPOSIT","MANUAL_CREDIT"].includes(type)?value:-value;
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    const merchant=await client.query(
      `SELECT id,user_id FROM sp_users
       WHERE id=$1 AND role='MERCHANT' AND status='ACTIVE'
         AND ($2='SUPER_ADMIN' OR ($2='ADMIN' AND parent_admin_id=$3))
       FOR UPDATE`,
      [merchant_id,actor.role,actor.sub]
    );
    if(!merchant.rowCount){await client.query("ROLLBACK");return sendJson(res,404,{ok:false,message:"Active merchant not found in your assigned scope"});}
    if(signedAmount<0){
      const bal=await client.query("SELECT COALESCE(SUM(amount_inr),0)::numeric AS balance FROM sp_ledger WHERE merchant_id=$1",[merchant_id]);
      if(Number(bal.rows[0].balance)+signedAmount < -0.000001){await client.query("ROLLBACK");return sendJson(res,409,{ok:false,message:"Insufficient merchant balance"});}
    }
    const inserted=await client.query(
      `INSERT INTO sp_ledger(merchant_id,reference,entry_type,amount_inr,description,created_by)
       VALUES($1,$2,$3,$4,$5,$6)
       RETURNING id,merchant_id,reference,entry_type,amount_inr,description,created_at`,
      [merchant_id,reference.trim(),type,signedAmount,String(description||type).trim().slice(0,240),actor.sub]
    );
    await client.query("INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,'BALANCE_LEDGER_ENTRY','MERCHANT',$2,$3)",
      [actor.sub,merchant_id,JSON.stringify({type,amount:value,reference:reference.trim()})]);
    await client.query("COMMIT");
    return sendJson(res,201,{ok:true,entry:inserted.rows[0]});
  }catch(e){
    await client.query("ROLLBACK");
    if(e.code==="23505") return sendJson(res,409,{ok:false,message:"This reference number has already been used"});
    console.error("Balance entry error:",e.message);
    return sendJson(res,500,{ok:false,message:e.code==="42703"?"Run the latest parent-admin migration in Neon SQL Editor first.":"Unable to save balance entry"});
  }finally{client.release();}
};
