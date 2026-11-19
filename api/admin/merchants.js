const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { getPool } = require("../_lib/db");
const { sendJson, allowMethods } = require("../_lib/http");
const { verifyToken } = require("../_lib/auth");


async function telegramCall(method, payload) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  if (!token) throw new Error("TELEGRAM_BOT_TOKEN is not configured");
  const response = await fetch("https://api.telegram.org/bot" + token + "/" + method, { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(payload) });
  const data = await response.json();
  if (!response.ok || !data.ok) throw new Error(data.description || "Telegram request failed");
  return data.result;
}
function encryptKyc(value) {
  if (!value) return null;
  const key = crypto.createHmac("sha256", String(process.env.JWT_SECRET || "")).update("superpay-kyc-encryption-v1").digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(String(value), "utf8"), cipher.final()]);
  return "v1:" + iv.toString("hex") + ":" + cipher.getAuthTag().toString("hex") + ":" + encrypted.toString("hex");
}
function decryptKyc(value) {
  if (!value) return "";
  const parts = String(value).split(":");
  if (parts.length !== 4 || parts[0] !== "v1") return "";
  const key = crypto.createHmac("sha256", String(process.env.JWT_SECRET || "")).update("superpay-kyc-encryption-v1").digest();
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(parts[1], "hex"));
  decipher.setAuthTag(Buffer.from(parts[2], "hex"));
  return Buffer.concat([decipher.update(Buffer.from(parts[3], "hex")), decipher.final()]).toString("utf8");
}
function normalizeMobile(value) {
  let digits = String(value || "").replace(/\D/g, "");
  if (digits.length === 12 && digits.startsWith("91")) digits = digits.slice(2);
  return digits;
}
function panFingerprint(value) {
  return crypto.createHmac("sha256", String(process.env.JWT_SECRET || ""))
    .update("superpay-pan-unique-v1:" + String(value || "").trim().toUpperCase())
    .digest("hex");
}
function telegramSecret() {
  return crypto.createHash("sha256").update(String(process.env.TELEGRAM_BOT_TOKEN || "") + ":superpay-webhook-v1").digest("hex").slice(0,48);
}
async function handleTelegramWebhook(req,res) {
  if (!process.env.TELEGRAM_BOT_TOKEN || req.headers["x-telegram-bot-api-secret-token"] !== telegramSecret()) return sendJson(res,401,{ok:false});
  const msg=req.body?.message, chatId=msg?.chat?.id, txt=String(msg?.text||"");
  if (!chatId || !txt.startsWith("/start")) return sendJson(res,200,{ok:true});
  const payload=txt.split(/\s+/)[1]||"";
  if (!payload.startsWith("link_")) {
    await telegramCall("sendMessage",{chat_id:chatId,text:"Welcome to SuperPay. Use the Connect Telegram button on your Merchant signup form to link your account."});
    return sendJson(res,200,{ok:true});
  }
  const raw=payload.slice(5);
  if (!/^[a-f0-9]{64}$/i.test(raw)) return sendJson(res,200,{ok:true});
  const hash=crypto.createHash("sha256").update(raw).digest("hex");
  const linked=await getPool().query("UPDATE sp_merchant_onboarding SET telegram_chat_id=$1,telegram_username=$2,telegram_verified_at=now(),telegram_link_token_hash=NULL,telegram_link_expires_at=NULL WHERE telegram_link_token_hash=$3 AND telegram_link_expires_at>now() AND telegram_chat_id IS NULL RETURNING merchant_id",[String(chatId),String(msg.from?.username||"").slice(0,80)||null,hash]);
  await telegramCall("sendMessage",{chat_id:chatId,text:linked.rowCount?"Telegram connected. Your SuperPay signup is waiting for Super Admin approval.":"This signup link is invalid or expired. Please register again to generate a fresh link."});
  return sendJson(res,200,{ok:true});
}

function authenticate(req, res) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) { sendJson(res, 401, { ok: false, message: "Authentication required" }); return null; }
  try {
    const user = verifyToken(token);
    if (!["SUPER_ADMIN", "ADMIN"].includes(user.role)) {
      sendJson(res, 403, { ok: false, message: "Admin access required" });
      return null;
    }
    return user;
  } catch {
    sendJson(res, 401, { ok: false, message: "Invalid or expired session" });
    return null;
  }
}

module.exports = async (req, res) => {
  if (req.method === "POST" && req.body?.message?.chat?.id) return handleTelegramWebhook(req,res);
  if (!allowMethods(req, res, ["GET", "POST", "PATCH"])) return;

    // Public referral registration: the referral code permanently assigns the new Merchant
    // to the referring Admin. The submitted parent ID is never trusted.
    if (req.method === "POST" && req.body?.action === "register_referral") {
      const pool = getPool();
      const { referral_code, display_name, email, phone, address, pan_number, aadhaar_number } = req.body || {};
      const code=String(referral_code||"").trim(), name=typeof display_name==="string"?display_name.trim():"";
      let accountId="";
      for(let attempt=0;attempt<10;attempt++){
        const candidate="SPM"+crypto.randomBytes(4).toString("hex").toUpperCase();
        const exists=await pool.query("SELECT 1 FROM sp_users WHERE user_id=$1",[candidate]);
        if(!exists.rowCount){accountId=candidate;break;}
      }
      if(!accountId) return sendJson(res,503,{ok:false,message:"Could not generate Merchant ID. Please try again."});
      const accountEmail=typeof email==="string"&&email.trim()?email.trim().toLowerCase():null, mobile=String(phone||"").trim(), fullAddress=String(address||"").trim();
      const pan=String(pan_number||"").trim().toUpperCase(), aadhaar=String(aadhaar_number||"").replace(/\D/g,"");
      const normalizedMobile=normalizeMobile(mobile), panHash=panFingerprint(pan);
      if(!/^[A-Za-z0-9_-]{20,100}$/.test(code)) return sendJson(res,400,{ok:false,message:"Invalid referral link"});
      if(name.length<2||name.length>80) return sendJson(res,400,{ok:false,message:"Name must be 2-80 characters"});
      if(mobile.length<8||mobile.length>20||normalizedMobile.length<8||normalizedMobile.length>15) return sendJson(res,400,{ok:false,message:"Enter a valid mobile number"});
      if(fullAddress.length<8||fullAddress.length>500) return sendJson(res,400,{ok:false,message:"Enter your full address"});
      if(!/^[A-Z]{5}[0-9]{4}[A-Z]$/.test(pan)) return sendJson(res,400,{ok:false,message:"Enter a valid 10-character PAN number"});
      if(aadhaar && !/^[0-9]{12}$/.test(aadhaar)) return sendJson(res,400,{ok:false,message:"Aadhaar number must contain exactly 12 digits"});
      if(accountEmail&&(accountEmail.length>254||!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(accountEmail))) return sendJson(res,400,{ok:false,message:"Enter a valid email address"});
      const referral=await pool.query("SELECT r.admin_id,a.user_id AS admin_user_id FROM sp_admin_referrals r JOIN sp_users a ON a.id=r.admin_id WHERE r.code=$1 AND r.active=TRUE AND a.role='ADMIN' AND a.status='ACTIVE'",[code]);
      if(!referral.rowCount) return sendJson(res,404,{ok:false,message:"This referral link is invalid or inactive"});
      const duplicate=await pool.query("SELECT CASE WHEN phone_normalized=$1 THEN 'MOBILE' WHEN pan_fingerprint=$2 THEN 'PAN' END AS duplicate_type FROM sp_merchant_onboarding WHERE phone_normalized=$1 OR pan_fingerprint=$2 LIMIT 1",[normalizedMobile,panHash]);
      if(duplicate.rowCount) return sendJson(res,409,{ok:false,message:duplicate.rows[0].duplicate_type==="MOBILE"?"This mobile number is already registered. Please use another number.":"This PAN number is already registered with SuperPay."});
      const passwordHash=await bcrypt.hash(crypto.randomBytes(48).toString("hex"),12);
      const created=await pool.query("INSERT INTO sp_users(id,user_id,email,password_hash,display_name,role,status,parent_admin_id) VALUES($1,$2,$3,$4,$5,'MERCHANT','SUSPENDED',$6) RETURNING id,user_id,display_name,role,status",[crypto.randomUUID(),accountId,accountEmail,passwordHash,name,referral.rows[0].admin_id]);
      const linkToken=crypto.randomBytes(32).toString("hex"), linkHash=crypto.createHash("sha256").update(linkToken).digest("hex");
      await pool.query("INSERT INTO sp_merchant_onboarding(merchant_id,phone,full_address,pan_number_encrypted,aadhaar_number_encrypted,phone_normalized,pan_fingerprint,telegram_link_token_hash,telegram_link_expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,now()+interval '30 minutes')",[created.rows[0].id,mobile,fullAddress,encryptKyc(pan),encryptKyc(aadhaar),normalizedMobile,panHash,linkHash]);
      await pool.query("INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,'MERCHANT_REFERRED_SIGNUP','MERCHANT',$2,$3)",[referral.rows[0].admin_id,created.rows[0].id,JSON.stringify({merchant_user_id:accountId,referral_admin_user_id:referral.rows[0].admin_user_id})]);
      await pool.query("INSERT INTO sp_notifications(user_id,title,message,category) SELECT id,'New Merchant referral signup',$1,'MERCHANT_SIGNUP' FROM sp_users WHERE (id=$2 OR role='SUPER_ADMIN') AND status='ACTIVE'",[`Merchant ${accountId} registered. Telegram connection and Super Admin approval are required.`,referral.rows[0].admin_id]);
      return sendJson(res,201,{ok:true,message:"Registration saved. Connect Telegram to finish verification.",bot_url:"https://t.me/superpay_notification_bot?start=link_"+linkToken,merchant:created.rows[0]});
    }

    if(req.method==="POST"&&req.body?.action==="set_merchant_password"){
      const pool=getPool();
      const raw=String(req.body?.token||""), password=req.body?.password;
      if(!/^[a-f0-9]{64}$/i.test(raw)||typeof password!=="string"||password.length<12||password.length>72) return sendJson(res,400,{ok:false,message:"Valid setup link and password (12-72 characters) required"});
      const hash=crypto.createHash("sha256").update(raw).digest("hex"), client=await pool.connect();
      try{
        await client.query("BEGIN");
        const found=await client.query("SELECT merchant_id FROM sp_merchant_onboarding WHERE setup_token_hash=$1 AND setup_expires_at>now() AND setup_used_at IS NULL FOR UPDATE",[hash]);
        if(!found.rowCount){await client.query("ROLLBACK");return sendJson(res,400,{ok:false,message:"Setup link is invalid or expired"});}
        const passwordHash=await bcrypt.hash(password,12);
        await client.query("UPDATE sp_users SET password_hash=$1,updated_at=now() WHERE id=$2 AND role='MERCHANT' AND status='ACTIVE'",[passwordHash,found.rows[0].merchant_id]);
        await client.query("UPDATE sp_merchant_onboarding SET setup_used_at=now(),setup_token_hash=NULL,setup_expires_at=NULL WHERE merchant_id=$1",[found.rows[0].merchant_id]);
        await client.query("COMMIT");return sendJson(res,200,{ok:true,message:"Password created. You can now login."});
      }catch(e){await client.query("ROLLBACK");throw e;}finally{client.release();}
    }

  const actor = authenticate(req, res);
  if (!actor) return;

  try {
    const pool = getPool();
    const activeActor = await pool.query(
      "SELECT id, role, status FROM sp_users WHERE id=$1",
      [actor.sub]
    );
    if (!activeActor.rowCount || activeActor.rows[0].status !== "ACTIVE" ||
        activeActor.rows[0].role !== actor.role) {
      return sendJson(res, 403, { ok: false, message: "Your account is not active" });
    }

    if (req.method === "GET") {

      if(actor.role==="SUPER_ADMIN"&&req.query?.action==="pending_signups"){
        const pending=await pool.query("SELECT u.id,u.user_id,u.display_name,u.email,u.created_at,o.phone,o.full_address,o.pan_number_encrypted,o.aadhaar_number_encrypted,o.telegram_username,o.telegram_verified_at FROM sp_users u JOIN sp_merchant_onboarding o ON o.merchant_id=u.id WHERE u.role='MERCHANT' AND u.status='SUSPENDED' AND o.review_status='PENDING' ORDER BY u.created_at DESC LIMIT 200");
        return sendJson(res,200,{ok:true,signups:pending.rows.map(row=>({ ...row, pan_number: decryptKyc(row.pan_number_encrypted), aadhaar_last4: decryptKyc(row.aadhaar_number_encrypted).slice(-4) }))});
      }
      if (actor.role === "ADMIN" && req.query?.action === "referral_link") {
        let referral = await pool.query("SELECT code FROM sp_admin_referrals WHERE admin_id=$1 AND active=TRUE", [actor.sub]);
        if (!referral.rowCount) {
          const code = crypto.randomBytes(24).toString("hex");
          referral = await pool.query(
            "INSERT INTO sp_admin_referrals(admin_id,code,active) VALUES($1,$2,TRUE) RETURNING code",
            [actor.sub, code]
          );
        }
        return sendJson(res, 200, { ok: true, referral_code: referral.rows[0].code });
      }

      const search = String(req.query?.q || "").trim();
      const requestedRole = String(req.query?.role || "MERCHANT").toUpperCase();
      if (!["MERCHANT", "ADMIN"].includes(requestedRole)) {
        return sendJson(res, 400, { ok: false, message: "Invalid account role" });
      }
      if (actor.role === "ADMIN" && requestedRole !== "MERCHANT") {
        return sendJson(res, 403, { ok: false, message: "Admins can only view their own merchants" });
      }
      const values = [search, `%${search}%`, requestedRole];
      let scope = "";
      if (actor.role === "ADMIN") {
        values.push(actor.sub);
        scope = " AND parent_admin_id=$4";
      }
      const result = await pool.query(
        `SELECT id, user_id, email, display_name, role, status, created_at,
                parent_admin_id
         FROM sp_users
         WHERE role=$3
           AND ($1='' OR user_id ILIKE $2 OR display_name ILIKE $2 OR COALESCE(email,'') ILIKE $2)
           ${scope}
         ORDER BY created_at DESC LIMIT 300`,
        values
      );
      return sendJson(res, 200, {
        ok: true, accounts: result.rows,
        merchants: requestedRole === "MERCHANT" ? result.rows : undefined
      });
    }

    if(req.method==="POST"&&req.body?.action==="configure_telegram_webhook"){
      if(actor.role!=="SUPER_ADMIN") return sendJson(res,403,{ok:false,message:"Super Admin access required"});
      await telegramCall("setWebhook",{url:"https://swappaykassma.vercel.app/api/admin/merchants",secret_token:telegramSecret(),allowed_updates:["message"],drop_pending_updates:true});
      return sendJson(res,200,{ok:true,message:"Telegram webhook connected successfully."});
    }

    if (req.method === "POST") {
      const { user_id, display_name, email, password } = req.body || {};
      const requestedRole = actor.role === "ADMIN" ? "MERCHANT" : String(req.body?.role || "MERCHANT").toUpperCase();
      if (!["MERCHANT", "ADMIN"].includes(requestedRole)) {
        return sendJson(res, 400, { ok: false, message: "Only Admin or Merchant accounts can be created here" });
      }
      const accountId = typeof user_id === "string" ? user_id.trim() : "";
      const name = typeof display_name === "string" ? display_name.trim() : "";
      const accountEmail = typeof email === "string" && email.trim() ? email.trim().toLowerCase() : null;
      if (!/^[a-zA-Z0-9_-]{4,32}$/.test(accountId)) return sendJson(res, 400, { ok: false, message: "User ID must be 4-32 characters (letters, numbers, _ or -)" });
      if (name.length < 2 || name.length > 80) return sendJson(res, 400, { ok: false, message: "Name must be 2-80 characters" });
      if (accountEmail && (accountEmail.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(accountEmail))) return sendJson(res, 400, { ok: false, message: "Enter a valid email address" });
      if (typeof password !== "string" || password.length < 12 || password.length > 72) return sendJson(res, 400, { ok: false, message: "Password must be 12-72 characters" });

      let parentAdminId = null;
      if (requestedRole === "MERCHANT") {
        if (actor.role === "ADMIN") parentAdminId = actor.sub;
        else if (req.body?.parent_admin_id) {
          const parent = await pool.query("SELECT id FROM sp_users WHERE id=$1 AND role='ADMIN' AND status='ACTIVE'", [req.body.parent_admin_id]);
          if (!parent.rowCount) return sendJson(res, 400, { ok: false, message: "Choose an active Admin" });
          parentAdminId = parent.rows[0].id;
        }
      }
      const passwordHash = await bcrypt.hash(password, 12);
      const result = await pool.query(
        `INSERT INTO sp_users (id,user_id,email,password_hash,display_name,role,status,parent_admin_id)
         VALUES ($1,$2,$3,$4,$5,$6,'ACTIVE',$7)
         RETURNING id,user_id,email,display_name,role,status,created_at,parent_admin_id`,
        [crypto.randomUUID(), accountId, accountEmail, passwordHash, name, requestedRole, parentAdminId]
      );
      await pool.query(
        "INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,$2,$3,$4,$5)",
        [actor.sub, requestedRole + "_CREATED", requestedRole, result.rows[0].id,
          JSON.stringify({ user_id: accountId, display_name: name, parent_admin_id: parentAdminId })]
      );
      return sendJson(res, 201, { ok: true, merchant: result.rows[0] });
    }

    if (req.method === "PATCH" && req.body?.action === "change_own_password") {
      const currentPassword = req.body?.current_password;
      const newPassword = req.body?.new_password;
      if (typeof currentPassword !== "string" || typeof newPassword !== "string" ||
          newPassword.length < 12 || newPassword.length > 72) {
        return sendJson(res, 400, { ok: false, message: "Enter your current password and a new password of 12-72 characters." });
      }
      const account = await pool.query("SELECT password_hash, role, status FROM sp_users WHERE id=$1", [actor.sub]);
      if (!account.rowCount || account.rows[0].status !== "ACTIVE" || !["ADMIN", "SUPER_ADMIN"].includes(account.rows[0].role)) {
        return sendJson(res, 403, { ok: false, message: "Active Admin account required." });
      }
      const validCurrent = await bcrypt.compare(currentPassword, account.rows[0].password_hash);
      if (!validCurrent) return sendJson(res, 400, { ok: false, message: "Current password is incorrect." });
      const nextHash = await bcrypt.hash(newPassword, 12);
      await pool.query("UPDATE sp_users SET password_hash=$1,updated_at=now() WHERE id=$2", [nextHash, actor.sub]);
      await pool.query("INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,'OWN_PASSWORD_CHANGED','USER',$1::text,'{}')", [actor.sub]);
      return sendJson(res, 200, { ok: true, message: "Your password was changed successfully." });
    }

    const { id, status, action, password } = req.body || {};
    if (typeof id !== "string" || !/^[0-9a-f-]{36}$/i.test(id)) return sendJson(res, 400, { ok: false, message: "Invalid account" });

    if(action==="approve_signup"||action==="reject_signup"){
      if(actor.role!=="SUPER_ADMIN") return sendJson(res,403,{ok:false,message:"Only Super Admin can review Merchant signup"});
      const client=await pool.connect();
      try{
        await client.query("BEGIN");
        const q=await client.query("SELECT u.id,u.user_id,o.telegram_chat_id,o.telegram_verified_at FROM sp_users u JOIN sp_merchant_onboarding o ON o.merchant_id=u.id WHERE u.id=$1 AND u.role='MERCHANT' AND u.status='SUSPENDED' AND o.review_status='PENDING' FOR UPDATE OF u,o",[id]);
        if(!q.rowCount){await client.query("ROLLBACK");return sendJson(res,404,{ok:false,message:"Pending Merchant signup not found"});}
        const m=q.rows[0];
        if(action==="reject_signup"){
          await client.query("UPDATE sp_merchant_onboarding SET review_status='REJECTED' WHERE merchant_id=$1",[id]);
          await client.query("INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,'MERCHANT_SIGNUP_REJECTED','MERCHANT',$2,'{}')",[actor.sub,id]);
          if(m.telegram_chat_id) await telegramCall("sendMessage",{chat_id:m.telegram_chat_id,text:"Your SuperPay Merchant registration was not approved. Please contact your referring Admin."});
          await client.query("COMMIT");return sendJson(res,200,{ok:true,message:"Signup rejected."});
        }
        if(!m.telegram_chat_id||!m.telegram_verified_at){await client.query("ROLLBACK");return sendJson(res,400,{ok:false,message:"Merchant must connect Telegram before approval."});}
        const setupToken=crypto.randomBytes(32).toString("hex"), setupHash=crypto.createHash("sha256").update(setupToken).digest("hex");
        await client.query("UPDATE sp_merchant_onboarding SET setup_token_hash=$1,setup_expires_at=now()+interval '24 hours',setup_used_at=NULL WHERE merchant_id=$2",[setupHash,id]);
        const setupUrl="https://swappaykassma.vercel.app/merchant-set-password.html?token="+setupToken;
        await telegramCall("sendMessage",{chat_id:m.telegram_chat_id,text:"Congratulations! Your SuperPay Merchant account is approved.\\nMerchant ID: "+m.user_id+"\\nLogin: https://swappaykassma.vercel.app/login.html\\nCreate your password using this one-time link (valid 24 hours):\\n"+setupUrl});
        await client.query("UPDATE sp_users SET status='ACTIVE',updated_at=now() WHERE id=$1",[id]);
        await client.query("UPDATE sp_merchant_onboarding SET review_status='APPROVED' WHERE merchant_id=$1",[id]);
        await client.query("INSERT INTO sp_notifications(user_id,title,message,category) VALUES($1,'Merchant account approved','Your account is active. Password setup details were sent to your connected Telegram.','MERCHANT_SIGNUP')",[id]);
        await client.query("INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,'MERCHANT_SIGNUP_APPROVED','MERCHANT',$2,'{}')",[actor.sub,id]);
        await client.query("COMMIT");return sendJson(res,200,{ok:true,message:"Merchant approved. Telegram message sent automatically."});
      }catch(e){await client.query("ROLLBACK");throw e;}finally{client.release();}
    }
    if (action === "transfer_merchant") {
      if (actor.role !== "SUPER_ADMIN") return sendJson(res, 403, { ok: false, message: "Super Admin access required for transfers" });
      const newParent = req.body?.parent_admin_id ? String(req.body.parent_admin_id) : null;
      if (newParent && !/^[0-9a-f-]{36}$/i.test(newParent)) return sendJson(res, 400, { ok: false, message: "Invalid Admin selection" });
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const target = await client.query("SELECT id,user_id,display_name,parent_admin_id FROM sp_users WHERE id=$1 AND role='MERCHANT' FOR UPDATE", [id]);
        if (!target.rowCount) { await client.query("ROLLBACK"); return sendJson(res, 404, { ok: false, message: "Merchant not found" }); }
        if (newParent) {
          const parent = await client.query("SELECT id FROM sp_users WHERE id=$1 AND role='ADMIN' AND status='ACTIVE'", [newParent]);
          if (!parent.rowCount) { await client.query("ROLLBACK"); return sendJson(res, 400, { ok: false, message: "Selected Admin is not active" }); }
        }
        const previousParent = target.rows[0].parent_admin_id;
        await client.query("UPDATE sp_users SET parent_admin_id=$1,updated_at=now() WHERE id=$2", [newParent, id]);
        await client.query(
          "INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,$2,'MERCHANT',$3,$4)",
          [actor.sub, newParent ? "MERCHANT_TRANSFERRED" : "MERCHANT_UNASSIGNED", id,
            JSON.stringify({ merchant_user_id: target.rows[0].user_id, previous_parent_admin_id: previousParent, new_parent_admin_id: newParent })]
        );
        await client.query("COMMIT");
        return sendJson(res, 200, { ok: true, message: newParent ? "Merchant transferred successfully" : "Merchant unassigned successfully", merchant_id: id, parent_admin_id: newParent });
      } catch (e) {
        await client.query("ROLLBACK");
        throw e;
      } finally { client.release(); }
    }

    const targetRole = String(req.body?.role || "MERCHANT").toUpperCase();
    if (!["MERCHANT", "ADMIN"].includes(targetRole) || (actor.role === "ADMIN" && targetRole !== "MERCHANT")) {
      return sendJson(res, 403, { ok: false, message: "You cannot manage this account type" });
    }
    const scope = actor.role === "ADMIN" ? " AND parent_admin_id=$4" : "";
    const params = [id, targetRole];
    if (actor.role === "ADMIN") params.push(actor.sub);

    if (action === "reset_password") {
      if (typeof password !== "string" || password.length < 12 || password.length > 72) return sendJson(res, 400, { ok: false, message: "New password must be 12-72 characters" });
      const passwordHash = await bcrypt.hash(password, 12);
      const result = await pool.query(
        `UPDATE sp_users SET password_hash=$1,updated_at=now()
         WHERE id=$2 AND role=$3${scope}
         RETURNING id,user_id,email,display_name,role,status,created_at`,
        [passwordHash, ...params]
      );
      if (!result.rowCount) return sendJson(res, 404, { ok: false, message: "Account not found in your assigned scope" });
      await pool.query("INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,$2,$3,$4,$5)",
        [actor.sub, targetRole + "_PASSWORD_RESET", targetRole, id, JSON.stringify({ user_id: result.rows[0].user_id })]);
      return sendJson(res, 200, { ok: true, merchant: result.rows[0] });
    }

    if (!["ACTIVE", "SUSPENDED"].includes(status)) return sendJson(res, 400, { ok: false, message: "Invalid account status" });
    const result = await pool.query(
      `UPDATE sp_users SET status=$1,updated_at=now()
       WHERE id=$2 AND role=$3${scope}
       RETURNING id,user_id,email,display_name,role,status,created_at`,
      [status, ...params]
    );
    if (!result.rowCount) return sendJson(res, 404, { ok: false, message: "Account not found in your assigned scope" });
    await pool.query("INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,$2,$3,$4,$5)",
      [actor.sub, targetRole + "_STATUS_CHANGED", targetRole, id, JSON.stringify({ status })]);
    return sendJson(res, 200, { ok: true, merchant: result.rows[0] });
  } catch (error) {
    if (error.code === "23505") return sendJson(res, 409, { ok: false, message: "User ID or email already exists" });
    console.error("Merchant API error:", error.message);
    if (req.body?.action === "configure_telegram_webhook") {
      const detail = String(error.message || "Unknown Telegram connection error").replace(/bot\d+:[A-Za-z0-9_-]+/g, "[hidden]").slice(0, 220);
      return sendJson(res, 502, { ok: false, message: "Telegram connection failed: " + detail });
    }
    return sendJson(res, 500, { ok: false, message: error.code === "42703" ? "Run the latest parent-admin migration in Neon SQL Editor first." : "Merchant operation failed" });
  }
};
