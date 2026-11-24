const { getPool } = require("./_lib/db");
const { sendJson, allowMethods } = require("./_lib/http");
const { verifyToken } = require("./_lib/auth");

const ALLOWED_PACKAGES = new Set([
  "com.google.android.apps.nbu.paisa.user",
  "com.phonepe.app",
  "com.bharatpe.app",
  "com.paytm.business"
]);

module.exports = async (req, res) => {
  if (!allowMethods(req, res, ["GET", "POST"])) return;
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return sendJson(res, 401, { ok: false, message: "Authentication required" });

  let actor;
  try {
    actor = verifyToken(token);
  } catch {
    return sendJson(res, 401, { ok: false, message: "Invalid or expired session" });
  }
  if (!["MERCHANT", "ADMIN", "SUPER_ADMIN"].includes(actor.role)) {
    return sendJson(res, 403, { ok: false, message: "Access denied" });
  }

  const body = req.body || {};
  const pool = getPool();

  if (req.method === "GET" && String(req.query?.devices || "") === "1") {
    if (actor.role === "MERCHANT") return sendJson(res,403,{ok:false,message:"Admin device monitoring access required"});
    const scope = actor.role === "ADMIN" ? "AND u.parent_admin_id=$1" : "";
    const values = actor.role === "ADMIN" ? [actor.sub] : [];
    try {
      const result = await pool.query(
        `SELECT u.id AS merchant_id,u.user_id,u.display_name,
                d.device_id,d.device_model,d.app_version,d.source_package,
                d.last_seen_at,d.last_ip,
                (d.last_seen_at >= now() - interval '3 minutes') AS online
         FROM sp_users u
         LEFT JOIN sp_merchant_devices d ON d.merchant_id=u.id
         WHERE u.role='MERCHANT' ${scope}
         ORDER BY u.display_name NULLS LAST,u.user_id`,
        values
      );
      return sendJson(res,200,{ok:true,devices:result.rows,online_count:result.rows.filter(x=>x.online).length});
    } catch (error) {
      console.error("Merchant device status read error:",error.message);
      return sendJson(res,500,{ok:false,message:"Unable to load merchant device status. Run the merchant-device-presence.sql migration first."});
    }
  }


  if (req.method === "GET" && String(req.query?.review_sms || "") === "1") {
    if (actor.role === "MERCHANT") return sendJson(res,403,{ok:false,message:"Admin SMS review access required"});
    const scope = actor.role === "ADMIN" ? "WHERE u.parent_admin_id=$1" : "";
    const values = actor.role === "ADMIN" ? [actor.sub] : [];
    try {
      const result = await pool.query(
        `SELECT s.id,s.merchant_id,u.user_id,u.display_name,s.sender,s.message_text,s.received_at,s.status
         FROM sp_payment_sms s JOIN sp_users u ON u.id=s.merchant_id
         ${scope} ORDER BY s.received_at DESC LIMIT 500`, values
      );
      return sendJson(res,200,{ok:true,messages:result.rows});
    } catch(error) {
      console.error("Payment SMS review read error:",error.message);
      return sendJson(res,500,{ok:false,message:"Unable to load payment SMS. Apply payment-sms-monitoring.sql first."});
    }
  }

  if (req.method === "GET" && String(req.query?.review || "") === "1") {
    if (actor.role === "MERCHANT") return sendJson(res,403,{ok:false,message:"Admin review access required"});
    const scope = actor.role === "ADMIN" ? "WHERE u.parent_admin_id=$1" : "";
    const values = actor.role === "ADMIN" ? [actor.sub] : [];
    const result = await pool.query(
      `SELECT n.id,n.merchant_id,u.user_id,u.display_name,n.source_package,
              n.notification_title,n.notification_text,n.posted_at,n.received_at,
              n.status,n.review_note,n.reviewed_at
       FROM sp_payment_notifications n
       JOIN sp_users u ON u.id=n.merchant_id
       ${scope}
       ORDER BY n.received_at DESC LIMIT 300`,
      values
    );
    return sendJson(res,200,{ok:true,notifications:result.rows});
  }

  let targetMerchantId = actor.sub;
  if (actor.role === "SUPER_ADMIN" || actor.role === "ADMIN") {
    targetMerchantId = String(req.method === "GET" ? req.query?.merchant_id || "" : body.merchant_id || "");
    if (!/^[0-9a-f-]{36}$/i.test(targetMerchantId)) {
      return sendJson(res, 400, { ok: false, message: "Select a valid merchant first" });
    }
    const target = await pool.query("SELECT id FROM sp_users WHERE id=$1 AND role='MERCHANT' AND ($2='SUPER_ADMIN' OR parent_admin_id=$3)", [targetMerchantId, actor.role, actor.sub]);
    if (!target.rows.length) return sendJson(res, 404, { ok: false, message: "Merchant not found" });
  }

  if (req.method === "GET") {
    try {
      const current = await pool.query(
        "SELECT source_package, enabled, updated_at FROM sp_merchant_notification_sources WHERE merchant_id=$1",
        [targetMerchantId]
      );
      return sendJson(res, 200, { ok: true, source: current.rows[0] || null });
    } catch (error) {
      console.error("Notification source read error:", error.message);
      return sendJson(res, 500, { ok: false, message: "Unable to read notification source settings" });
    }
  }

  if (req.method === "POST" && body.action === "heartbeat") {
    if (actor.role !== "MERCHANT") return sendJson(res,403,{ok:false,message:"Only merchant APK sessions can send device heartbeat"});
    const deviceId=String(body.device_id||"").slice(0,80);
    const deviceModel=String(body.device_model||"").slice(0,120);
    const appVersion=String(body.app_version||"").slice(0,40);
    if (!/^[a-zA-Z0-9._:-]{8,80}$/.test(deviceId)) return sendJson(res,400,{ok:false,message:"Invalid device identifier"});
    const forwarded=String(req.headers["x-forwarded-for"]||"").split(",")[0].trim();
    const ip=forwarded || String(req.socket?.remoteAddress||"").slice(0,64) || null;
    try {
      const selected=await pool.query(
        "SELECT source_package FROM sp_merchant_notification_sources WHERE merchant_id=$1 AND enabled=TRUE",
        [actor.sub]
      );
      await pool.query(
        `INSERT INTO sp_merchant_devices
          (merchant_id,device_id,device_model,app_version,source_package,last_seen_at,last_ip,updated_at)
         VALUES($1,$2,$3,$4,$5,now(),$6,now())
         ON CONFLICT(merchant_id) DO UPDATE SET
           device_id=EXCLUDED.device_id,device_model=EXCLUDED.device_model,
           app_version=EXCLUDED.app_version,source_package=EXCLUDED.source_package,
           last_seen_at=now(),last_ip=EXCLUDED.last_ip,updated_at=now()`,
        [actor.sub,deviceId,deviceModel,appVersion,selected.rows[0]?.source_package||null,ip]
      );
      return sendJson(res,200,{ok:true,online:true,last_seen_at:new Date().toISOString()});
    } catch(error) {
      console.error("Merchant device heartbeat error:",error.message);
      return sendJson(res,500,{ok:false,message:"Unable to update merchant device status"});
    }
  }

  if (req.method === "POST" && body.action === "payment_sms") {
    if (actor.role !== "MERCHANT") return sendJson(res,403,{ok:false,message:"Only merchant devices can submit payment SMS"});
    const sender=String(body.sender||"").slice(0,100);
    const messageText=String(body.message_text||"").replace(/\s+/g," ").trim().slice(0,2000);
    const receivedAt=Number(body.received_at);
    const messageHash=String(body.message_hash||"");
    const paymentSignal=/(credited|received|deposited|debited|paid|payment|transfer|transaction|upi|deposit|withdrawal|refund|INR|Rs\.?|₹)/i;
    const sensitiveSignal=/(\bOTP\b|one.time.password|password|\bPIN\b|verification code|login code|CVV|card number)/i;
    if (!sender || messageText.length<8 || !Number.isFinite(receivedAt) || receivedAt<1 ||
        !/^[a-f0-9]{64}$/i.test(messageHash) || !paymentSignal.test(messageText) || sensitiveSignal.test(messageText)) {
      return sendJson(res,200,{ok:true,ignored:true,message:"SMS did not match the payment-only safety filter"});
    }
    try {
      const result=await pool.query(
        `INSERT INTO sp_payment_sms(merchant_id,sender,message_text,message_hash,received_at)
         VALUES($1,$2,$3,$4,to_timestamp($5/1000.0))
         ON CONFLICT(merchant_id,message_hash) DO NOTHING RETURNING id,status`,
        [actor.sub,sender,messageText,messageHash.toLowerCase(),receivedAt]
      );
      return sendJson(res,200,{ok:true,duplicate:!result.rows.length,received:!!result.rows.length});
    } catch(error) {
      console.error("Payment SMS ingestion error:",error.message);
      return sendJson(res,500,{ok:false,message:"Unable to save payment SMS"});
    }
  }

  // A merchant may enable exactly one payment app at a time.
  if (body.action === "configure_source") {
    const sourcePackage = String(body.source_package || "");
    if (!ALLOWED_PACKAGES.has(sourcePackage)) {
      return sendJson(res, 400, { ok: false, message: "Choose one supported payment app" });
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `INSERT INTO sp_merchant_notification_sources
          (merchant_id, source_package, enabled, updated_by, updated_at)
         VALUES ($1,$2,TRUE,$3,now())
         ON CONFLICT (merchant_id) DO UPDATE
         SET source_package=EXCLUDED.source_package, enabled=TRUE,
             updated_by=EXCLUDED.updated_by, updated_at=now()`,
        [targetMerchantId, sourcePackage, actor.sub]
      );
      await client.query(
        `INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details)
         VALUES($1,'NOTIFICATION_SOURCE_CHANGED','MERCHANT',$2,$3)`,
        [actor.sub, targetMerchantId, JSON.stringify({ merchant_id: targetMerchantId, source_package: sourcePackage })]
      );
      await client.query("COMMIT");
      return sendJson(res, 200, { ok: true, source_package: sourcePackage, enabled: true });
    } catch (error) {
      await client.query("ROLLBACK");
      console.error("Notification source configuration error:", error.message);
      return sendJson(res, 500, { ok: false, message: "Unable to save notification source. Run the notification-source-settings.sql migration first." });
    } finally {
      client.release();
    }
  }

  if (actor.role !== "MERCHANT") return sendJson(res, 403, { ok: false, message: "Only merchant devices can submit payment notifications" });

  const sourcePackage = String(body.source_package || "");
  const notificationKey = String(body.notification_key || "");
  const title = String(body.title || "").slice(0, 300);
  const notificationText = String(body.notification_text || "").trim().slice(0, 5000);
  const postedAt = Number(body.posted_at);

  if (!ALLOWED_PACKAGES.has(sourcePackage)) {
    return sendJson(res, 400, { ok: false, message: "Unsupported payment app" });
  }
  if (!/^[a-f0-9]{64}$/i.test(notificationKey) || notificationText.length < 2) {
    return sendJson(res, 400, { ok: false, message: "Invalid notification details" });
  }
  if (!Number.isFinite(postedAt) || postedAt < 1) {
    return sendJson(res, 400, { ok: false, message: "Invalid notification time" });
  }

  try {
    const configured = await pool.query(
      `SELECT source_package FROM sp_merchant_notification_sources
       WHERE merchant_id=$1 AND enabled=TRUE`,
      [targetMerchantId]
    );
    if (!configured.rows.length) {
      return sendJson(res, 403, { ok: false, message: "Select and enable one payment app in Paykassma before sending notifications" });
    }
    if (configured.rows[0].source_package !== sourcePackage) {
      return sendJson(res, 403, { ok: false, message: "This app is not enabled for this merchant. Only the selected payment app is accepted." });
    }

    const result = await pool.query(
      `INSERT INTO sp_payment_notifications
        (merchant_id, source_package, notification_key, notification_title, notification_text, posted_at)
       VALUES ($1,$2,$3,$4,$5,to_timestamp($6 / 1000.0))
       ON CONFLICT (merchant_id, notification_key) DO NOTHING
       RETURNING id, status, received_at`,
      [targetMerchantId, sourcePackage, notificationKey.toLowerCase(), title, notificationText, postedAt]
    );
    if (!result.rows.length) {
      return sendJson(res, 200, { ok: true, duplicate: true, message: "Notification already received" });
    }
    return sendJson(res, 201, {
      ok: true,
      duplicate: false,
      status: result.rows[0].status,
      received_at: result.rows[0].received_at
    });
  } catch (error) {
    console.error("Device event ingestion error:", error.message);
    return sendJson(res, 500, { ok: false, message: "Unable to save notification" });
  }
};
