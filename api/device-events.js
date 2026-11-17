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
  if (!allowMethods(req, res, ["POST"])) return;
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return sendJson(res, 401, { ok: false, message: "Authentication required" });

  let actor;
  try {
    actor = verifyToken(token);
  } catch {
    return sendJson(res, 401, { ok: false, message: "Invalid or expired session" });
  }
  if (actor.role !== "MERCHANT") {
    return sendJson(res, 403, { ok: false, message: "Merchant account required" });
  }

  const body = req.body || {};
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
    const result = await getPool().query(
      `INSERT INTO sp_payment_notifications
        (merchant_id, source_package, notification_key, notification_title, notification_text, posted_at)
       VALUES ($1,$2,$3,$4,$5,to_timestamp($6 / 1000.0))
       ON CONFLICT (merchant_id, notification_key) DO NOTHING
       RETURNING id, status, received_at`,
      [actor.sub, sourcePackage, notificationKey.toLowerCase(), title, notificationText, postedAt]
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
