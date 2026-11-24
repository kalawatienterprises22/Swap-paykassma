const { getPool } = require("../_lib/db");
const { sendJson, allowMethods } = require("../_lib/http");

module.exports = async (req, res) => {
  if (!allowMethods(req, res, ["GET"])) return;

  const staffUserId = String(req.query?.userId || "").trim();
  if (!staffUserId || staffUserId.length > 120) {
    return sendJson(res, 400, {
      ok: false,
      verified: false,
      message: "A valid Staff User ID is required"
    });
  }

  try {
    const result = await getPool().query(
      "SELECT belongs_to FROM sp_staff_verifications WHERE staff_user_id=$1 AND status='ACTIVE' LIMIT 1",
      [staffUserId]
    );

    if (!result.rowCount) {
      return sendJson(res, 404, {
        ok: true,
        verified: false,
        message: "Staff not verified"
      });
    }

    return sendJson(res, 200, {
      ok: true,
      verified: true,
      message: "Staff Verified",
      belongsTo: result.rows[0].belongs_to
    });
  } catch (error) {
    console.error("Staff check error:", error.message);
    return sendJson(res, 500, {
      ok: false,
      verified: false,
      message: "Verification unavailable"
    });
  }
};
