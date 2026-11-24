
const bcrypt = require("bcryptjs");
const { getPool } = require("./_lib/db");
const { sendJson, allowMethods } = require("./_lib/http");
const { createToken } = require("./_lib/auth");

module.exports = async (req, res) => {
  if (!allowMethods(req, res, ["POST"])) return;

  try {
    const { user_id, password, login_type, display_name } = req.body || {};
    // Gaming/ParixBet authentication belongs to its own deployment, never Paykassma.
    if (process.env.PAYKASSMA_ONLY === "1" && ["gaming_admin", "gaming_register", "gaming"].includes(login_type)) {
      return sendJson(res, 404, { ok: false, message: "Gaming login is not available on the Paykassma platform." });
    }

    if (
      !["standard", "super_admin"].includes(login_type) ||
      typeof user_id !== "string" ||
      typeof password !== "string" ||
      !user_id.trim() ||
      !password
    ) {
      return sendJson(res, 400, {
        ok: false,
        message: "User ID and password are required"
      });
    }

    const result = await getPool().query(
      `SELECT id, user_id, display_name, password_hash, role, status
       FROM sp_users
       WHERE LOWER(user_id) = LOWER($1)
       LIMIT 1`,
      [user_id.trim()]
    );

    if (!result.rows.length) {
      return sendJson(res, 401, {
        ok: false,
        message: "Invalid User ID or password"
      });
    }

    const user = result.rows[0];

    if (user.status !== "ACTIVE") {
      return sendJson(res, 403, {
        ok: false,
        message: "Account is inactive"
      });
    }

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return sendJson(res, 401, {
        ok: false,
        message: "Invalid User ID or password"
      });
    }

    if (login_type === "super_admin" && user.role !== "SUPER_ADMIN") {
      return sendJson(res, 403, { ok: false, message: "This account is not a Super Admin account. Use the normal login." });
    }
    if (login_type === "standard" && user.role === "SUPER_ADMIN") {
      return sendJson(res, 403, { ok: false, message: "Super Admin must use the separate Super Admin Login." });
    }

    const token = createToken(user);

    return sendJson(res, 200, {
      ok: true,
      message: "Login successful",
      token,
      user: {
        id: user.id,
        user_id: user.user_id,
        display_name: user.display_name,
        role: user.role
      }
    });

  } catch (error) {
    console.error("Login error:", error.message);

    return sendJson(res, 500, {
      ok: false,
      message: "Login service unavailable"
    });
  }
};
