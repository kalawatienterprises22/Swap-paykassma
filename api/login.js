const bcrypt = require("bcryptjs");
const { getPool } = require("./_lib/db");
const { sendJson, allowMethods } = require("./_lib/http");
const { createToken } = require("./_lib/auth");

module.exports = async (req, res) => {
  if (!allowMethods(req, res, ["POST"])) return;

  try {
    const { user_id, password } = req.body || {};

    if (!user_id || !password) {
      return sendJson(res, 400, {
        ok: false,
        message: "User ID and password are required"
      });
    }

    const result = await getPool().query(
      `SELECT id, user_id, password_hash, role, is_active
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

    if (!user.is_active) {
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

    const token = createToken(user);

    return sendJson(res, 200, {
      ok: true,
      message: "Login successful",
      token,
      user: {
        id: user.id,
        user_id: user.user_id,
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
