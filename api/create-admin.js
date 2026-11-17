const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { getPool } = require("./_lib/db");
const { sendJson, allowMethods } = require("./_lib/http");

module.exports = async (req, res) => {
  if (!allowMethods(req, res, ["POST"])) return;

  const bootstrapSecret = process.env.ADMIN_BOOTSTRAP_SECRET;
  const suppliedSecret = req.headers["x-bootstrap-secret"];

  if (
    !bootstrapSecret ||
    bootstrapSecret.length < 32 ||
    typeof suppliedSecret !== "string"
  ) {
    return sendJson(res, 401, {
      ok: false,
      message: "Unauthorized"
    });
  }

  const expected = Buffer.from(bootstrapSecret);
  const supplied = Buffer.from(suppliedSecret);

  if (
    expected.length !== supplied.length ||
    !crypto.timingSafeEqual(expected, supplied)
  ) {
    return sendJson(res, 401, {
      ok: false,
      message: "Unauthorized"
    });
  }

  const { password } = req.body || {};

  if (
    typeof password !== "string" ||
    password.length < 12 ||
    password.length > 72
  ) {
    return sendJson(res, 400, {
      ok: false,
      message: "Password must be 12 to 72 characters"
    });
  }

  const pool = getPool();
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    await client.query(
      "SELECT pg_advisory_xact_lock(5762026)"
    );

    const existing = await client.query(
      "SELECT COUNT(*)::int AS total FROM sp_users"
    );

    if (existing.rows[0].total !== 0) {
      await client.query("ROLLBACK");

      return sendJson(res, 409, {
        ok: false,
        message: "Admin setup is already closed"
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await client.query(
      `INSERT INTO sp_users (
        id,
        user_id,
        email,
        password_hash,
        display_name,
        role,
        status,
        created_at,
        updated_at
      )
      VALUES ($1, $2, NULL, $3, $4, $5, $6, NOW(), NOW())
      RETURNING id, user_id, display_name, role, status`,
      [
        crypto.randomUUID(),
        "sanjanaraj576",
        passwordHash,
        "Super Admin",
        "SUPER_ADMIN",
        "ACTIVE"
      ]
    );

    await client.query("COMMIT");

    return sendJson(res, 201, {
      ok: true,
      message: "First Super Admin created successfully",
      user: result.rows[0]
    });

  } catch (error) {
    await client.query("ROLLBACK");

    console.error("Admin creation error:", error.message);

    return sendJson(res, 500, {
      ok: false,
      message: "Admin creation failed"
    });

  } finally {
    client.release();
  }
};
