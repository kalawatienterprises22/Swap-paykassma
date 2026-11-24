const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { getPool } = require("./db");

function createToken(user) {
  const secret = process.env.JWT_SECRET;

  if (!secret) {
    throw new Error("JWT_SECRET is not configured");
  }

  return jwt.sign(
    {
      sub: user.id,
      role: user.role,
      userId: user.user_id,
      // A one-way password fingerprint makes existing Admin JWTs revocable.
      ...(["ADMIN", "SUPER_ADMIN"].includes(user.role) && user.password_hash
        ? { pwdv: crypto.createHash("sha256").update(user.password_hash).digest("hex") }
        : {})
    },
    secret,
    {
      expiresIn: "8h",
      issuer: "superpay"
    }
  );
}

function verifyToken(token) {
  const secret = process.env.JWT_SECRET;

  if (!secret) {
    throw new Error("JWT_SECRET is not configured");
  }

  return jwt.verify(token, secret, {
    issuer: "superpay"
  });
}

async function verifyAdminToken(token) {
  const user = verifyToken(token);
  if (!["ADMIN", "SUPER_ADMIN"].includes(user.role)) return user;

  // Tokens issued before password fingerprinting are deliberately rejected.
  if (typeof user.pwdv !== "string" || !/^[a-f0-9]{64}$/i.test(user.pwdv)) {
    throw new Error("Admin session has been revoked");
  }

  const result = await getPool().query(
    "SELECT password_hash, role, status FROM sp_users WHERE id=$1 LIMIT 1",
    [user.sub]
  );
  if (!result.rowCount || result.rows[0].status !== "ACTIVE" ||
      result.rows[0].role !== user.role || !result.rows[0].password_hash) {
    throw new Error("Admin account is inactive");
  }

  const current = crypto.createHash("sha256").update(result.rows[0].password_hash).digest();
  const supplied = Buffer.from(user.pwdv, "hex");
  if (supplied.length !== current.length || !crypto.timingSafeEqual(supplied, current)) {
    throw new Error("Admin password changed; session revoked");
  }
  return user;
}

module.exports = {
  createToken,
  verifyToken,
  verifyAdminToken
};
