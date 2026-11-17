const jwt = require("jsonwebtoken");

function createToken(user) {
  const secret = process.env.JWT_SECRET;

  if (!secret) {
    throw new Error("JWT_SECRET is not configured");
  }

  return jwt.sign(
    {
      sub: user.id,
      role: user.role,
      userId: user.user_id
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

module.exports = {
  createToken,
  verifyToken
};
