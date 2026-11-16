const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 1,
});

module.exports = async function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({
      ok: false,
      message: "Method not allowed"
    });
  }

  if (!process.env.DATABASE_URL) {
    return res.status(500).json({
      ok: false,
      message: "DATABASE_URL is not configured"
    });
  }

  try {
    const result = await pool.query(
      "SELECT current_database() AS database, NOW() AS server_time"
    );

    return res.status(200).json({
      ok: true,
      message: "Neon database connected",
      database: result.rows[0].database,
      serverTime: result.rows[0].server_time
    });
  } catch (error) {
    console.error("Database connection failed:", error.message);
    return res.status(500).json({
      ok: false,
      message: "Database connection failed"
    });
  }
};
