const { getPool } = require("./_lib/db");
const { sendJson, allowMethods } = require("./_lib/http");
const { verifyToken } = require("./_lib/auth");
const bcrypt = require("bcryptjs");

async function ensureGamingTables(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sp_game_players (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(40) NOT NULL UNIQUE,
      display_name VARCHAR(100) NOT NULL,
      password_hash TEXT NOT NULL,
      status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','SUSPENDED')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS sp_game_wallets (
      player_id BIGINT PRIMARY KEY REFERENCES sp_game_players(id) ON DELETE CASCADE,
      virtual_coins BIGINT NOT NULL DEFAULT 1000 CHECK (virtual_coins >= 0),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS sp_game_sessions (
      id BIGSERIAL PRIMARY KEY,
      player_id BIGINT NOT NULL REFERENCES sp_game_players(id) ON DELETE CASCADE,
      game_code VARCHAR(40) NOT NULL,
      result JSONB NOT NULL DEFAULT '{}'::jsonb,
      coins_change BIGINT NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS sp_game_coin_ledger (
      id BIGSERIAL PRIMARY KEY,
      player_id BIGINT NOT NULL REFERENCES sp_game_players(id) ON DELETE CASCADE,
      amount BIGINT NOT NULL,
      entry_type VARCHAR(24) NOT NULL,
      note VARCHAR(240),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS sp_game_ad_revenue (
      id BIGSERIAL PRIMARY KEY,
      network VARCHAR(80) NOT NULL,
      amount NUMERIC(12,2) NOT NULL CHECK (amount >= 0),
      currency CHAR(3) NOT NULL DEFAULT 'INR',
      report_period DATE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS sp_game_giveaways (
      id BIGSERIAL PRIMARY KEY,
      title VARCHAR(160) NOT NULL,
      details TEXT,
      status VARCHAR(20) NOT NULL DEFAULT 'DRAFT',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS sp_game_cricket_cache (
      cache_key VARCHAR(40) PRIMARY KEY,
      payload JSONB NOT NULL,
      fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

function getGamingAdmin(req, res) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) {
    sendJson(res, 401, { ok: false, message: "ParixBet Admin login required" });
    return null;
  }
  try {
    const user = verifyToken(token);
    if (user.role !== "GAMING_ADMIN") {
      sendJson(res, 403, { ok: false, message: "ParixBet Admin access denied" });
      return null;
    }
    return user;
  } catch {
    sendJson(res, 401, { ok: false, message: "Invalid or expired ParixBet Admin session" });
    return null;
  }
}

function getAdmin(req, res) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) {
    sendJson(res, 401, { ok: false, message: "Authentication required" });
    return null;
  }
  try {
    const user = verifyToken(token);
    if (user.role !== "SUPER_ADMIN") {
      sendJson(res, 403, { ok: false, message: "Access denied" });
      return null;
    }
    return user;
  } catch {
    sendJson(res, 401, { ok: false, message: "Invalid or expired session" });
    return null;
  }
}

module.exports = async (req, res) => {
  const isPlayer = req.query && req.query.module === "gaming-player";
  if (isPlayer) {
    if (!allowMethods(req, res, ["GET"])) return;
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    let player;
    try { player = token ? verifyToken(token) : null; } catch {}
    if (!player || player.role !== "GAMING_PLAYER" || !player.sub) {
      return sendJson(res, 401, { ok: false, message: "Gaming player login required" });
    }
    try {
      const pool = getPool();
      await ensureGamingTables(pool);
      const profile = await pool.query(
        `SELECT p.id,p.username,p.display_name,p.status,
                COALESCE(w.virtual_coins,0)::bigint AS virtual_coins
         FROM sp_game_players p LEFT JOIN sp_game_wallets w ON w.player_id=p.id
         WHERE p.id=$1 LIMIT 1`, [player.sub]
      );
      if (!profile.rows.length || profile.rows[0].status !== "ACTIVE") {
        return sendJson(res, 403, { ok: false, message: "Gaming account is unavailable" });
      }
      const history = await pool.query(
        "SELECT id,game_code,result,coins_change,created_at FROM sp_game_sessions WHERE player_id=$1 ORDER BY created_at DESC LIMIT 30",
        [player.sub]
      );
      return sendJson(res, 200, { ok: true, player: profile.rows[0], history: history.rows });
    } catch (error) {
      console.error("Gaming player API error:", error.message);
      return sendJson(res, 500, { ok: false, message: "Gaming profile unavailable" });
    }
  }

  const isGaming = req.query && req.query.module === "gaming";
  if (isGaming) {
    if (!["GET", "POST", "PATCH"].includes(req.method)) {
      return sendJson(res, 405, { ok: false, message: "Method not allowed" });
    }
    if (!getGamingAdmin(req, res)) return;
    try {
      const pool = getPool();
      await ensureGamingTables(pool);
      if (req.method === "GET") {
        const action = req.query.action || "stats";
        if (action === "stats") {
          const [players, games, coins] = await Promise.all([
            pool.query("SELECT COUNT(*)::int AS total FROM sp_game_players"),
            pool.query("SELECT COUNT(*)::int AS total FROM sp_game_sessions"),
            pool.query("SELECT COALESCE(SUM(virtual_coins),0)::bigint AS total FROM sp_game_wallets")
          ]);
          return sendJson(res, 200, { ok: true, stats: {
            players: players.rows[0].total,
            games: games.rows[0].total,
            coins: String(coins.rows[0].total),
            live_matches: null
          }});
        }
        if (action === "players") {
          const result = await pool.query(`
            SELECT p.id,p.username,p.display_name,p.status,p.created_at,
                   COALESCE(w.virtual_coins,0)::bigint AS virtual_coins
            FROM sp_game_players p LEFT JOIN sp_game_wallets w ON w.player_id=p.id
            ORDER BY p.created_at DESC LIMIT 100
          `);
          return sendJson(res, 200, { ok: true, players: result.rows });
        }
        if (action === "cricket") {
          const cached = await pool.query("SELECT payload,fetched_at FROM sp_game_cricket_cache WHERE cache_key='livescores' LIMIT 1");
          const age = cached.rows[0] ? Date.now() - new Date(cached.rows[0].fetched_at).getTime() : Infinity;
          if (age < 30000) return sendJson(res,200,{ok:true,source:"Sportmonks Cricket API",cached:true,matches:cached.rows[0].payload});
          const apiKey = process.env.SPORTMONKS_CRICKET_TOKEN;
          if (!apiKey) return sendJson(res,200,{ok:false,connected:false,message:"SPORTMONKS_CRICKET_TOKEN is not configured"});
          const url = "https://cricket.sportmonks.com/api/v2.0/livescores?api_token="+encodeURIComponent(apiKey)+"&include=localteam,visitorteam,scoreboards";
          const response = await fetch(url,{headers:{Accept:"application/json"}});
          if(!response.ok) throw new Error("Cricket provider returned HTTP "+response.status);
          const payload = await response.json();
          const matches = Array.isArray(payload.data) ? payload.data : [];
          await pool.query(
            "INSERT INTO sp_game_cricket_cache(cache_key,payload,fetched_at) VALUES('livescores',$1::jsonb,NOW()) ON CONFLICT(cache_key) DO UPDATE SET payload=EXCLUDED.payload,fetched_at=NOW()",
            [JSON.stringify(matches)]
          );
          return sendJson(res,200,{ok:true,source:"Sportmonks Cricket API",cached:false,matches});
        }
        if (action === "records") {
          const result = await pool.query(`
            SELECT s.id,p.username,p.display_name,s.game_code,s.result,s.coins_change,s.created_at
            FROM sp_game_sessions s JOIN sp_game_players p ON p.id=s.player_id
            ORDER BY s.created_at DESC LIMIT 100
          `);
          return sendJson(res, 200, { ok: true, records: result.rows });
        }
        return sendJson(res, 400, { ok: false, message: "Unknown gaming action" });
      }
      const body = req.body || {};
      if (req.method === "POST" && body.action === "create_player") {
        const username = String(body.username || "").trim().toLowerCase();
        const displayName = String(body.display_name || "").trim();
        const password = String(body.password || "");
        if (!/^[a-z0-9_]{4,40}$/.test(username) || displayName.length < 2 || password.length < 8) {
          return sendJson(res, 400, { ok: false, message: "Username (4-40 letters/numbers/_), display name and password (8+ characters) are required." });
        }
        const hash = await bcrypt.hash(password, 12);
        const client = await pool.connect();
        try {
          await client.query("BEGIN");
          const player = await client.query(
            "INSERT INTO sp_game_players (username,display_name,password_hash) VALUES ($1,$2,$3) RETURNING id,username,display_name,status,created_at",
            [username, displayName, hash]
          );
          await client.query("INSERT INTO sp_game_wallets (player_id,virtual_coins) VALUES ($1,1000)", [player.rows[0].id]);
          await client.query("INSERT INTO sp_game_coin_ledger (player_id,amount,entry_type,note) VALUES ($1,1000,'WELCOME','Starting virtual points')", [player.rows[0].id]);
          await client.query("COMMIT");
          return sendJson(res, 201, { ok: true, player: { ...player.rows[0], virtual_coins: 1000 } });
        } catch (e) {
          await client.query("ROLLBACK");
          if (e.code === "23505") return sendJson(res, 409, { ok: false, message: "This username is already registered." });
          throw e;
        } finally { client.release(); }
      }
      if (req.method === "PATCH" && body.action === "player_status") {
        const id = Number(body.player_id);
        if (!Number.isSafeInteger(id) || !["ACTIVE","SUSPENDED"].includes(body.status)) {
          return sendJson(res, 400, { ok: false, message: "Invalid player or status" });
        }
        const result = await pool.query("UPDATE sp_game_players SET status=$1 WHERE id=$2 RETURNING id,status", [body.status,id]);
        if (!result.rowCount) return sendJson(res,404,{ok:false,message:"Player not found"});
        return sendJson(res,200,{ok:true,player:result.rows[0]});
      }
      return sendJson(res, 400, { ok: false, message: "Unknown gaming action" });
    } catch (error) {
      console.error("Gaming dashboard API error:", error.message);
      return sendJson(res, 500, { ok: false, message: "Gaming data service unavailable" });
    }
  }

  if (!allowMethods(req, res, ["GET"])) return;
  if (!getAdmin(req, res)) return;
  try {
    const pool = getPool();
    const [merchants, transactions, deposits, payments, pendingAccounts] = await Promise.all([
      pool.query("SELECT COUNT(*)::int AS total FROM sp_users WHERE role = 'MERCHANT'"),
      pool.query("SELECT COUNT(*)::int AS total FROM sp_ledger"),
      pool.query("SELECT COUNT(*)::int AS total FROM sp_deposits"),
      pool.query("SELECT COUNT(*)::int AS total FROM sp_ledger WHERE entry_type IN ('PAYMENT','MANUAL_DEBIT','CHARGE')"),
      pool.query("SELECT COUNT(*)::int AS total FROM sp_merchant_accounts WHERE status = 'PENDING'")
    ]);
    return sendJson(res, 200, { ok: true, stats: {
      merchants: merchants.rows[0].total,
      transactions: transactions.rows[0].total,
      deposits: deposits.rows[0].total,
      payments_debits: payments.rows[0].total,
      pending_account_requests: pendingAccounts.rows[0].total
    }});
  } catch (error) {
    console.error("Dashboard API error:", error.message);
    return sendJson(res, 500, {
      ok: false,
      message: error.code === "42P01"
        ? "A required Paykassma database table is missing. Run the latest database SQL files in Neon."
        : "Dashboard data unavailable"
    });
  }
};
