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
    CREATE TABLE IF NOT EXISTS sp_game_settings (
      game_code VARCHAR(40) PRIMARY KEY,
      title VARCHAR(100) NOT NULL,
      description VARCHAR(240) NOT NULL DEFAULT '',
      enabled BOOLEAN NOT NULL DEFAULT FALSE,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    INSERT INTO sp_game_settings(game_code,title,description,enabled) VALUES
      ('TAP_CHALLENGE','Tap Speed Challenge','10-second reaction and tapping game',TRUE),
      ('CRICKET_CENTRE','Cricket Centre','Cricket information and verified live data',TRUE),
      ('FOOTBALL_CENTRE','Football Centre','Football live scores, fixtures and results',TRUE)
    ON CONFLICT(game_code) DO NOTHING;
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
  const isPlayerFootball = req.query && req.query.module === "gaming-football";
  if (isPlayerFootball) {
    if (!allowMethods(req, res, ["GET"])) return;
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    let player;
    try { player = token ? verifyToken(token) : null; } catch {}
    if (!player || player.role !== "GAMING_PLAYER" || !player.sub) {
      return sendJson(res, 401, { ok: false, message: "ParixBet player login required" });
    }
    try {
      const pool = getPool();
      await ensureGamingTables(pool);
      const active = await pool.query("SELECT id FROM sp_game_players WHERE id=$1 AND status='ACTIVE' LIMIT 1", [player.sub]);
      if (!active.rowCount) return sendJson(res, 403, { ok: false, message: "Player account is unavailable" });
      const setting = await pool.query("SELECT enabled FROM sp_game_settings WHERE game_code='FOOTBALL_CENTRE' LIMIT 1");
      if (!setting.rows[0]?.enabled) return sendJson(res, 403, { ok: false, message: "Football Centre is currently disabled" });
      const apiKey = process.env.FOOTBALL_API_KEY;
      if (!apiKey) return sendJson(res, 200, { ok: true, connected: false, message: "Football data is not connected yet.", matches: [], upcoming: [], results: [] });

      async function getFootballData(cacheKey, url, maxAge) {
        const cached = await pool.query("SELECT payload,fetched_at FROM sp_game_cricket_cache WHERE cache_key=$1 LIMIT 1", [cacheKey]);
        const age = cached.rows[0] ? Date.now() - new Date(cached.rows[0].fetched_at).getTime() : Infinity;
        if (age < maxAge) return cached.rows[0].payload;
        try {
          const response = await fetch(url, { headers: { Accept: "application/json", Authorization: "Bearer " + apiKey } });
          if (!response.ok) throw new Error("Football provider returned HTTP " + response.status);
          const payload = await response.json();
          if (payload && payload.error) throw new Error(payload.error.message || "Football provider API error");
          const data = Array.isArray(payload.data) ? payload.data : [];
          await pool.query(
            "INSERT INTO sp_game_cricket_cache(cache_key,payload,fetched_at) VALUES($1,$2::jsonb,NOW()) ON CONFLICT(cache_key) DO UPDATE SET payload=EXCLUDED.payload,fetched_at=NOW()",
            [cacheKey, JSON.stringify(data)]
          );
          return data;
        } catch (error) {
          if (cached.rows[0] && Array.isArray(cached.rows[0].payload)) {
            console.warn("Using cached football data after provider error:", cacheKey, error.message);
            return cached.rows[0].payload;
          }
          throw error;
        }
      }

      const now = new Date();
      const dateKey = value => value.toISOString().slice(0, 10);
      const livePromise = getFootballData(
        "football-live",
        "https://api.sportsapi.app/v2/livescores?sport=football",
        30000
      );
      const fixtureDates = [];
      for (let offset = -2; offset <= 5; offset++) {
        const day = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + offset));
        fixtureDates.push(dateKey(day));
      }
      const fixtureLists = await Promise.all(fixtureDates.map(date =>
        getFootballData(
          "football-" + date.replace(/-/g, ""),
          "https://api.sportsapi.app/v2/fixtures?date=" + date + "&sport=football",
          900000
        )
      ));
      const matches = await livePromise;
      const fixtures = fixtureLists.flat();
      const upcoming = fixtures.filter(match => {
        const start = new Date(match.startTime || 0);
        const status = String(match.status?.type || "").toLowerCase();
        return !Number.isNaN(start.getTime()) && start >= now && !["finished", "cancelled", "postponed"].includes(status);
      }).sort((a,b) => new Date(a.startTime) - new Date(b.startTime)).slice(0, 15);
      const results = fixtures.filter(match => String(match.status?.type || "").toLowerCase() === "finished")
        .sort((a,b) => new Date(b.startTime || 0) - new Date(a.startTime || 0)).slice(0, 15);
      return sendJson(res, 200, { ok: true, connected: true, matches, upcoming, results });
    } catch (error) {
      console.error("ParixBet player football API error:", error.message);
      return sendJson(res, 502, { ok: false, message: "Live football data is temporarily unavailable" });
    }
  }
  const isPlayerCricket = req.query && req.query.module === "gaming-cricket";
  if (isPlayerCricket) {
    if (!allowMethods(req, res, ["GET"])) return;
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    let player;
    try { player = token ? verifyToken(token) : null; } catch {}
    if (!player || player.role !== "GAMING_PLAYER" || !player.sub) {
      return sendJson(res, 401, { ok: false, message: "ParixBet player login required" });
    }
    try {
      const pool = getPool();
      await ensureGamingTables(pool);
      const active = await pool.query("SELECT id FROM sp_game_players WHERE id=$1 AND status='ACTIVE' LIMIT 1", [player.sub]);
      if (!active.rowCount) return sendJson(res, 403, { ok: false, message: "Player account is unavailable" });
      const setting = await pool.query("SELECT enabled FROM sp_game_settings WHERE game_code='CRICKET_CENTRE' LIMIT 1");
      if (!setting.rows[0]?.enabled) return sendJson(res, 403, { ok: false, message: "Cricket Centre is currently disabled" });
      const apiKey = process.env.SPORTMONKS_CRICKET_TOKEN;
      if (!apiKey) return sendJson(res, 200, { ok: true, connected: false, message: "Live cricket data is not connected yet.", matches: [], upcoming: [], results: [] });

      async function getCricketData(cacheKey, url, maxAge) {
        const cached = await pool.query("SELECT payload,fetched_at FROM sp_game_cricket_cache WHERE cache_key=$1 LIMIT 1", [cacheKey]);
        const age = cached.rows[0] ? Date.now() - new Date(cached.rows[0].fetched_at).getTime() : Infinity;
        if (age < maxAge) return cached.rows[0].payload;
        const response = await fetch(url, { headers: { Accept: "application/json" } });
        if (!response.ok) throw new Error("Cricket provider returned HTTP " + response.status);
        const payload = await response.json();
        const data = Array.isArray(payload.data) ? payload.data : [];
        await pool.query(
          "INSERT INTO sp_game_cricket_cache(cache_key,payload,fetched_at) VALUES($1,$2::jsonb,NOW()) ON CONFLICT(cache_key) DO UPDATE SET payload=EXCLUDED.payload,fetched_at=NOW()",
          [cacheKey, JSON.stringify(data)]
        );
        return data;
      }

      const now = new Date();
      const day = value => value.toISOString().slice(0, 10);
      const pastStart = new Date(now.getTime() - 14 * 86400000);
      const futureEnd = new Date(now.getTime() + 14 * 86400000);
      const liveUrl = "https://cricket.sportmonks.com/api/v2.0/livescores?api_token=" + encodeURIComponent(apiKey) + "&include=localteam,visitorteam,scoreboards,runs,batting,bowling,venue,tosswon";
      const fixtureBase = "https://cricket.sportmonks.com/api/v2.0/fixtures?api_token=" + encodeURIComponent(apiKey) + "&include=localteam,visitorteam,scoreboards,runs,batting,bowling,venue,tosswon&filter[starts_between]=";
      const [matches, fixturePast, fixtureFuture] = await Promise.all([
        getCricketData("livescores", liveUrl, 30000),
        getCricketData("fixtures-recent", fixtureBase + day(pastStart) + "," + day(now), 900000),
        getCricketData("fixtures-upcoming", fixtureBase + day(now) + "," + day(futureEnd), 900000)
      ]);
      const results = fixturePast.filter(match => String(match.status || "").toLowerCase() === "finished")
        .sort((a,b) => new Date(b.starting_at || 0) - new Date(a.starting_at || 0)).slice(0, 12);
      const upcoming = fixtureFuture.filter(match => {
        const start = new Date(match.starting_at || 0);
        const status = String(match.status || "").toLowerCase();
        return !Number.isNaN(start.getTime()) && start >= now && status !== "finished" && status !== "cancelled";
      }).sort((a,b) => new Date(a.starting_at) - new Date(b.starting_at)).slice(0, 12);
      return sendJson(res, 200, { ok: true, connected: true, cached: false, matches, upcoming, results });
    } catch (error) {
      console.error("ParixBet player cricket API error:", error.message);
      return sendJson(res, 502, { ok: false, message: "Live cricket data is temporarily unavailable" });
    }
  }
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
      const games = await pool.query("SELECT game_code,title,description,enabled FROM sp_game_settings ORDER BY title");
      return sendJson(res, 200, { ok: true, player: profile.rows[0], history: history.rows, games: games.rows });
    } catch (error) {
      console.error("Gaming player API error:", error.message);
      return sendJson(res, 500, { ok: false, message: "Gaming profile unavailable" });
    }
  }

  const isPlayerGame = req.query && req.query.module === "gaming-play";
  if (isPlayerGame) {
    if (!allowMethods(req, res, ["POST"])) return;
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    let player;
    try { player = token ? verifyToken(token) : null; } catch {}
    if (!player || player.role !== "GAMING_PLAYER" || !player.sub) {
      return sendJson(res, 401, { ok: false, message: "ParixBet player login required" });
    }
    try {
      const pool = getPool();
      await ensureGamingTables(pool);
      const taps = Number(req.body && req.body.taps);
      const durationMs = Number(req.body && req.body.duration_ms);
      if (!Number.isInteger(taps) || taps < 0 || taps > 500 ||
          !Number.isInteger(durationMs) || durationMs < 5000 || durationMs > 60000) {
        return sendJson(res, 400, { ok: false, message: "Invalid game result" });
      }
      const active = await pool.query("SELECT id FROM sp_game_players WHERE id=$1 AND status='ACTIVE' LIMIT 1",[player.sub]);
      if (!active.rowCount) return sendJson(res,403,{ok:false,message:"Player account is unavailable"});
      const gameSetting = await pool.query("SELECT enabled FROM sp_game_settings WHERE game_code='TAP_CHALLENGE' LIMIT 1");
      if (!gameSetting.rows[0]?.enabled) return sendJson(res,403,{ok:false,message:"This game is currently disabled by the administrator"});
      const saved = await pool.query(
        "INSERT INTO sp_game_sessions(player_id,game_code,result,coins_change) VALUES($1,'TAP_CHALLENGE',$2::jsonb,0) RETURNING id,created_at",
        [player.sub,JSON.stringify({taps,duration_ms:durationMs,points_awarded:0})]
      );
      return sendJson(res,200,{ok:true,session:saved.rows[0],score:taps,message:"Score saved. Virtual points were not changed."});
    } catch (error) {
      console.error("ParixBet game save error:",error.message);
      return sendJson(res,500,{ok:false,message:"Game result could not be saved"});
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
        if (action === "games") {
          const result = await pool.query("SELECT game_code,title,description,enabled,updated_at FROM sp_game_settings ORDER BY title");
          return sendJson(res,200,{ok:true,games:result.rows});
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
      if (req.method === "PATCH" && body.action === "game_status") {
        const gameCode = String(body.game_code || "");
        if (!/^[A-Z0-9_]{3,40}$/.test(gameCode) || typeof body.enabled !== "boolean") {
          return sendJson(res,400,{ok:false,message:"Invalid game or status"});
        }
        const result = await pool.query(
          "UPDATE sp_game_settings SET enabled=$1,updated_at=NOW() WHERE game_code=$2 RETURNING game_code,title,enabled",
          [body.enabled,gameCode]
        );
        if (!result.rowCount) return sendJson(res,404,{ok:false,message:"Game not found"});
        return sendJson(res,200,{ok:true,game:result.rows[0]});
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
