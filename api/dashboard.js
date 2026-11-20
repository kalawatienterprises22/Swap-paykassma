const { getPool } = require("./_lib/db");
const { sendJson, allowMethods } = require("./_lib/http");
const { verifyToken } = require("./_lib/auth");
const bcrypt = require("bcryptjs");

let tablesReadyPromise = null;

async function ensureGamingTables(pool) {
  if (tablesReadyPromise) return tablesReadyPromise;

  tablesReadyPromise = (async () => {
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
      CREATE TABLE IF NOT EXISTS sp_prediction_matches (
        id BIGSERIAL PRIMARY KEY,
        sport VARCHAR(20) NOT NULL DEFAULT 'CRICKET',
        provider_match_id VARCHAR(100),
        title VARCHAR(200) NOT NULL,
        side_a VARCHAR(100) NOT NULL,
        side_b VARCHAR(100) NOT NULL,
        scheduled_at TIMESTAMPTZ,
        status VARCHAR(20) NOT NULL DEFAULT 'UPCOMING',
        result_side VARCHAR(1),
        result_label VARCHAR(100),
        result_source VARCHAR(20),
        result_data JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(sport,provider_match_id)
      );
      CREATE TABLE IF NOT EXISTS sp_predictions (
        id BIGSERIAL PRIMARY KEY,
        match_id BIGINT NOT NULL REFERENCES sp_prediction_matches(id) ON DELETE CASCADE,
        player_id BIGINT NOT NULL REFERENCES sp_game_players(id) ON DELETE CASCADE,
        selection_side VARCHAR(1) NOT NULL CHECK (selection_side IN ('A','B')),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(match_id,player_id)
      );
      CREATE TABLE IF NOT EXISTS sp_prediction_monitor_settings (
        id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id=1),
        min_predictions INTEGER NOT NULL DEFAULT 5 CHECK (min_predictions BETWEEN 1 AND 10000),
        imbalance_threshold_pct NUMERIC(5,2) NOT NULL DEFAULT 60 CHECK (imbalance_threshold_pct BETWEEN 50 AND 95),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      INSERT INTO sp_prediction_monitor_settings(id,min_predictions,imbalance_threshold_pct)
      VALUES(1,5,60) ON CONFLICT(id) DO NOTHING;
      CREATE TABLE IF NOT EXISTS sp_prediction_settlements (
        id BIGSERIAL PRIMARY KEY,
        match_id BIGINT NOT NULL UNIQUE REFERENCES sp_prediction_matches(id) ON DELETE CASCADE,
        prediction_count INTEGER NOT NULL DEFAULT 0,
        correct_count INTEGER NOT NULL DEFAULT 0,
        incorrect_count INTEGER NOT NULL DEFAULT 0,
        void_count INTEGER NOT NULL DEFAULT 0,
        result_side VARCHAR(1),
        result_source VARCHAR(20),
        settled_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS sp_prediction_audit_logs (
        id BIGSERIAL PRIMARY KEY,
        match_id BIGINT REFERENCES sp_prediction_matches(id) ON DELETE SET NULL,
        event_type VARCHAR(40) NOT NULL,
        event_note VARCHAR(240) NOT NULL DEFAULT '',
        event_data JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
        ('FOOTBALL_CENTRE','Football Centre','Football live scores, fixtures and results',TRUE),
        ('AVIATOR_FLIGHT','Aviator Flight Challenge','Plane flight timing challenge · score only, no wagers',TRUE),
        ('CARD_MEMORY','Card Memory Match','Match identical cards · score only, no prizes',TRUE)
      ON CONFLICT(game_code) DO NOTHING;
    `);
  })().catch((err) => {
    tablesReadyPromise = null;
    throw err;
  });

  return tablesReadyPromise;
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
  const mod = req.query && req.query.module;

  // 1. Player Football Module
  if (mod === "gaming-football") {
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
            return cached.rows[0].payload;
          }
          throw error;
        }
      }

      const now = new Date();
      const dateKey = value => value.toISOString().slice(0, 10);
      const livePromise = getFootballData("football-live", "https://api.sportsapi.app/v2/livescores?sport=football", 30000);
      const fixtureDates = [];
      for (let offset = -2; offset <= 5; offset++) {
        const day = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + offset));
        fixtureDates.push(dateKey(day));
      }
      const fixtureLists = await Promise.all(fixtureDates.map(date =>
        getFootballData("football-" + date.replace(/-/g, ""), "https://api.sportsapi.app/v2/fixtures?date=" + date + "&sport=football", 900000)
      ));
      const matches = await livePromise;
      const fixtures = fixtureLists.flat();
      const upcoming = fixtures.filter(match => {
        const start = new Date(match.startTime || 0);
        const status = String(match.status?.type || "").toLowerCase();
        return !Number.isNaN(start.getTime()) && start >= now && !["finished", "cancelled", "postponed"].includes(status);
      }).sort((a, b) => new Date(a.startTime) - new Date(b.startTime)).slice(0, 15);
      const results = fixtures.filter(match => String(match.status?.type || "").toLowerCase() === "finished")
        .sort((a, b) => new Date(b.startTime || 0) - new Date(a.startTime || 0)).slice(0, 15);
      return sendJson(res, 200, { ok: true, connected: true, matches, upcoming, results });
    } catch (error) {
      console.error("ParixBet player football API error:", error.message);
      return sendJson(res, 502, { ok: false, message: "Live football data is temporarily unavailable" });
    }
  }

  // 2. Player Predictions Module
  if (mod === "gaming-predictions") {
    if (!allowMethods(req, res, ["GET", "POST"])) return;
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
      if (req.method === "GET") {
        const result = await pool.query(`
          SELECT m.id,m.sport,m.title,m.side_a,m.side_b,m.scheduled_at,m.status,m.result_side,m.result_label,
                 p.selection_side AS my_selection
          FROM sp_prediction_matches m
          LEFT JOIN sp_predictions p ON p.match_id=m.id AND p.player_id=$1
          ORDER BY CASE WHEN m.status='FINISHED' THEN 1 ELSE 0 END,m.scheduled_at ASC NULLS LAST,m.id DESC
          LIMIT 40
        `, [player.sub]);
        return sendJson(res, 200, { ok: true, matches: result.rows });
      }
      const body = req.body || {};
      const matchId = Number(body.match_id);
      const side = String(body.selection_side || "").toUpperCase();
      if (!Number.isSafeInteger(matchId) || matchId < 1 || !["A", "B"].includes(side)) {
        return sendJson(res, 400, { ok: false, message: "Choose a match and side" });
      }
      const client = await pool.connect();
      let saved;
      try {
        await client.query("BEGIN");
        const match = await client.query("SELECT id FROM sp_prediction_matches WHERE id=$1 AND status='UPCOMING' FOR UPDATE", [matchId]);
        if (!match.rowCount) {
          await client.query("ROLLBACK");
          return sendJson(res, 409, { ok: false, message: "This match is locked, finished, cancelled, or unavailable for predictions" });
        }
        const result = await client.query(
          "INSERT INTO sp_predictions(match_id,player_id,selection_side) VALUES($1,$2,$3) ON CONFLICT(match_id,player_id) DO UPDATE SET selection_side=EXCLUDED.selection_side,created_at=NOW() RETURNING id,match_id,selection_side,created_at",
          [matchId, player.sub, side]
        );
        saved = result.rows[0];
        await client.query(
          "INSERT INTO sp_prediction_audit_logs(match_id,event_type,event_note,event_data) VALUES($1,'PREDICTION_SAVED','Player saved or updated a match prediction',$2::jsonb)",
          [matchId, JSON.stringify({ player_id: Number(player.sub), selection_side: side })]
        );
        await client.query("COMMIT");
      } catch (transactionError) {
        await client.query("ROLLBACK").catch(() => {});
        throw transactionError;
      } finally {
        client.release();
      }
      return sendJson(res, 200, { ok: true, prediction: saved, message: "Prediction saved." });
    } catch (error) {
      console.error("ParixBet player prediction error:", error.message);
      return sendJson(res, 500, { ok: false, message: "Prediction could not be saved" });
    }
  }

  // 3. Player Cricket Module
  if (mod === "gaming-cricket") {
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

      const matches = await getCricketData(
        "cricket-livescores",
        "https://cricket.sportmonks.com/api/v2.0/livescores?api_token=" + encodeURIComponent(apiKey),
        30000
      );
      return sendJson(res, 200, { ok: true, connected: true, matches, upcoming: [], results: [] });
    } catch (error) {
      console.error("ParixBet player cricket API error:", error.message);
      return sendJson(res, 502, { ok: false, message: "Live cricket data is temporarily unavailable" });
    }
  }

  // 4. Gaming Admin Dashboard Module (module=gaming)
  if (mod === "gaming") {
    if (!allowMethods(req, res, ["GET", "POST", "PATCH"])) return;
    if (!getGamingAdmin(req, res)) return;

    try {
      const pool = getPool();
      await ensureGamingTables(pool);
      const action = String((req.method === "GET" ? req.query?.action : req.body?.action) || "");
      const body = req.body || {};

      if (req.method === "GET" && action === "stats") {
        const [pRes, gRes, cRes] = await Promise.all([
          pool.query("SELECT COUNT(*)::int AS total FROM sp_game_players"),
          pool.query("SELECT COUNT(*)::int AS total FROM sp_game_sessions"),
          pool.query("SELECT COALESCE(SUM(virtual_coins),0)::bigint AS total FROM sp_game_wallets")
        ]);
        return sendJson(res, 200, {
          ok: true,
          stats: {
            players: pRes.rows[0].total,
            games: gRes.rows[0].total,
            coins: Number(cRes.rows[0].total)
          }
        });
      }

      if (req.method === "GET" && action === "games") {
        const r = await pool.query("SELECT game_code,title,description,enabled FROM sp_game_settings ORDER BY game_code ASC");
        return sendJson(res, 200, { ok: true, games: r.rows });
      }

      if (req.method === "GET" && action === "players") {
        const r = await pool.query(`
          SELECT p.id,p.username,p.display_name,p.status,p.created_at,COALESCE(w.virtual_coins,0) AS virtual_coins
          FROM sp_game_players p
          LEFT JOIN sp_game_wallets w ON w.player_id=p.id
          ORDER BY p.id DESC LIMIT 100
        `);
        return sendJson(res, 200, { ok: true, players: r.rows });
      }

      if (req.method === "GET" && action === "records") {
        const r = await pool.query(`
          SELECT s.id,s.game_code,s.coins_change,s.created_at,p.username
          FROM sp_game_sessions s
          JOIN sp_game_players p ON p.id=s.player_id
          ORDER BY s.id DESC LIMIT 50
        `);
        return sendJson(res, 200, { ok: true, records: r.rows });
      }

      if (req.method === "GET" && action === "cricket") {
        const apiKey = process.env.SPORTMONKS_CRICKET_TOKEN;
        if (!apiKey) {
          return sendJson(