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
      const body = req.body || {};
      const gameCode = String(body.game_code || "TAP_CHALLENGE");
      const allowedGames = ["TAP_CHALLENGE","AVIATOR_FLIGHT","CARD_MEMORY"];
      if (!allowedGames.includes(gameCode)) return sendJson(res,400,{ok:false,message:"Unknown score-only game"});
      const durationMs = Number(body.duration_ms);
      let result = {};
      let score = 0;
      if (gameCode === "TAP_CHALLENGE") {
        const taps = Number(body.taps);
        if (!Number.isInteger(taps) || taps < 0 || taps > 500 || !Number.isInteger(durationMs) || durationMs < 5000 || durationMs > 60000)
          return sendJson(res,400,{ok:false,message:"Invalid tap challenge result"});
        score = taps;
        result = {taps,duration_ms:durationMs,points_awarded:0};
      } else if (gameCode === "AVIATOR_FLIGHT") {
        if (!Number.isInteger(durationMs) || durationMs < 0 || durationMs > 30000)
          return sendJson(res,400,{ok:false,message:"Invalid flight challenge result"});
        score = Math.floor(durationMs / 100) / 10;
        result = {flight_ms:durationMs,score_seconds:score,points_awarded:0};
      } else {
        const moves = Number(body.moves);
        const matches = Number(body.matches);
        if (!Number.isInteger(durationMs) || durationMs < 1000 || durationMs > 600000 ||
            !Number.isInteger(moves) || moves < 8 || moves > 200 || matches !== 8)
          return sendJson(res,400,{ok:false,message:"Invalid card memory result"});
        score = Math.max(0,1000 - moves * 10 - Math.floor(durationMs / 1000));
        result = {moves,matches,duration_ms:durationMs,score,points_awarded:0};
      }
      const active = await pool.query("SELECT id FROM sp_game_players WHERE id=$1 AND status='ACTIVE' LIMIT 1",[player.sub]);
      if (!active.rowCount) return sendJson(res,403,{ok:false,message:"Player account is unavailable"});
      const gameSetting = await pool.query("SELECT enabled FROM sp_game_settings WHERE game_code=$1 LIMIT 1",[gameCode]);
      if (!gameSetting.rows[0]?.enabled) return sendJson(res,403,{ok:false,message:"This game is currently disabled by the administrator"});
      const saved = await pool.query(
        "INSERT INTO sp_game_sessions(player_id,game_code,result,coins_change) VALUES($1,$2,$3::jsonb,0) RETURNING id,created_at",
        [player.sub,gameCode,JSON.stringify(result)]
      );
      return sendJson(res,200,{ok:true,session:saved.rows[0],score,message:"Score saved. Virtual points were not changed."});
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
        if (action === "prediction_matches") {
          const result = await pool.query(`
            SELECT m.*,
              COUNT(p.id)::int AS prediction_count,
              COUNT(p.id) FILTER (WHERE p.selection_side=m.result_side)::int AS correct_count
            FROM sp_prediction_matches m
            LEFT JOIN sp_predictions p ON p.match_id=m.id
            GROUP BY m.id ORDER BY m.scheduled_at DESC NULLS LAST,m.id DESC LIMIT 100
          `);
          return sendJson(res,200,{ok:true,matches:result.rows});
        }
        if (action === "monitoring") {
          const [matches,virtualReserve,settlements,audit] = await Promise.all([
            pool.query(`
              SELECT m.id,m.title,m.sport,m.side_a,m.side_b,m.status,m.result_side,m.result_label,m.result_source,
                     COUNT(p.id)::int AS prediction_count,
                     COUNT(p.id) FILTER (WHERE p.selection_side='A')::int AS side_a_count,
                     COUNT(p.id) FILTER (WHERE p.selection_side='B')::int AS side_b_count,
                     COUNT(p.id) FILTER (WHERE p.selection_side=m.result_side)::int AS correct_count
              FROM sp_prediction_matches m LEFT JOIN sp_predictions p ON p.match_id=m.id
              GROUP BY m.id ORDER BY m.updated_at DESC,m.id DESC LIMIT 50
            `),
            pool.query("SELECT COUNT(*)::int AS wallet_count,COALESCE(SUM(virtual_coins),0)::bigint AS virtual_points FROM sp_game_wallets"),
            pool.query("SELECT COUNT(*)::int AS settled_matches,COALESCE(SUM(prediction_count),0)::bigint AS predictions,COALESCE(SUM(correct_count),0)::bigint AS correct,COALESCE(SUM(incorrect_count),0)::bigint AS incorrect,COALESCE(SUM(void_count),0)::bigint AS void FROM sp_prediction_settlements"),
            pool.query("SELECT id,match_id,event_type,event_note,event_data,created_at FROM sp_prediction_audit_logs ORDER BY created_at DESC LIMIT 20")
          ]);
          const rows=matches.rows.map(m=>{
            const total=Number(m.prediction_count||0),a=Number(m.side_a_count||0),b=Number(m.side_b_count||0);
            return {...m,side_a_count:a,side_b_count:b,imbalance_percent:total?Math.round(Math.abs(a-b)*100/total):0};
          });
          return sendJson(res,200,{ok:true,monitoring:{
            exposure:{matches:rows,total_predictions:rows.reduce((n,m)=>n+Number(m.prediction_count||0),0),unbalanced_matches:rows.filter(m=>m.imbalance_percent>=60&&Number(m.prediction_count)>=5).length},
            liquidity:{wallet_count:virtualReserve.rows[0].wallet_count,virtual_points:String(virtualReserve.rows[0].virtual_points),unit:"virtual points only"},
            reserve:{virtual_points:String(virtualReserve.rows[0].virtual_points),unit:"virtual points only",cash_value:0},
            settlement:{...settlements.rows[0],recent:audit.rows}
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
      if (req.method === "POST" && body.action === "create_prediction_match") {
        const sport=String(body.sport||"CRICKET").toUpperCase();
        const sideA=String(body.side_a||"").trim().slice(0,100);
        const sideB=String(body.side_b||"").trim().slice(0,100);
        const title=String(body.title||"").trim().slice(0,200);
        if(!["CRICKET","FOOTBALL","OTHER"].includes(sport)||!sideA||!sideB||sideA===sideB||!title)
          return sendJson(res,400,{ok:false,message:"Sport, match title and two different team names are required"});
        const scheduled=body.scheduled_at?new Date(body.scheduled_at):null;
        if(scheduled && Number.isNaN(scheduled.getTime())) return sendJson(res,400,{ok:false,message:"Invalid match date"});
        const saved=await pool.query(
          "INSERT INTO sp_prediction_matches(sport,title,side_a,side_b,scheduled_at,status,result_source) VALUES($1,$2,$3,$4,$5,'UPCOMING','MANUAL') RETURNING *",
          [sport,title,sideA,sideB,scheduled]
        );
        return sendJson(res,201,{ok:true,match:saved.rows[0]});
      }
      if (req.method === "POST" && body.action === "manual_match_result") {
        const matchId=Number(body.match_id), side=String(body.result_side||"").toUpperCase();
        if(!Number.isSafeInteger(matchId)||matchId<1||!["A","B","D"].includes(side))
          return sendJson(res,400,{ok:false,message:"Choose a valid match and result"});
        const saved=await pool.query(
          "UPDATE sp_prediction_matches SET result_side=$1,result_label=CASE WHEN $1='A' THEN side_a WHEN $1='B' THEN side_b ELSE 'Draw / No Result' END,status='FINISHED',result_source='MANUAL',updated_at=NOW() WHERE id=$2 RETURNING *",
          [side,matchId]
        );
        if(!saved.rowCount)return sendJson(res,404,{ok:false,message:"Match not found"});
        const count=await pool.query("SELECT COUNT(*)::int AS total,COUNT(*) FILTER(WHERE selection_side=$1)::int AS correct FROM sp_predictions WHERE match_id=$2",[side,matchId]);
        const total=Number(count.rows[0].total||0),correct=side==="D"?0:Number(count.rows[0].correct||0),voidCount=side==="D"?total:0,incorrect=side==="D"?0:total-correct;
        await pool.query(`
          INSERT INTO sp_prediction_settlements(match_id,prediction_count,correct_count,incorrect_count,void_count,result_side,result_source,settled_at)
          VALUES($1,$2,$3,$4,$5,$6,'MANUAL',NOW())
          ON CONFLICT(match_id) DO UPDATE SET prediction_count=EXCLUDED.prediction_count,correct_count=EXCLUDED.correct_count,incorrect_count=EXCLUDED.incorrect_count,void_count=EXCLUDED.void_count,result_side=EXCLUDED.result_side,result_source='MANUAL',settled_at=NOW()
        `,[matchId,total,correct,incorrect,voidCount,side]);
        await pool.query("INSERT INTO sp_prediction_audit_logs(match_id,event_type,event_note,event_data) VALUES($1,'MANUAL_RESULT','Admin saved a manual match result',$2::jsonb)",[matchId,JSON.stringify({result_side:side,prediction_count:total,correct_count:correct,incorrect_count:incorrect,void_count:voidCount})]);
        return sendJson(res,200,{ok:true,match:saved.rows[0],predictions:{total,correct,incorrect,void:voidCount}});
      }
      if (req.method === "POST" && body.action === "sync_match_results") {
        const apiKey=process.env.FOOTBALL_API_KEY;
        const cricketKey=process.env.SPORTMONKS_CRICKET_TOKEN;
        let updated=0,review=0,checked=0,skippedManual=0,errors=[];
        const textValue=value=>String(value===undefined||value===null?"":value).trim();
        const same=(a,b)=>textValue(a).toLocaleLowerCase()===textValue(b).toLocaleLowerCase();
        async function saveProviderMatch(sport,providerId,title,a,b,scheduled,resultSide,resultLabel,data){
          if(!providerId||!a||!b||same(a,b))return;
          checked++;
          const existing=await pool.query("SELECT id,result_source,status,result_side FROM sp_prediction_matches WHERE sport=$1 AND provider_match_id=$2",[sport,String(providerId)]);
          if(existing.rows[0]?.result_source==="MANUAL"){skippedManual++;return;}
          const status="FINISHED";
          await pool.query(`
            INSERT INTO sp_prediction_matches(sport,provider_match_id,title,side_a,side_b,scheduled_at,status,result_side,result_label,result_source,result_data)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)
            ON CONFLICT(sport,provider_match_id) DO UPDATE SET
              title=EXCLUDED.title,side_a=EXCLUDED.side_a,side_b=EXCLUDED.side_b,
              scheduled_at=COALESCE(EXCLUDED.scheduled_at,sp_prediction_matches.scheduled_at),
              status=CASE WHEN sp_prediction_matches.result_source='MANUAL' THEN sp_prediction_matches.status ELSE EXCLUDED.status END,
              result_side=CASE WHEN sp_prediction_matches.result_source='MANUAL' THEN sp_prediction_matches.result_side ELSE COALESCE(EXCLUDED.result_side,sp_prediction_matches.result_side) END,
              result_label=CASE WHEN sp_prediction_matches.result_source='MANUAL' THEN sp_prediction_matches.result_label ELSE COALESCE(EXCLUDED.result_label,sp_prediction_matches.result_label) END,
              result_source=CASE WHEN sp_prediction_matches.result_source='MANUAL' THEN 'MANUAL' ELSE EXCLUDED.result_source END,
              result_data=EXCLUDED.result_data,updated_at=NOW()
            RETURNING id
          `,[sport,String(providerId),title,a,b,scheduled||null,status,resultSide||null,resultLabel||null,resultSide?"API":"API_REVIEW",JSON.stringify(data||{})]);
          if(resultSide) {
            updated++;
            if(existing.rows[0]?.result_side!==resultSide) {
              const matchId=Number((await pool.query("SELECT id FROM sp_prediction_matches WHERE sport=$1 AND provider_match_id=$2",[sport,String(providerId)])).rows[0]?.id||0);
              if(matchId) {
                const counts=await pool.query("SELECT COUNT(*)::int AS total,COUNT(*) FILTER(WHERE selection_side=$1)::int AS correct FROM sp_predictions WHERE match_id=$2",[resultSide,matchId]);
                const total=Number(counts.rows[0].total||0),correct=Number(counts.rows[0].correct||0);
                await pool.query(`
                  INSERT INTO sp_prediction_settlements(match_id,prediction_count,correct_count,incorrect_count,void_count,result_side,result_source,settled_at)
                  VALUES($1,$2,$3,$4,0,$5,'API',NOW())
                  ON CONFLICT(match_id) DO UPDATE SET prediction_count=EXCLUDED.prediction_count,correct_count=EXCLUDED.correct_count,incorrect_count=EXCLUDED.incorrect_count,void_count=0,result_side=EXCLUDED.result_side,result_source='API',settled_at=NOW()
                `,[matchId,total,correct,total-correct,resultSide]);
                await pool.query("INSERT INTO sp_prediction_audit_logs(match_id,event_type,event_note,event_data) VALUES($1,'API_RESULT','Provider result imported',$2::jsonb)",[matchId,JSON.stringify({result_side:resultSide,prediction_count:total,correct_count:correct,incorrect_count:total-correct})]);
              }
            }
          } else review++;
        }
        try {
          if(apiKey){
            const dates=[];const now=new Date();
            for(let offset=-7;offset<=0;offset++){const d=new Date(now);d.setUTCDate(d.getUTCDate()+offset);dates.push(d.toISOString().slice(0,10));}
            const lists=await Promise.all(dates.map(async date=>{
              const resp=await fetch("https://api.sportsapi.app/v2/fixtures?date="+date+"&sport=football",{headers:{Accept:"application/json",Authorization:"Bearer "+apiKey}});
              if(!resp.ok)throw new Error("Football API HTTP "+resp.status);
              const payload=await resp.json();return Array.isArray(payload.data)?payload.data:[];
            }));
            const seen=new Set();
            for(const m of lists.flat()){
              if(String(m.status?.type||"").toLowerCase()!=="finished")continue;
              const home=m.home?.name||m.homeTeam?.name||m.home_team?.name||m.homeTeamName||m.teams?.home?.name||"";
              const away=m.away?.name||m.awayTeam?.name||m.away_team?.name||m.awayTeamName||m.teams?.away?.name||"";
              const a=textValue(home),b=textValue(away);
              const id=m.id||m.fixtureId||m.matchId;
              if(!id||!a||!b||seen.has(String(id)))continue;
              seen.add(String(id));
              const winnerObj=m.winner||m.winnerTeam||m.winner_team||m.status?.winner;
              const winnerName=typeof winnerObj==="string"?winnerObj:textValue(winnerObj?.name||winnerObj?.shortName||m.winnerName);
              const homeId=m.home?.id||m.homeTeam?.id||m.home_team?.id||m.teams?.home?.id;
              const awayId=m.away?.id||m.awayTeam?.id||m.away_team?.id||m.teams?.away?.id;
              const winnerId=winnerObj?.id||m.winnerTeamId||m.winner_team_id;
              let side=null;
              if(winnerId&&homeId&&String(winnerId)===String(homeId))side="A";
              else if(winnerId&&awayId&&String(winnerId)===String(awayId))side="B";
              else if(winnerName&&same(winnerName,a))side="A";
              else if(winnerName&&same(winnerName,b))side="B";
              else {
                const hs=Number(m.homeScore?.current??m.homeScore??m.scores?.home?.current);
                const as=Number(m.awayScore?.current??m.awayScore??m.scores?.away?.current);
                if(Number.isFinite(hs)&&Number.isFinite(as)&&hs>as)side="A";
                else if(Number.isFinite(hs)&&Number.isFinite(as)&&as>hs)side="B";
              }
              const label=side?(side==="A"?a:b):(winnerName||null);
              await saveProviderMatch("FOOTBALL",id,a+" vs "+b,a,b,m.startTime||m.starting_at||null,side,label,m);
            }
          } else errors.push("Football: FOOTBALL_API_KEY is not configured");
        } catch(e){errors.push("Football: "+e.message)}
        try {
          if(cricketKey){
            const now=new Date();
            const from=new Date(now.getTime()-14*86400000).toISOString().slice(0,10);
            const to=now.toISOString().slice(0,10);
            const url="https://cricket.sportmonks.com/api/v2.0/fixtures?api_token="+encodeURIComponent(cricketKey)+"&filter[starts_between]="+from+","+to+"&include=localteam,visitorteam,scoreboards,winnerteam";
            const resp=await fetch(url,{headers:{Accept:"application/json"}});
            if(!resp.ok)throw new Error("Cricket API HTTP "+resp.status);
            const payload=await resp.json();
            for(const m of (Array.isArray(payload.data)?payload.data:[])){
              if(String(m.status||"").toLowerCase()!=="finished")continue;
              const a=textValue(m.localteam?.name||m.localteam?.data?.name);
              const b=textValue(m.visitorteam?.name||m.visitorteam?.data?.name);
              const winnerObj=m.winnerteam||m.winner_team||m.winnerTeam||m.winner;
              const winnerId=m.winner_team_id||m.winnerteam_id||winnerObj?.id||winnerObj?.data?.id;
              const localId=m.localteam_id||m.localteam?.id||m.localteam?.data?.id;
              const visitorId=m.visitorteam_id||m.visitorteam?.id||m.visitorteam?.data?.id;
              const winnerName=textValue(winnerObj?.name||winnerObj?.data?.name);
              let side=null;
              if(winnerId&&localId&&String(winnerId)===String(localId))side="A";
              else if(winnerId&&visitorId&&String(winnerId)===String(visitorId))side="B";
              else if(winnerName&&same(winnerName,a))side="A";
              else if(winnerName&&same(winnerName,b))side="B";
              const label=side?(side==="A"?a:b):(winnerName||null);
              await saveProviderMatch("CRICKET",m.id,a+" vs "+b,a,b,m.starting_at||null,side,label,m);
            }
          } else errors.push("Cricket: SPORTMONKS_CRICKET_TOKEN is not configured");
        } catch(e){errors.push("Cricket: "+e.message)}
        return sendJson(res,200,{ok:true,checked,updated,needs_manual_review:review,skipped_manual:skippedManual,errors});
      }
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
