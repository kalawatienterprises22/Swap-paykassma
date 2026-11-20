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
    -- Compatibility migration for prediction tables created from the Neon SQL editor.
    ALTER TABLE sp_prediction_matches
      ADD COLUMN IF NOT EXISTS provider_match_id VARCHAR(100),
      ADD COLUMN IF NOT EXISTS title VARCHAR(200),
      ADD COLUMN IF NOT EXISTS side_a VARCHAR(100),
      ADD COLUMN IF NOT EXISTS side_b VARCHAR(100),
      ADD COLUMN IF NOT EXISTS scheduled_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS result_label VARCHAR(100),
      ADD COLUMN IF NOT EXISTS result_data JSONB NOT NULL DEFAULT '{}'::jsonb;

    DO $compat$
    DECLARE
      constraint_row RECORD;
      legacy_column TEXT;
    BEGIN
      FOR constraint_row IN
        SELECT conname
          FROM pg_constraint
         WHERE conrelid = 'sp_prediction_matches'::regclass
           AND contype = 'c'
           AND pg_get_constraintdef(oid) ILIKE '%status%'
      LOOP
        EXECUTE format('ALTER TABLE sp_prediction_matches DROP CONSTRAINT %I', constraint_row.conname);
      END LOOP;

      IF EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = current_schema()
           AND table_name = 'sp_prediction_matches'
           AND column_name = 'external_match_id'
      ) THEN
        EXECUTE $migration$
          UPDATE sp_prediction_matches
             SET provider_match_id = COALESCE(provider_match_id, external_match_id),
                 title = COALESCE(title, match_title),
                 side_a = COALESCE(side_a, team_a),
                 side_b = COALESCE(side_b, team_b),
                 scheduled_at = COALESCE(scheduled_at, starts_at),
                 sport = UPPER(sport),
                 status = CASE
                   WHEN UPPER(status) = 'OPEN' THEN 'UPCOMING'
                   WHEN UPPER(status) = 'SETTLED' THEN 'FINISHED'
                   ELSE UPPER(status)
                 END
           WHERE title IS NULL OR side_a IS NULL OR side_b IS NULL
              OR scheduled_at IS NULL OR provider_match_id IS NULL
              OR status IN ('OPEN','SETTLED') OR sport <> UPPER(sport)
        $migration$;
      ELSE
        UPDATE sp_prediction_matches
           SET sport = UPPER(sport),
               status = CASE
                 WHEN UPPER(status) = 'OPEN' THEN 'UPCOMING'
                 WHEN UPPER(status) = 'SETTLED' THEN 'FINISHED'
                 ELSE UPPER(status)
               END;
      END IF;

      FOREACH legacy_column IN ARRAY ARRAY['match_title','team_a','team_b'] LOOP
        IF EXISTS (
          SELECT 1 FROM information_schema.columns
           WHERE table_schema = current_schema()
             AND table_name = 'sp_prediction_matches'
             AND column_name = legacy_column
        ) THEN
          EXECUTE format('ALTER TABLE sp_prediction_matches ALTER COLUMN %I DROP NOT NULL', legacy_column);
        END IF;
      END LOOP;
    END $compat$;

    CREATE UNIQUE INDEX IF NOT EXISTS idx_sp_prediction_provider_match
      ON sp_prediction_matches(sport, provider_match_id)
      WHERE provider_match_id IS NOT NULL;

    ALTER TABLE sp_predictions
      ADD COLUMN IF NOT EXISTS selection_side VARCHAR(1);

    UPDATE sp_predictions
       SET selection_side = selected_side
     WHERE selection_side IS NULL;

    ALTER TABLE sp_predictions
      ALTER COLUMN selected_side DROP NOT NULL;

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

  const isPlayerPredictions = req.query && req.query.module === "gaming-predictions";
  if (isPlayerPredictions) {
    if (!allowMethods(req,res,["GET","POST"])) return;
    const auth=req.headers.authorization||"";
    const token=auth.startsWith("Bearer ")?auth.slice(7):"";
    let player;
    try { player=token?verifyToken(token):null; } catch {}
    if(!player||player.role!=="GAMING_PLAYER"||!player.sub)
      return sendJson(res,401,{ok:false,message:"ParixBet player login required"});
    try {
      const pool=getPool();
      await ensureGamingTables(pool);
      const active=await pool.query("SELECT id FROM sp_game_players WHERE id=$1 AND status='ACTIVE' LIMIT 1",[player.sub]);
      if(!active.rowCount)return sendJson(res,403,{ok:false,message:"Player account is unavailable"});
      if(req.method==="GET"){
        const result=await pool.query(`
          SELECT m.id,m.sport,m.title,m.side_a,m.side_b,m.scheduled_at,m.status,m.result_side,m.result_label,
                 p.selection_side AS my_selection
          FROM sp_prediction_matches m
          LEFT JOIN sp_predictions p ON p.match_id=m.id AND p.player_id=$1
          ORDER BY CASE WHEN m.status='FINISHED' THEN 1 ELSE 0 END,m.scheduled_at ASC NULLS LAST,m.id DESC
          LIMIT 40
        `,[player.sub]);
        return sendJson(res,200,{ok:true,matches:result.rows});
      }
      const body=req.body||{},matchId=Number(body.match_id),side=String(body.selection_side||"").toUpperCase();
      if(!Number.isSafeInteger(matchId)||matchId<1||!["A","B"].includes(side))
        return sendJson(res,400,{ok:false,message:"Choose a match and side"});
      const client=await pool.connect();
      let saved;
      try {
        await client.query("BEGIN");
        const match=await client.query("SELECT id FROM sp_prediction_matches WHERE id=$1 AND status='UPCOMING' FOR UPDATE",[matchId]);
        if(!match.rowCount){
          await client.query("ROLLBACK");
          return sendJson(res,409,{ok:false,message:"This match is locked, finished, cancelled, or unavailable for predictions"});
        }
        const result=await client.query(
          "INSERT INTO sp_predictions(match_id,player_id,selection_side) VALUES($1,$2,$3) ON CONFLICT(match_id,player_id) DO UPDATE SET selection_side=EXCLUDED.selection_side,created_at=NOW() RETURNING id,match_id,selection_side,created_at",
          [matchId,player.sub,side]
        );
        saved=result.rows[0];
        await client.query("INSERT INTO sp_prediction_audit_logs(match_id,event_type,event_note,event_data) VALUES($1,'PREDICTION_SAVED','Player saved or updated a match prediction',$2::jsonb)",[matchId,JSON.stringify({player_id:Number(player.sub),selection_side:side})]);
        await client.query("COMMIT");
      } catch(transactionError) {
        await client.query("ROLLBACK").catch(()=>{});
        throw transactionError;
      } finally {
        client.release();
      }
      return sendJson(res,200,{ok:true,prediction:saved,message:"Prediction saved."});
    } catch(error) {
      console.error("ParixBet player prediction error:",error.message);
      return sendJson(res,500,{ok:false,message:"Prediction could not be saved"});
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
          const monitorSettings = await pool.query("SELECT min_predictions,imbalance_threshold_pct,updated_at FROM sp_prediction_monitor_settings WHERE id=1");
          const monitorConfig = monitorSettings.rows[0] || {min_predictions:5,imbalance_threshold_pct:60};
          const minPredictions = Number(monitorConfig.min_predictions);
          const imbalanceThreshold = Number(monitorConfig.imbalance_threshold_pct);
          const [matches,exposureTotals,virtualReserve,settlements,audit] = await Promise.all([
            pool.query(`
              SELECT m.id,m.title,m.sport,m.side_a,m.side_b,m.status,m.result_side,m.result_label,m.result_source,
                     COUNT(p.id)::int AS prediction_count,
                     COUNT(p.id) FILTER (WHERE p.selection_side='A')::int AS side_a_count,
                     COUNT(p.id) FILTER (WHERE p.selection_side='B')::int AS side_b_count,
                     COUNT(p.id) FILTER (WHERE p.selection_side=m.result_side)::int AS correct_count
              FROM sp_prediction_matches m LEFT JOIN sp_predictions p ON p.match_id=m.id
              GROUP BY m.id ORDER BY m.updated_at DESC,m.id DESC LIMIT 50
            `),
            pool.query(`
              SELECT COALESCE(SUM(prediction_count),0)::bigint AS total_predictions,
                     COUNT(*) FILTER (
                       WHERE prediction_count >= $1
                         AND GREATEST(side_a_count,side_b_count) * 100.0 / NULLIF(prediction_count,0) >= $2
                     )::int AS unbalanced_matches
              FROM (
                SELECT m.id,COUNT(p.id)::int AS prediction_count,
                       COUNT(p.id) FILTER (WHERE p.selection_side='A')::int AS side_a_count,
                       COUNT(p.id) FILTER (WHERE p.selection_side='B')::int AS side_b_count
                FROM sp_prediction_matches m LEFT JOIN sp_predictions p ON p.match_id=m.id
                GROUP BY m.id
              ) AS all_match_counts
            `,[minPredictions,imbalanceThreshold]),
            pool.query("SELECT COUNT(*)::int AS wallet_count,COALESCE(SUM(virtual_coins),0)::bigint AS virtual_points FROM sp_game_wallets"),
            pool.query("SELECT COUNT(*)::int AS settled_matches,COALESCE(SUM(prediction_count),0)::bigint AS predictions,COALESCE(SUM(correct_count),0)::bigint AS correct,COALESCE(SUM(incorrect_count),0)::bigint AS incorrect,COALESCE(SUM(void_count),0)::bigint AS void FROM sp_prediction_settlements"),
            pool.query("SELECT id,match_id,event_type,event_note,event_data,created_at FROM sp_prediction_audit_logs ORDER BY created_at DESC LIMIT 20")
          ]);
          const rows=matches.rows.map(m=>{
            const total=Number(m.prediction_count||0),a=Number(m.side_a_count||0),b=Number(m.side_b_count||0);
            return {...m,side_a_count:a,side_b_count:b,imbalance_percent:total?Math.round(Math.max(a,b)*100/total):0};
          });
          return sendJson(res,200,{ok:true,monitoring:{
            exposure:{matches:rows,total_predictions:String(exposureTotals.rows[0].total_predictions||0),unbalanced_matches:Number(exposureTotals.rows[0].unbalanced_matches||0)},
            liquidity:{wallet_count:virtualReserve.rows[0].wallet_count,virtual_points:String(virtualReserve.rows[0].virtual_points),unit:"virtual points only"},
            reserve:{virtual_points:String(virtualReserve.rows[0].virtual_points),unit:"virtual points only",cash_value:0},
            settlement:{...settlements.rows[0],recent:audit.rows},
            alert_settings:{min_predictions:minPredictions,imbalance_threshold_pct:imbalanceThreshold,updated_at:monitorConfig.updated_at||null}
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
      const action = body.action || "";

      if (req.method === "POST" && action === "update_monitor_settings") {
        const minPred = Number(body.min_predictions);
        const thresh = Number(body.imbalance_threshold_pct);
        if (!Number.isInteger(minPred) || minPred < 1 || minPred > 10000 || !Number.isFinite(thresh) || thresh < 50 || thresh > 95) {
          return sendJson(res, 400, { ok: false, message: "Invalid alert settings values" });
        }
        await pool.query(
          "UPDATE sp_prediction_monitor_settings SET min_predictions=$1,imbalance_threshold_pct=$2,updated_at=NOW() WHERE id=1",
          [minPred, thresh]
        );
        return sendJson(res, 200, { ok: true, message: `Saved: ${minPred}+ predictions and ${thresh}% threshold.` });
      }

      if (req.method === "POST" && action === "create_prediction_match") {
        const sport = String(body.sport || "CRICKET").toUpperCase();
        const title = String(body.title || "").trim();
        const sideA = String(body.side_a || "").trim();
        const sideB = String(body.side_b || "").trim();
        const scheduledAt = body.scheduled_at ? new Date(body.scheduled_at).toISOString() : null;
        if (!["CRICKET", "FOOTBALL", "OTHER"].includes(sport) || !title || !sideA || !sideB) {
          return sendJson(res, 400, { ok: false, message: "Sport, title, Side A, and Side B are required." });
        }
        const ins = await pool.query(
          "INSERT INTO sp_prediction_matches(sport,title,side_a,side_b,scheduled_at,status) VALUES($1,$2,$3,$4,$5,'UPCOMING') RETURNING *",
          [sport, title, sideA, sideB, scheduledAt]
        );
        await pool.query(
          "INSERT INTO sp_prediction_audit_logs(match_id,event_type,event_note) VALUES($1,'MATCH_CREATED',$2)",
          [ins.rows[0].id, `Admin created match: ${title}`]
        );
        return sendJson(res, 201, { ok: true, match: ins.rows[0] });
      }

      if (req.method === "PATCH" && action === "prediction_match_status") {
        const matchId = Number(body.match_id);
        const status = String(body.status || "").toUpperCase();
        if (!Number.isSafeInteger(matchId) || !["UPCOMING", "LOCKED"].includes(status)) {
          return sendJson(res, 400, { ok: false, message: "Invalid match or status" });
        }
        const upd = await pool.query(
          "UPDATE sp_prediction_matches SET status=$1,updated_at=NOW() WHERE id=$2 AND result_side IS NULL RETURNING *",
          [status, matchId]
        );
        if (!upd.rowCount) return sendJson(res, 404, { ok: false, message: "Match not found or already settled" });
        await pool.query(
          "INSERT INTO sp_prediction_audit_logs(match_id,event_type,event_note) VALUES($1,'MATCH_STATUS',$2)",
          [matchId, `Match status changed to ${status}`]
        );
        return sendJson(res, 200, { ok: true, message: `Match ${status === "LOCKED" ? "locked" : "reopened"}.` });
      }

      if (req.method === "POST" && action === "manual_match_result") {
        const matchId = Number(body.match_id);
        const resultSide = String(body.result_side || "").toUpperCase();
        if (!Number.isSafeInteger(matchId) || !["A", "B", "D"].includes(resultSide)) {
          return sendJson(res, 400, { ok: false, message: "Invalid match or result side" });
        }
        const client = await pool.connect();
        try {
          await client.query("BEGIN");
          const mRes = await client.query("SELECT * FROM sp_prediction_matches WHERE id=$1 FOR UPDATE", [matchId]);
          if (!mRes.rowCount) {
            await client.query("ROLLBACK");
            return sendJson(res, 404, { ok: false, message: "Match not found" });
          }
          const m = mRes.rows[0];
          const label = resultSide === "A" ? m.side_a : (resultSide === "B" ? m.side_b : "Draw / No Result");

          await client.query(
            "UPDATE sp_prediction_matches SET status='FINISHED',result_side=$1,result_label=$2,result_source='MANUAL',updated_at=NOW() WHERE id=$3",
            [resultSide, label, matchId]
          );

          const counts = await client.query(`
            SELECT COUNT(*)::int AS total,
                   COALESCE(SUM(CASE WHEN selection_side=$1 THEN 1 ELSE 0 END),0)::int AS correct
            FROM sp_predictions WHERE match_id=$2
          `, [resultSide, matchId]);

          const total = counts.rows[0].total;
          const correct = ["A", "B"].includes(resultSide) ? counts.rows[0].correct : 0;
          const incorrect = ["A", "B"].includes(resultSide) ? (total - correct) : 0;
          const voidCount
