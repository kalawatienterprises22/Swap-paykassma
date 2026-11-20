const { getPool } = require("./_lib/db");
const { sendJson, allowMethods } = require("./_lib/http");
const { verifyToken } = require("./_lib/auth");
const bcrypt = require("bcryptjs");

const RISK_TIER_CONFIG = {
  1: { label: "1 · Low", reservePct: 5, weight: 1.0 },
  2: { label: "2 · Moderate", reservePct: 8, weight: 1.15 },
  3: { label: "3 · Standard", reservePct: 10, weight: 1.3 },
  4: { label: "4 · Elevated", reservePct: 15, weight: 1.5 },
  5: { label: "5 · High", reservePct: 20, weight: 1.8 }
};

function computeEngineMetrics({ mode, tier, picksA, picksB, winnerSide }) {
  const safeTier = RISK_TIER_CONFIG[Number(tier)] ? Number(tier) : 3;
  const tierCfg = RISK_TIER_CONFIG[safeTier];
  const safeMode = ["SCORE_POOL", "DIFFICULTY", "MATCH_CENTRE"].includes(String(mode || "").toUpperCase())
    ? String(mode).toUpperCase()
    : "SCORE_POOL";

  const a = Math.max(0, Number(picksA || 0));
  const b = Math.max(0, Number(picksB || 0));
  const total = a + b;
  const side = winnerSide === "A" || winnerSide === "B" ? winnerSide : null;
  const winningPicks = side === "A" ? a : (side === "B" ? b : 0);
  const losingPicks = side ? Math.max(0, total - winningPicks) : 0;

  let multiplier = 1.0;
  if (safeMode === "SCORE_POOL") {
    if (total > 0 && winningPicks > 0) {
      const rawPoolMult = total / winningPicks;
      multiplier = Number(Math.min(3.5, Math.max(1.05, rawPoolMult)).toFixed(2));
    } else {
      multiplier = 1.0;
    }
  } else if (safeMode === "DIFFICULTY") {
    multiplier = Number((tierCfg.weight * 1.1).toFixed(2));
  } else if (safeMode === "MATCH_CENTRE") {
    const shareFactor = total > 0 ? (winningPicks / total) : 0.5;
    multiplier = Number(Math.max(1.0, (1.25 + (1 - shareFactor) * tierCfg.weight)).toFixed(2));
  }

  const effectiveScore = Number((winningPicks * multiplier * 10).toFixed(2));
  const exposureUnits = Number((total * tierCfg.weight).toFixed(2));

  return {
    mode: safeMode,
    riskTier: safeTier,
    tierLabel: tierCfg.label,
    reservePct: tierCfg.reservePct,
    tierWeight: tierCfg.weight,
    picksA: a,
    picksB: b,
    totalPicks: total,
    winnerSide: side,
    winningPicks,
    losingPicks,
    multiplier,
    effectiveScore,
    exposureUnits
  };
}

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
      CREATE TABLE IF NOT EXISTS sp_game_reserve (
        id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id=1),
        reserve_balance NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK (reserve_balance >= 0),
        currency CHAR(3) NOT NULL DEFAULT 'INR',
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      INSERT INTO sp_game_reserve(id,reserve_balance,currency)
      VALUES(1,0,'INR') ON CONFLICT(id) DO NOTHING;
      CREATE TABLE IF NOT EXISTS sp_game_reserve_ledger (
        id BIGSERIAL PRIMARY KEY,
        entry_type VARCHAR(24) NOT NULL CHECK (entry_type IN ('DEPOSIT','WITHDRAW','SET_BALANCE')),
        amount NUMERIC(14,2) NOT NULL CHECK (amount >= 0),
        balance_after NUMERIC(14,2) NOT NULL CHECK (balance_after >= 0),
        note VARCHAR(240) NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS sp_settlement_engine_sessions (
        id BIGSERIAL PRIMARY KEY,
        engine_mode VARCHAR(30) NOT NULL DEFAULT 'SCORE_POOL',
        risk_tier SMALLINT NOT NULL DEFAULT 3 CHECK (risk_tier BETWEEN 1 AND 5),
        label_a VARCHAR(80) NOT NULL DEFAULT 'Team / Player A',
        label_b VARCHAR(80) NOT NULL DEFAULT 'Team / Player B',
        picks_a INTEGER NOT NULL DEFAULT 0 CHECK (picks_a >= 0),
        picks_b INTEGER NOT NULL DEFAULT 0 CHECK (picks_b >= 0),
        status VARCHAR(20) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','SETTLED','ARCHIVED')),
        winner_side VARCHAR(1) CHECK (winner_side IN ('A','B')),
        winning_picks INTEGER NOT NULL DEFAULT 0 CHECK (winning_picks >= 0),
        multiplier NUMERIC(8,2) NOT NULL DEFAULT 1.00,
        effective_score NUMERIC(14,2) NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        settled_at TIMESTAMPTZ
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
        ('AVIATOR_FLIGHT','Aviator Flight Challenge','Plane flight timing challenge',TRUE),
        ('CARD_MEMORY','Card Memory Match','Match identical cards',TRUE)
      ON CONFLICT(game_code) DO NOTHING;
    `);
  })().catch((err) => {
    tablesReadyPromise = null;
    throw err;
  });

  return tablesReadyPromise;
}

async function getOrCreateActiveEngineSession(client) {
  const existing = await client.query(
    "SELECT * FROM sp_settlement_engine_sessions WHERE status='OPEN' ORDER BY id DESC LIMIT 1 FOR UPDATE"
  );
  if (existing.rows[0]) return existing.rows[0];
  const created = await client.query(
    `INSERT INTO sp_settlement_engine_sessions(engine_mode,risk_tier,label_a,label_b,picks_a,picks_b,status)
     VALUES('SCORE_POOL',3,'Team / Player A','Team / Player B',0,0,'OPEN')
     RETURNING *`
  );
  return created.rows[0];
}

function formatEngineSessionResponse(row) {
  const metrics = computeEngineMetrics({
    mode: row.engine_mode,
    tier: row.risk_tier,
    picksA: row.picks_a,
    picksB: row.picks_b,
    winnerSide: row.winner_side
  });
  return {
    id: row.id,
    engine_mode: row.engine_mode,
    risk_tier: Number(row.risk_tier),
    label_a: row.label_a,
    label_b: row.label_b,
    picks_a: Number(row.picks_a || 0),
    picks_b: Number(row.picks_b || 0),
    total_picks: metrics.totalPicks,
    status: row.status,
    winner_side: row.winner_side,
    winning_picks: row.status === "SETTLED" ? Number(row.winning_picks || 0) : metrics.winningPicks,
    losing_picks: metrics.losingPicks,
    multiplier: row.status === "SETTLED" ? Number(row.multiplier || metrics.multiplier) : metrics.multiplier,
    effective_score: row.status === "SETTLED" ? Number(row.effective_score || metrics.effectiveScore) : metrics.effectiveScore,
    reserve_pct: metrics.reservePct,
    tier_label: metrics.tierLabel,
    exposure_units: metrics.exposureUnits,
    created_at: row.created_at,
    settled_at: row.settled_at
  };
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

  if (mod === "gaming") {
    if (!allowMethods(req, res, ["GET", "POST", "PATCH"])) return;
    if (!getGamingAdmin(req, res)) return;

    try {
      const pool = getPool();
      await ensureGamingTables(pool);
      const action = String((req.method === "GET" ? req.query?.action : req.body?.action) || "");
      const body = req.body || {};

      if (req.method === "GET" && action === "stats") {
        const [pRes, gRes, cRes, rRes] = await Promise.all([
          pool.query("SELECT COUNT(*)::int AS total FROM sp_game_players"),
          pool.query("SELECT COUNT(*)::int AS total FROM sp_game_sessions"),
          pool.query("SELECT COALESCE(SUM(virtual_coins),0)::bigint AS total FROM sp_game_wallets"),
          pool.query("SELECT COALESCE(reserve_balance,0)::numeric(14,2) AS balance FROM sp_game_reserve WHERE id=1")
        ]);
        return sendJson(res, 200, {
          ok: true,
          stats: {
            players: pRes.rows[0].total,
            games: gRes.rows[0].total,
            coins: Number(cRes.rows[0].total),
            reserve_balance: Number(rRes.rows[0]?.balance || 0)
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
          return sendJson(res, 200, { ok: true, source: "Sportmonks", cached: false, matches: [] });
        }
        const cached = await pool.query("SELECT payload,fetched_at FROM sp_game_cricket_cache WHERE cache_key='cricket-livescores' LIMIT 1");
        if (cached.rows[0] && Date.now() - new Date(cached.rows[0].fetched_at).getTime() < 30000) {
          return sendJson(res, 200, { ok: true, source: "Sportmonks", cached: true, matches: cached.rows[0].payload });
        }
        const resp = await fetch("https://cricket.sportmonks.com/api/v2.0/livescores?api_token=" + encodeURIComponent(apiKey), { headers: { Accept: "application/json" } });
        if (!resp.ok) throw new Error("Cricket API HTTP " + resp.status);
        const payload = await resp.json();
        const matches = Array.isArray(payload.data) ? payload.data : [];
        await pool.query(
          "INSERT INTO sp_game_cricket_cache(cache_key,payload,fetched_at) VALUES('cricket-livescores',$1::jsonb,NOW()) ON CONFLICT(cache_key) DO UPDATE SET payload=EXCLUDED.payload,fetched_at=NOW()",
          [JSON.stringify(matches)]
        );
        return sendJson(res, 200, { ok: true, source: "Sportmonks", cached: false, matches });
      }

      if (req.method === "GET" && action === "prediction_matches") {
        const r = await pool.query(`
          SELECT m.*,
                 COALESCE(COUNT(p.id),0)::int AS prediction_count,
                 COALESCE(SUM(CASE WHEN m.result_side IN ('A','B') AND p.selection_side=m.result_side THEN 1 ELSE 0 END),0)::int AS correct_count
          FROM sp_prediction_matches m
          LEFT JOIN sp_predictions p ON p.match_id=m.id
          GROUP BY m.id
          ORDER BY m.id DESC LIMIT 60
        `);
        return sendJson(res, 200, { ok: true, matches: r.rows });
      }

      if (req.method === "GET" && action === "engine_session") {
        const client = await pool.connect();
        try {
          await client.query("BEGIN");
          const row = await getOrCreateActiveEngineSession(client);
          await client.query("COMMIT");
          return sendJson(res, 200, { ok: true, session: formatEngineSessionResponse(row) });
        } catch (err) {
          await client.query("ROLLBACK").catch(() => {});
          throw err;
        } finally {
          client.release();
        }
      }

      if (req.method === "POST" && action === "engine_pick") {
        const side = String(body.selection_side || "").toUpperCase();
        if (!["A", "B"].includes(side)) {
          return sendJson(res, 400, { ok: false, message: "Select Side A or Side B" });
        }
        const mode = ["SCORE_POOL", "DIFFICULTY", "MATCH_CENTRE"].includes(String(body.engine_mode || "").toUpperCase())
          ? String(body.engine_mode).toUpperCase()
          : "SCORE_POOL";
        const tier = RISK_TIER_CONFIG[Number(body.risk_tier)] ? Number(body.risk_tier) : 3;
        const labelA = String(body.label_a || "Team / Player A").trim().slice(0, 80) || "Team / Player A";
        const labelB = String(body.label_b || "Team / Player B").trim().slice(0, 80) || "Team / Player B";

        const client = await pool.connect();
        try {
          await client.query("BEGIN");
          const current = await getOrCreateActiveEngineSession(client);
          const total = Number(current.picks_a || 0) + Number(current.picks_b || 0);
          if (total >= 500) {
            await client.query("ROLLBACK");
            return sendJson(res, 400, { ok: false, message: "Session limit reached (500 picks). Settle or reset session." });
          }
          const nextA = Number(current.picks_a || 0) + (side === "A" ? 1 : 0);
          const nextB = Number(current.picks_b || 0) + (side === "B" ? 1 : 0);
          const upd = await client.query(
            `UPDATE sp_settlement_engine_sessions
                SET engine_mode=$1, risk_tier=$2, label_a=$3, label_b=$4, picks_a=$5, picks_b=$6
              
