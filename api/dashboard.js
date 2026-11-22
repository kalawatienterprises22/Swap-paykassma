const { getPool } = require("./_lib/db");
const { sendJson, allowMethods } = require("./_lib/http");
const bcrypt = require("bcryptjs");
const { createToken, verifyToken } = require("./_lib/auth");

const RISK_TIER_CONFIG = {
  1: { label: "1 · Low", reservePct: 5, weight: 1.0 },
  2: { label: "2 · Moderate", reservePct: 8, weight: 1.15 },
  3: { label: "3 · Standard", reservePct: 10, weight: 1.3 },
  4: { label: "4 · Elevated", reservePct: 15, weight: 1.5 },
  5: { label: "5 · High", reservePct: 20, weight: 1.8 }
};

function signPlayerToken(payload) {
  return createToken({
    id: payload.sub,
    user_id: payload.username,
    role: payload.role
  });
}

function readPlayerAuth(req) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return null;

  try {
    const user = verifyToken(token);
    if (user && user.role === "GAMING_PLAYER" && user.sub) return user;
  } catch {}

  return null;
}

function computeEngineMetrics({ mode, tier, picksA, picksB, winnerSide }) {
  const safeTier = RISK_TIER_CONFIG[Number(tier)] ? Number(tier) : 3;
  const tierCfg = RISK_TIER_CONFIG[safeTier];
  const safeMode = ["SCORE_POOL", "DIFFICULTY", "MATCH_CENTRE"].includes(String(mode || "").toUpperCase())
    ? String(mode).toUpperCase() : "SCORE_POOL";

  const a = Math.max(0, Number(picksA || 0));
  const b = Math.max(0, Number(picksB || 0));
  const total = a + b;
  const side = winnerSide === "A" || winnerSide === "B" ? winnerSide : null;
  const winningPicks = side === "A" ? a : (side === "B" ? b : 0);
  const losingPicks = side ? Math.max(0, total - winningPicks) : 0;

  let multiplier = 1.0;
  if (safeMode === "SCORE_POOL") {
    if (total > 0 && winningPicks > 0) {
      multiplier = Number(Math.min(3.5, Math.max(1.05, total / winningPicks)).toFixed(2));
    }
  } else if (safeMode === "DIFFICULTY") {
    multiplier = Number((tierCfg.weight * 1.1).toFixed(2));
  } else if (safeMode === "MATCH_CENTRE") {
    const shareFactor = total > 0 ? (winningPicks / total) : 0.5;
    multiplier = Number(Math.max(1.0, (1.25 + (1 - shareFactor) * tierCfg.weight)).toFixed(2));
  }

  return {
    mode: safeMode, riskTier: safeTier, tierLabel: tierCfg.label,
    reservePct: tierCfg.reservePct, tierWeight: tierCfg.weight,
    picksA: a, picksB: b, totalPicks: total, winnerSide: side,
    winningPicks, losingPicks, multiplier,
    effectiveScore: Number((winningPicks * multiplier * 10).toFixed(2)),
    exposureUnits: Number((total * tierCfg.weight).toFixed(2))
  };
}

let tablesReadyPromise = null;

async function ensureGamingTables(pool) {
  if (tablesReadyPromise) return tablesReadyPromise;
  tablesReadyPromise = (async () => {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS sp_game_players (
        id BIGSERIAL PRIMARY KEY, username VARCHAR(40) NOT NULL UNIQUE,
        display_name VARCHAR(100) NOT NULL, email VARCHAR(140), phone VARCHAR(30),
        password_hash TEXT NOT NULL,
        status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','SUSPENDED')),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      ALTER TABLE sp_game_players ADD COLUMN IF NOT EXISTS email VARCHAR(140);
      ALTER TABLE sp_game_players ADD COLUMN IF NOT EXISTS phone VARCHAR(30);
      CREATE TABLE IF NOT EXISTS sp_game_wallets (
        player_id BIGINT PRIMARY KEY REFERENCES sp_game_players(id) ON DELETE CASCADE,
        virtual_coins BIGINT NOT NULL DEFAULT 1000 CHECK (virtual_coins >= 0),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS sp_game_sessions (
        id BIGSERIAL PRIMARY KEY, player_id BIGINT NOT NULL REFERENCES sp_game_players(id) ON DELETE CASCADE,
        game_code VARCHAR(40) NOT NULL, result JSONB NOT NULL DEFAULT '{}'::jsonb,
        coins_change BIGINT NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS sp_game_coin_ledger (
        id BIGSERIAL PRIMARY KEY, player_id BIGINT NOT NULL REFERENCES sp_game_players(id) ON DELETE CASCADE,
        amount BIGINT NOT NULL, entry_type VARCHAR(24) NOT NULL, note VARCHAR(240),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS sp_game_cricket_cache (
        cache_key VARCHAR(40) PRIMARY KEY, payload JSONB NOT NULL,
        fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS sp_prediction_matches (
        id BIGSERIAL PRIMARY KEY, sport VARCHAR(20) NOT NULL DEFAULT 'CRICKET',
        provider_match_id VARCHAR(100), title VARCHAR(200) NOT NULL,
        side_a VARCHAR(100) NOT NULL, side_b VARCHAR(100) NOT NULL,
        odds_a NUMERIC(6,2) NOT NULL DEFAULT 1.90, odds_b NUMERIC(6,2) NOT NULL DEFAULT 1.90,
        scheduled_at TIMESTAMPTZ, status VARCHAR(20) NOT NULL DEFAULT 'UPCOMING',
        result_side VARCHAR(1), result_label VARCHAR(100), result_source VARCHAR(20),
        result_data JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(sport,provider_match_id)
      );
      ALTER TABLE sp_prediction_matches ADD COLUMN IF NOT EXISTS odds_a NUMERIC(6,2) NOT NULL DEFAULT 1.90;
      ALTER TABLE sp_prediction_matches ADD COLUMN IF NOT EXISTS odds_b NUMERIC(6,2) NOT NULL DEFAULT 1.90;
      CREATE TABLE IF NOT EXISTS sp_predictions (
        id BIGSERIAL PRIMARY KEY,
        match_id BIGINT NOT NULL REFERENCES sp_prediction_matches(id) ON DELETE CASCADE,
        player_id BIGINT NOT NULL REFERENCES sp_game_players(id) ON DELETE CASCADE,
        selection_side VARCHAR(1) NOT NULL CHECK (selection_side IN ('A','B')),
        stake_amount BIGINT NOT NULL DEFAULT 100 CHECK (stake_amount >= 0),
        payout_amount BIGINT NOT NULL DEFAULT 0,
        settled BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(match_id,player_id)
      );
      ALTER TABLE sp_predictions ADD COLUMN IF NOT EXISTS stake_amount BIGINT NOT NULL DEFAULT 100;
      ALTER TABLE sp_predictions ADD COLUMN IF NOT EXISTS payout_amount BIGINT NOT NULL DEFAULT 0;
      ALTER TABLE sp_predictions ADD COLUMN IF NOT EXISTS settled BOOLEAN NOT NULL DEFAULT FALSE;
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
        prediction_count INTEGER NOT NULL DEFAULT 0, correct_count INTEGER NOT NULL DEFAULT 0,
        incorrect_count INTEGER NOT NULL DEFAULT 0, void_count INTEGER NOT NULL DEFAULT 0,
        result_side VARCHAR(1), result_source VARCHAR(20), settled_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS sp_prediction_audit_logs (
        id BIGSERIAL PRIMARY KEY, match_id BIGINT REFERENCES sp_prediction_matches(id) ON DELETE SET NULL,
        event_type VARCHAR(40) NOT NULL, event_note VARCHAR(240) NOT NULL DEFAULT '',
        event_data JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS sp_game_reserve (
        id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id=1),
        reserve_balance NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK (reserve_balance >= 0),
        currency CHAR(3) NOT NULL DEFAULT 'INR', updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      INSERT INTO sp_game_reserve(id,reserve_balance,currency) VALUES(1,0,'INR') ON CONFLICT(id) DO NOTHING;
      CREATE TABLE IF NOT EXISTS sp_game_reserve_ledger (
        id BIGSERIAL PRIMARY KEY,
        entry_type VARCHAR(24) NOT NULL CHECK (entry_type IN ('DEPOSIT','WITHDRAW','SET_BALANCE')),
        amount NUMERIC(14,2) NOT NULL CHECK (amount >= 0),
        balance_after NUMERIC(14,2) NOT NULL CHECK (balance_after >= 0),
        note VARCHAR(240) NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS sp_settlement_engine_sessions (
        id BIGSERIAL PRIMARY KEY, engine_mode VARCHAR(30) NOT NULL DEFAULT 'SCORE_POOL',
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
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), settled_at TIMESTAMPTZ
      );
      CREATE TABLE IF NOT EXISTS sp_game_settings (
        game_code VARCHAR(40) PRIMARY KEY, title VARCHAR(100) NOT NULL,
        description VARCHAR(240) NOT NULL DEFAULT '', enabled BOOLEAN NOT NULL DEFAULT FALSE,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      INSERT INTO sp_game_settings(game_code,title,description,enabled) VALUES
        ('TAP_CHALLENGE','Tap Speed Challenge','10-second reaction and tapping game',TRUE),
        ('CRICKET_CENTRE','Cricket Centre','Cricket live scores, fixtures & match odds',TRUE),
        ('FOOTBALL_CENTRE','Football Centre','Football live scores, fixtures & match odds',TRUE),
        ('TENNIS_CENTRE','Tennis Arena','ATP/WTA match centre & winner picks',TRUE),
        ('BASKETBALL_CENTRE','Basketball Court','NBA & international basketball markets',TRUE),
        ('ESPORTS_CENTRE','Esports Hub','CS2, Dota 2 & Valorant match markets',TRUE),
        ('KABADDI_CENTRE','Kabaddi Pro League','Pro Kabaddi live fixtures & picks',TRUE),
        ('AVIATOR_FLIGHT','Aviator Flight Challenge','Crash multiplier flight timing game',TRUE),
        ('CARD_MEMORY','Card Memory Match','Fast card matching multiplier game',TRUE)
      ON CONFLICT(game_code) DO NOTHING;
    `);
  })().catch((err) => { tablesReadyPromise = null; throw err; });
  return tablesReadyPromise;
}

async function getOrCreateActiveEngineSession(client) {
  const existing = await client.query(
    "SELECT * FROM sp_settlement_engine_sessions WHERE status='OPEN' ORDER BY id DESC LIMIT 1 FOR UPDATE"
  );
  if (existing.rows[0]) return existing.rows[0];
  const created = await client.query(
    `INSERT INTO sp_settlement_engine_sessions(engine_mode,risk_tier,label_a,label_b,picks_a,picks_b,status)
     VALUES('SCORE_POOL',3,'Team / Player A','Team / Player B',0,0,'OPEN') RETURNING *`
  );
  return created.rows[0];
}

function formatEngineSessionResponse(row) {
  const m = computeEngineMetrics({
    mode: row.engine_mode, tier: row.risk_tier,
    picksA: row.picks_a, picksB: row.picks_b, winnerSide: row.winner_side
  });
  return {
    id: row.id, engine_mode: row.engine_mode, risk_tier: Number(row.risk_tier),
    label_a: row.label_a, label_b: row.label_b,
    picks_a: Number(row.picks_a || 0), picks_b: Number(row.picks_b || 0),
    total_picks: m.totalPicks, status: row.status, winner_side: row.winner_side,
    winning_picks: row.status === "SETTLED" ? Number(row.winning_picks || 0) : m.winningPicks,
    losing_picks: m.losingPicks,
    multiplier: row.status === "SETTLED" ? Number(row.multiplier || m.multiplier) : m.multiplier,
    effective_score: row.status === "SETTLED" ? Number(row.effective_score || m.effectiveScore) : m.effectiveScore,
    reserve_pct: m.reservePct, tier_label: m.tierLabel, exposure_units: m.exposureUnits,
    created_at: row.created_at, settled_at: row.settled_at
  };
}

async function getGamingAdmin(req, res) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) {
    sendJson(res, 401, { ok: false, message: "ParixBet Admin login required" });
    return null;
  }

  let user;
  try {
    user = verifyToken(token);
  } catch {
    sendJson(res, 401, { ok: false, message: "Invalid or expired ParixBet Admin session" });
    return null;
  }

  if (user.role !== "GAMING_ADMIN" || !user.sub ||
      !Number.isInteger(user.tokenVersion) || user.tokenVersion < 0) {
    sendJson(res, 403, { ok: false, message: "ParixBet Admin access denied" });
    return null;
  }

  try {
    const activeAdmin = await getPool().query(
      `SELECT id, username, token_version
       FROM sp_gaming_admins
       WHERE id = $1 AND status = 'ACTIVE'
       LIMIT 1`,
      [user.sub]
    );
    const adminRecord = activeAdmin.rows[0];
    if (!adminRecord || Number(adminRecord.token_version) !== user.tokenVersion) {
      sendJson(res, 403, { ok: false, message: "ParixBet Admin session has been revoked or account is inactive" });
      return null;
    }
    return user;
  } catch (error) {
    console.error("ParixBet Admin authorization check failed:", error.message);
    sendJson(res, 503, { ok: false, message: "Admin authorization service unavailable" });
    return null;
  }
}

async function getAdmin(req, res) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) { sendJson(res, 401, { ok: false, message: "Authentication required" }); return null; }

  let user;
  try {
    user = verifyToken(token);
  } catch {
    sendJson(res, 401, { ok: false, message: "Invalid or expired session" });
    return null;
  }

  if (user.role !== "SUPER_ADMIN" || !user.sub) {
    sendJson(res, 403, { ok: false, message: "Access denied" });
    return null;
  }

  try {
    const activeAdmin = await getPool().query(
      "SELECT id FROM sp_users WHERE id = $1 AND role = 'SUPER_ADMIN' AND status = 'ACTIVE' LIMIT 1",
      [user.sub]
    );
    if (!activeAdmin.rowCount) {
      sendJson(res, 403, { ok: false, message: "Super Admin account is inactive or unavailable" });
      return null;
    }
    return user;
  } catch (error) {
    console.error("Super Admin authorization check failed:", error.message);
    sendJson(res, 503, { ok: false, message: "Authorization service unavailable" });
    return null;
  }
}
module.exports = async (req, res) => {
  const mod = req.query && req.query.module;

  if (mod === "gaming-auth") {
    if (!allowMethods(req, res, ["POST", "GET"])) return;
    try {
      const pool = getPool();
      await ensureGamingTables(pool);

      if (req.method === "GET") {
        const authPlayer = readPlayerAuth(req);
        if (!authPlayer) return sendJson(res, 401, { ok: false, message: "Player session expired or not logged in" });
        const pRes = await pool.query(
          `SELECT p.id, p.username, p.display_name, p.email, p.phone, p.status, p.created_at,
                  COALESCE(w.virtual_coins, 0)::bigint AS balance
           FROM sp_game_players p
           LEFT JOIN sp_game_wallets w ON w.player_id = p.id
           WHERE p.id = $1 LIMIT 1`,
          [authPlayer.sub]
        );
        if (!pRes.rowCount) return sendJson(res, 404, { ok: false, message: "Player not found" });
        if (pRes.rows[0].status !== "ACTIVE") {
          return sendJson(res, 403, { ok: false, message: "Player account is unavailable" });
        }
        const ledger = await pool.query(
          "SELECT id, amount, entry_type, note, created_at FROM sp_game_coin_ledger WHERE player_id = $1 ORDER BY id DESC LIMIT 15",
          [authPlayer.sub]
        );
        return sendJson(res, 200, { ok: true, player: pRes.rows[0], ledger: ledger.rows });
      }

      const body = req.body || {};
      const authMode = String(body.mode || "LOGIN").toUpperCase();

      if (authMode === "SIGNUP") {
        const username = String(body.username || "").trim().toLowerCase();
        const displayName = String(body.display_name || "").trim();
        const email = String(body.email || "").trim().toLowerCase() || null;
        const phone = String(body.phone || "").trim() || null;
        const password = String(body.password || "");

        if (!/^[a-z0-9_]{4,40}$/.test(username) || displayName.length < 2 || password.length < 8) {
          return sendJson(res, 400, { ok: false, message: "Username (4-40 chars a-z, 0-9, _), display name, and password (8+ chars) required" });
        }

        const passwordHash = await bcrypt.hash(password, 12);
        const client = await pool.connect();
        try {
          await client.query("BEGIN");
          const created = await client.query(
            "INSERT INTO sp_game_players(username,display_name,email,phone,password_hash,status) VALUES($1,$2,$3,$4,$5,'ACTIVE') RETURNING id,username,display_name,email,phone,status,created_at",
            [username, displayName, email, phone, passwordHash]
          );
          const player = created.rows[0];
          await client.query(
            "INSERT INTO sp_game_wallets(player_id,virtual_coins) VALUES($1,1000)",
            [player.id]
          );
          await client.query(
            "INSERT INTO sp_game_coin_ledger(player_id,amount,entry_type,note) VALUES($1,1000,'INITIAL_CREDIT','New player starter virtual points')",
            [player.id]
          );
          await client.query("COMMIT");
          const token = signPlayerToken({ sub: player.id, username: player.username, role: "GAMING_PLAYER" });
          return sendJson(res, 201, {
            ok: true, token,
            player: { ...player, balance: 1000 },
            message: "Account created successfully."
          });
        } catch (e) {
          await client.query("ROLLBACK").catch(() => {});
          if (e.code === "23505") return sendJson(res, 409, { ok: false, message: "Username already exists" });
          throw e;
        } finally {
          client.release();
        }
      }

      if (authMode !== "LOGIN") {
        return sendJson(res, 400, { ok: false, message: "Unsupported authentication mode" });
      }

      const loginId = String(body.login_id || body.username || body.email || "").trim().toLowerCase();
      const password = String(body.password || "");
      if (!loginId || !password) {
        return sendJson(res, 400, { ok: false, message: "Username/email and password required." });
      }

      const r = await pool.query(
        `SELECT p.id, p.username, p.display_name, p.password_hash, p.status,
                COALESCE(w.virtual_coins, 0)::bigint AS balance
         FROM sp_game_players p
         LEFT JOIN sp_game_wallets w ON w.player_id = p.id
         WHERE LOWER(p.username) = $1 OR LOWER(COALESCE(p.email, '')) = $1
         LIMIT 1`,
        [loginId]
      );
      const p = r.rows[0];
      if (!p) return sendJson(res, 401, { ok: false, message: "Invalid credentials" });
      if (p.status !== "ACTIVE") return sendJson(res, 403, { ok: false, message: "Account is suspended" });
      const valid = await bcrypt.compare(password, p.password_hash);
      if (!valid) return sendJson(res, 401, { ok: false, message: "Invalid credentials" });

      const token = signPlayerToken({ sub: p.id, username: p.username, role: "GAMING_PLAYER" });
      return sendJson(res, 200, {
        ok: true, token,
        player: { id: p.id, username: p.username, display_name: p.display_name, status: p.status, balance: Number(p.balance) }
      });
    } catch (err) {
      console.error("Gaming auth error:", err.message);
      return sendJson(res, 500, { ok: false, message: "Authentication service error" });
    }
  }

  if (mod === "gaming-play") {
    if (!allowMethods(req, res, ["POST", "GET"])) return;
    const authPlayer = readPlayerAuth(req);
    if (!authPlayer) return sendJson(res, 401, { ok: false, message: "Player login required" });
    try {
      const pool = getPool();
      await ensureGamingTables(pool);
      const activePlayer = await pool.query(
        "SELECT id FROM sp_game_players WHERE id = $1 AND status = 'ACTIVE' LIMIT 1",
        [authPlayer.sub]
      );
      if (!activePlayer.rowCount) {
        return sendJson(res, 403, { ok: false, message: "Player account is unavailable" });
      }
      const gamesRes = await pool.query("SELECT game_code, title, description, enabled FROM sp_game_settings ORDER BY game_code ASC");
      if (req.method === "GET") {
        const sess = await pool.query(
          "SELECT id, game_code, coins_change, result, created_at FROM sp_game_sessions WHERE player_id = $1 ORDER BY id DESC LIMIT 20",
          [authPlayer.sub]
        );
        return sendJson(res, 200, { ok: true, games: gamesRes.rows, sessions: sess.rows });
      }
      const body = req.body || {};
      const gameCode = String(body.game_code || "").toUpperCase();
      const stake = Math.max(10, Math.min(10000, Number(body.stake || 50)));
      const targetMult = Math.max(1.1, Math.min(10.0, Number(body.multiplier || 1.5)));
      const won = Boolean(body.won);
      const gRow = gamesRes.rows.find(x => x.game_code === gameCode);
      if (!gRow || !gRow.enabled) return sendJson(res, 403, { ok: false, message: "This game is currently disabled" });

      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const pChk = await client.query("SELECT id, status FROM sp_game_players WHERE id = $1 FOR UPDATE", [authPlayer.sub]);
        if (!pChk.rowCount || pChk.rows[0].status !== "ACTIVE") {
          await client.query("ROLLBACK");
          return sendJson(res, 403, { ok: false, message: "Player account unavailable" });
        }
        const wChk = await client.query("SELECT virtual_coins FROM sp_game_wallets WHERE player_id = $1 FOR UPDATE", [authPlayer.sub]);
        const curBal = Number(wChk.rows[0]?.virtual_coins || 0);
        if (curBal < stake) {
          await client.query("ROLLBACK");
          return sendJson(res, 400, { ok: false, message: "Insufficient balance for ₹" + stake + " round" });
        }
        const payout = won ? Math.round(stake * targetMult) : 0;
        const netChange = payout - stake;
        const nextBal = curBal + netChange;
        await client.query("UPDATE sp_game_wallets SET virtual_coins = $1, updated_at = NOW() WHERE player_id = $2", [nextBal, authPlayer.sub]);
        await client.query(
          "INSERT INTO sp_game_sessions(player_id, game_code, result, coins_change) VALUES($1, $2, $3::jsonb, $4)",
          [authPlayer.sub, gameCode, JSON.stringify({ stake, multiplier: targetMult, won, payout, score: body.score || null }), netChange]
        );
        await client.query(
          "INSERT INTO sp_game_coin_ledger(player_id, amount, entry_type, note) VALUES($1, $2, $3, $4)",
          [authPlayer.sub, netChange, won ? "GAME_WIN" : "GAME_LOSS", `${gRow.title}: stake ₹${stake}${won ? ` · won ₹${payout} (${targetMult}x)` : " · round lost"}`]
        );
        await client.query("COMMIT");
        return sendJson(res, 200, {
          ok: true, won, stake, payout, net_change: netChange, balance: nextBal,
          message: won ? `Won ₹${payout} (${targetMult}x) in ${gRow.title}!` : `Round closed (-₹${stake}) in ${gRow.title}.`
        });
      } catch (e) {
        await client.query("ROLLBACK").catch(() => {});
        throw e;
      } finally { client.release(); }
    } catch (err) {
      console.error("Gaming play error:", err.message);
      return sendJson(res, 500, { ok: false, message: "Could not process game round" });
    }
  }
  if (mod === "gaming-football") {
    if (!allowMethods(req, res, ["GET"])) return;
    const player = readPlayerAuth(req);
    if (!player) return sendJson(res, 401, { ok: false, message: "ParixBet player login required" });
    try {
      const pool = getPool();
      await ensureGamingTables(pool);
      const active = await pool.query("SELECT id FROM sp_game_players WHERE id=$1 AND status='ACTIVE' LIMIT 1", [player.sub]);
      if (!active.rowCount) return sendJson(res, 403, { ok: false, message: "Player account is unavailable" });
      const setting = await pool.query("SELECT enabled FROM sp_game_settings WHERE game_code='FOOTBALL_CENTRE' LIMIT 1");
      if (!setting.rows[0]?.enabled) return sendJson(res, 403, { ok: false, message: "Football Centre is currently disabled" });
      const apiKey = process.env.FOOTBALL_API_KEY;
      if (!apiKey) return sendJson(res, 200, { ok: true, connected: false, message: "Football provider key not set; live matches synced from DB.", matches: [], upcoming: [], results: [] });

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
          if (cached.rows[0] && Array.isArray(cached.rows[0].payload)) return cached.rows[0].payload;
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
    const player = readPlayerAuth(req);
    if (!player) return sendJson(res, 401, { ok: false, message: "ParixBet player login required" });
    try {
      const pool = getPool();
      await ensureGamingTables(pool);
      const active = await pool.query("SELECT id FROM sp_game_players WHERE id=$1 AND status='ACTIVE' LIMIT 1", [player.sub]);
      if (!active.rowCount) return sendJson(res, 403, { ok: false, message: "Player account is unavailable" });
      if (req.method === "GET") {
        const result = await pool.query(`
          SELECT m.id,m.sport,m.title,m.side_a,m.side_b,COALESCE(m.odds_a,1.90) AS odds_a,COALESCE(m.odds_b,1.90) AS odds_b,
                 m.scheduled_at,m.status,m.result_side,m.result_label,
                 p.selection_side AS my_selection, p.stake_amount AS my_stake, p.payout_amount AS my_payout, p.settled AS my_settled
          FROM sp_prediction_matches m
          LEFT JOIN sp_predictions p ON p.match_id=m.id AND p.player_id=$1
          ORDER BY CASE WHEN m.status='FINISHED' THEN 1 ELSE 0 END,m.scheduled_at ASC NULLS LAST,m.id DESC
          LIMIT 60
        `, [player.sub]);
        return sendJson(res, 200, { ok: true, matches: result.rows });      }
      const body = req.body || {};
      const matchId = Number(body.match_id);
      const side = String(body.selection_side || "").toUpperCase();
      const stake = Math.max(0, Math.min(50000, Number(body.stake_amount || 100)));
      if (!Number.isSafeInteger(matchId) || matchId < 1 || !["A", "B"].includes(side)) {
        return sendJson(res, 400, { ok: false, message: "Choose a match and side" });
      }
      const client = await pool.connect();
      let saved, nextBal;
      try {
        await client.query("BEGIN");
        const match = await client.query("SELECT id, title, status FROM sp_prediction_matches WHERE id=$1 AND status='UPCOMING' FOR UPDATE", [matchId]);
        if (!match.rowCount) {
          await client.query("ROLLBACK");
          return sendJson(res, 409, { ok: false, message: "This match is locked, finished, cancelled, or unavailable for predictions" });
        }
        const prevPick = await client.query("SELECT stake_amount FROM sp_predictions WHERE match_id=$1 AND player_id=$2 FOR UPDATE", [matchId, player.sub]);
        const prevStake = Number(prevPick.rows[0]?.stake_amount || 0);
        const diff = stake - prevStake;
        const wRes = await client.query("SELECT virtual_coins FROM sp_game_wallets WHERE player_id=$1 FOR UPDATE", [player.sub]);
        const curBal = Number(wRes.rows[0]?.virtual_coins || 0);
        if (diff > 0 && curBal < diff) {
          await client.query("ROLLBACK");
          return sendJson(res, 400, { ok: false, message: "Insufficient wallet balance for ₹" + diff + " stake" });
        }
        nextBal = curBal - diff;
        await client.query("UPDATE sp_game_wallets SET virtual_coins=$1, updated_at=NOW() WHERE player_id=$2", [nextBal, player.sub]);
        if (diff !== 0) {
          await client.query(
            "INSERT INTO sp_game_coin_ledger(player_id, amount, entry_type, note) VALUES($1, $2, $3, $4)",
            [player.sub, -diff, diff > 0 ? "PREDICTION_STAKE" : "STAKE_REFUND", `Match #${matchId} (${match.rows[0].title}) Side ${side}`]
          );
        }
        const result = await client.query(
          `INSERT INTO sp_predictions(match_id,player_id,selection_side,stake_amount) VALUES($1,$2,$3,$4)
           ON CONFLICT(match_id,player_id) DO UPDATE SET selection_side=EXCLUDED.selection_side,stake_amount=EXCLUDED.stake_amount,created_at=NOW()
           RETURNING id,match_id,selection_side,stake_amount,created_at`,
          [matchId, player.sub, side, stake]
        );
        saved = result.rows[0];
        await client.query(
          "INSERT INTO sp_prediction_audit_logs(match_id,event_type,event_note,event_data) VALUES($1,'PREDICTION_SAVED','Player saved match pick & stake',$2::jsonb)",
          [matchId, JSON.stringify({ player_id: Number(player.sub), selection_side: side, stake_amount: stake })]
        );
        await client.query("COMMIT");
      } catch (transactionError) {
        await client.query("ROLLBACK").catch(() => {});
        throw transactionError;
      } finally { client.release(); }
      return sendJson(res, 200, { ok: true, prediction: saved, balance: nextBal, message: "Prediction & stake saved." });
    } catch (error) {
      console.error("ParixBet player prediction error:", error.message);
      return sendJson(res, 500, { ok: false, message: "Prediction could not be saved" });
    }
  }

  if (mod === "gaming-cricket") {
    if (!allowMethods(req, res, ["GET"])) return;
    const player = readPlayerAuth(req);
    if (!player) return sendJson(res, 401, { ok: false, message: "ParixBet player login required" });
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
        try {
          const response = await fetch(url, { headers: { Accept: "application/json" } });
          if (!response.ok) throw new Error("Cricket provider returned HTTP " + response.status);
          const payload = await response.json();
          if (payload && payload.error) throw new Error(payload.error.message || "Cricket provider API error");
          const data = payload?.data ?? [];
          await pool.query(
            "INSERT INTO sp_game_cricket_cache(cache_key,payload,fetched_at) VALUES($1,$2::jsonb,NOW()) ON CONFLICT(cache_key) DO UPDATE SET payload=EXCLUDED.payload,fetched_at=NOW()",
            [cacheKey, JSON.stringify(data)]
          );
          return data;
        } catch (error) {
          if (cached.rows[0]) return cached.rows[0].payload;
          throw error;
        }
      }

      const fixtureId = String(req.query.fixture_id || "").trim();
      if (fixtureId) {
        if (!/^\\d{1,12}$/.test(fixtureId)) {
          return sendJson(res, 400, { ok: false, message: "Invalid cricket fixture ID" });
        }
        const fixture = await getCricketData(
          "cricket-fixture-" + fixtureId,
          "https://cricket.sportmonks.com/api/v2.0/fixtures/" + fixtureId +
            "?api_token=" + encodeURIComponent(apiKey) +
            "&include=runs,batting,bowling,lineup,venue,localteam,visitorteam,scoreboards",
          20000
        );
        return sendJson(res, 200, { ok: true, connected: true, fixture });
      }

      const now = new Date();
      const dateOnly = date => date.toISOString().slice(0, 10);
      const fromDate = new Date(now);
      fromDate.setUTCDate(fromDate.getUTCDate() - 3);
      const toDate = new Date(now);
      toDate.setUTCDate(toDate.getUTCDate() + 7);
      const from = dateOnly(fromDate);
      const to = dateOnly(toDate);

      const [matches, fixtures] = await Promise.all([
        getCricketData(
          "cricket-livescores",
          "https://cricket.sportmonks.com/api/v2.0/livescores?api_token=" +
            encodeURIComponent(apiKey) + "&include=runs,batting,bowling,lineup,venue,localteam,visitorteam",
          30000
        ),
        getCricketData(
          "cricket-fixtures-" + from.replace(/-/g, "") + "-" + to.replace(/-/g, ""),
          "https://cricket.sportmonks.com/api/v2.0/fixtures?api_token=" +
            encodeURIComponent(apiKey) + "&filter%5Bstarts_between%5D=" +
            encodeURIComponent(from + "," + to) + "&include=localteam,visitorteam,venue,runs",
          600000
        )
      ]);

      const fixtureList = Array.isArray(fixtures) ? fixtures : [];
      const upcoming = fixtureList.filter(match => {
        const start = new Date(match.starting_at || 0);
        const status = String(match.status || "").toLowerCase();
        return !Number.isNaN(start.getTime()) && start >= now &&
          !["finished", "abandoned", "cancelled", "no result", "no-result"].includes(status) &&
          !match.winner_team_id;
      }).sort((a, b) => new Date(a.starting_at) - new Date(b.starting_at)).slice(0, 20);
      const results = fixtureList.filter(match => {
        const status = String(match.status || "").toLowerCase();
        return ["finished", "abandoned", "no result", "no-result"].includes(status) || Boolean(match.winner_team_id);
      }).sort((a, b) => new Date(b.starting_at || 0) - new Date(a.starting_at || 0)).slice(0, 20);

      return sendJson(res, 200, {
        ok: true, connected: true, matches: Array.isArray(matches) ? matches : [],
        upcoming, results, refreshed_at: new Date().toISOString()
      });
    } catch (error) {
      console.error("ParixBet player cricket API error:", error.message);
      return sendJson(res, 502, { ok: false, message: "Live cricket data is temporarily unavailable" });
    }
  }
  if (mod === "gaming") {
    if (!allowMethods(req, res, ["GET", "POST", "PATCH"])) return;
    const admin = await getGamingAdmin(req, res);
    if (!admin) return;
    try {
      const pool = getPool();

      if (req.method === "GET" && req.query.action === "db-check") {
        const identity = await pool.query(`
          SELECT current_database() AS database,
                 current_user AS db_user,
                 session_user AS session_user,
                 current_schema() AS schema,
                 to_regclass('public.sp_game_players') AS players_table,
                 COALESCE(c.relrowsecurity, FALSE) AS rls_enabled,
                 COALESCE(c.relforcerowsecurity, FALSE) AS rls_forced,
                 CASE WHEN c.oid IS NOT NULL THEN has_table_privilege(current_user, c.oid, 'SELECT') ELSE FALSE END AS can_select,
                 current_setting('row_security') AS row_security_setting
          FROM (SELECT 1) AS seed
          LEFT JOIN pg_class c ON c.oid = to_regclass('public.sp_game_players')
        `);
        let playerCount = null;
        let policyCount = null;
        if (identity.rows[0].players_table) {
          const count = await pool.query("SELECT COUNT(*)::int AS count FROM public.sp_game_players");
          playerCount = count.rows[0].count;
          const policies = await pool.query(
            "SELECT COUNT(*)::int AS count FROM pg_policies WHERE schemaname='public' AND tablename='sp_game_players'"
          );
          policyCount = policies.rows[0].count;
        }
        let dbHost = null;
        try {
          dbHost = new URL(process.env.DATABASE_URL).hostname;
        } catch {}
        return sendJson(res, 200, {
          ok: true,
          diagnostic: {
            database: identity.rows[0].database,
            db_user: identity.rows[0].db_user,
            session_user: identity.rows[0].session_user,
            schema: identity.rows[0].schema,
            players_table: Boolean(identity.rows[0].players_table),
            player_count: playerCount,
            db_host: dbHost,
            rls_enabled: identity.rows[0].rls_enabled,
            rls_forced: identity.rows[0].rls_forced,
            can_select: identity.rows[0].can_select,
            row_security_setting: identity.rows[0].row_security_setting,
            policy_count: policyCount
          }
        });
      }

      await ensureGamingTables(pool);

      if (req.method === "GET") {
        const action = req.query.action || "stats";

        if (action === "stats") {
          const [players, games, coins, reserve] = await Promise.all([
            pool.query("SELECT COUNT(*)::int AS c FROM sp_game_players"),
            pool.query("SELECT COUNT(*)::int AS c FROM sp_game_settings WHERE enabled=TRUE"),
            pool.query("SELECT COALESCE(SUM(virtual_coins),0)::bigint AS c FROM sp_game_wallets"),
            pool.query("SELECT reserve_balance FROM sp_game_reserve WHERE id=1")
          ]);
          return sendJson(res, 200, {
            ok: true,
            stats: {
              players: players.rows[0].c,
              games: games.rows[0].c,
              coins: Number(coins.rows[0].c),
              reserve_balance: Number(reserve.rows[0]?.reserve_balance || 0)
            }
          });
        }

        if (action === "games") {
          const r = await pool.query("SELECT game_code,title,description,enabled,updated_at FROM sp_game_settings ORDER BY game_code ASC");
          return sendJson(res, 200, { ok: true, games: r.rows });
        }

        if (action === "players") {
          const r = await pool.query(`
            SELECT p.id,p.username,p.display_name,p.email,p.phone,p.status,p.created_at,COALESCE(w.virtual_coins,0)::bigint AS virtual_coins
            FROM sp_game_players p LEFT JOIN sp_game_wallets w ON w.player_id=p.id
            ORDER BY p.id DESC LIMIT 100
          `);
          return sendJson(res, 200, { ok: true, players: r.rows });
        }

        if (action === "records") {
          const r = await pool.query(`
            SELECT s.id,s.game_code,s.coins_change,s.result,s.created_at,p.username,p.display_name
            FROM sp_game_sessions s JOIN sp_game_players p ON p.id=s.player_id
            ORDER BY s.id DESC LIMIT 100
          `);
          return sendJson(res, 200, { ok: true, records: r.rows });
        }

        if (action === "cricket") {
          const apiKey = process.env.SPORTMONKS_CRICKET_TOKEN;
          if (!apiKey) return sendJson(res, 200, { ok: false, message: "SPORTMONKS_CRICKET_TOKEN is not set in environment variables." });
          const cached = await pool.query("SELECT payload,fetched_at FROM sp_game_cricket_cache WHERE cache_key='admin-cricket-live' LIMIT 1");
          if (cached.rows[0] && (Date.now() - new Date(cached.rows[0].fetched_at).getTime()) < 30000) {
            return sendJson(res, 200, { ok: true, source: "sportmonks", cached: true, matches: cached.rows[0].payload });
          }
          const resp = await fetch("https://cricket.sportmonks.com/api/v2.0/livescores?api_token=" + encodeURIComponent(apiKey), { headers: { Accept: "application/json" } });
          if (!resp.ok) throw new Error("Cricket provider HTTP " + resp.status);
          const json = await resp.json();
          const matches = Array.isArray(json.data) ? json.data : [];
          await pool.query(
            "INSERT INTO sp_game_cricket_cache(cache_key,payload,fetched_at) VALUES('admin-cricket-live',$1::jsonb,NOW()) ON CONFLICT(cache_key) DO UPDATE SET payload=EXCLUDED.payload,fetched_at=NOW()",
            [JSON.stringify(matches)]
          );
          return sendJson(res, 200, { ok: true, source: "sportmonks", cached: false, matches });
        }

        if (action === "engine_session") {
          const client = await pool.connect();
          let session;
          try {
            await client.query("BEGIN");
            const row = await getOrCreateActiveEngineSession(client);
            await client.query("COMMIT");
            session = formatEngineSessionResponse(row);
          } catch (e) {
            await client.query("ROLLBACK").catch(() => {});
            throw e;
          } finally { client.release(); }
          return sendJson(res, 200, { ok: true, session });
        }

        if (action === "prediction_matches") {
          const r = await pool.query(`
            SELECT m.id,m.sport,m.provider_match_id,m.title,m.side_a,m.side_b,
                   COALESCE(m.odds_a,1.90) AS odds_a,COALESCE(m.odds_b,1.90) AS odds_b,
                   m.scheduled_at,m.status,m.result_side,m.result_label,m.result_source,
                   COUNT(p.id)::int AS prediction_count,
                   COUNT(p.id) FILTER (WHERE p.selection_side=m.result_side)::int AS correct_count
            FROM sp_prediction_matches m LEFT JOIN sp_predictions p ON p.match_id=m.id
            GROUP BY m.id ORDER BY m.id DESC LIMIT 80
          `);
          return sendJson(res, 200, { ok: true, matches: r.rows });
        }

        if (action === "monitoring") {
          const [alertCfg, matchRows, walletSum, reserveRow, reserveLedger, settlementStats, recentAudits, activeEngine] = await Promise.all([
            pool.query("SELECT min_predictions,imbalance_threshold_pct FROM sp_prediction_monitor_settings WHERE id=1"),
            pool.query(`
              SELECT m.id,m.sport,m.title,m.side_a,m.side_b,m.status,m.result_label,
                     COUNT(p.id)::int AS prediction_count,
                     COUNT(p.id) FILTER (WHERE p.selection_side='A')::int AS side_a_count,
                     COUNT(p.id) FILTER (WHERE p.selection_side='B')::int AS side_b_count
              FROM sp_prediction_matches m LEFT JOIN sp_predictions p ON p.match_id=m.id
              GROUP BY m.id ORDER BY m.id DESC LIMIT 50
            `),
            pool.query("SELECT COALESCE(SUM(virtual_coins),0)::bigint AS total_coins FROM sp_game_wallets"),
            pool.query("SELECT reserve_balance FROM sp_game_reserve WHERE id=1"),
            pool.query("SELECT id,entry_type,amount,balance_after,note,created_at FROM sp_game_reserve_ledger ORDER BY id DESC LIMIT 25"),
            pool.query(`
              SELECT COUNT(*)::int AS settled_matches,
                     COALESCE(SUM(correct_count),0)::int AS correct,
                     COALESCE(SUM(incorrect_count),0)::int AS incorrect,
                     COALESCE(SUM(void_count),0)::int AS voided
              FROM sp_prediction_settlements
            `),
            pool.query("SELECT id,match_id,event_type,event_note,created_at FROM sp_prediction_audit_logs ORDER BY id DESC LIMIT 30"),
            pool.query("SELECT * FROM sp_settlement_engine_sessions WHERE status='OPEN' ORDER BY id DESC LIMIT 1")
          ]);
          const cfg = alertCfg.rows[0] || { min_predictions: 5, imbalance_threshold_pct: 60 };
          let totalPicks = 0, unbalancedMatches = 0;
          const matches = matchRows.rows.map(row => {
            const count = Number(row.prediction_count || 0);
            const aCnt = Number(row.side_a_count || 0);
            const bCnt = Number(row.side_b_count || 0);
            totalPicks += count;
            const share = count > 0 ? Number(((Math.max(aCnt, bCnt) / count) * 100).toFixed(1)) : 0;
            if (count >= Number(cfg.min_predictions) && share >= Number(cfg.imbalance_threshold_pct)) unbalancedMatches++;
            return { ...row, imbalance_percent: share };
          });
          const engRow = activeEngine.rows[0] || null;
          const engMetrics = engRow ? computeEngineMetrics({
            mode: engRow.engine_mode, tier: engRow.risk_tier,
            picksA: engRow.picks_a, picksB: engRow.picks_b, winnerSide: engRow.winner_side
          }) : computeEngineMetrics({ mode: "SCORE_POOL", tier: 3, picksA: 0, picksB: 0, winnerSide: null });
          const realReserve = Number(reserveRow.rows[0]?.reserve_balance || 0);
          const playerBalance = Number(walletSum.rows[0]?.total_coins || 0);
          const requiredTierReserve = Number(((playerBalance * engMetrics.reservePct) / 100).toFixed(2));

          return sendJson(res, 200, {
            ok: true,
            monitoring: {
              alert_settings: cfg,
              exposure: { total_predictions: totalPicks, unbalanced_matches: unbalancedMatches, matches },
              liquidity: {
                player_balance: playerBalance, virtual_points: playerBalance,
                real_reserve: realReserve, risk_tier: engMetrics.riskTier,
                tier_reserve_pct: engMetrics.reservePct, required_tier_reserve: requiredTierReserve,
                reserve_ledger: reserveLedger.rows
              },
              settlement: { ...settlementStats.rows[0], recent: recentAudits.rows },
              engine_session: engRow ? formatEngineSessionResponse(engRow) : null
            }
          });
        }

        return sendJson(res, 400, { ok: false, message: "Unknown gaming action" });
      }
      if (req.method === "PATCH") {
        const body = req.body || {};
        const action = body.action;

        if (action === "game_status") {
          const code = String(body.game_code || "").trim();
          const enabled = Boolean(body.enabled);
          const r = await pool.query(
            "UPDATE sp_game_settings SET enabled=$1,updated_at=NOW() WHERE game_code=$2 RETURNING game_code,title,description,enabled,updated_at",
            [enabled, code]
          );
          if (!r.rowCount) return sendJson(res, 404, { ok: false, message: "Game not found" });
          return sendJson(res, 200, { ok: true, game: r.rows[0] });
        }

        if (action === "player_status") {
          const id = Number(body.player_id);
          const status = body.status === "SUSPENDED" ? "SUSPENDED" : "ACTIVE";
          if (!Number.isSafeInteger(id) || id < 1) return sendJson(res, 400, { ok: false, message: "Invalid player ID" });
          const r = await pool.query("UPDATE sp_game_players SET status=$1 WHERE id=$2 RETURNING id,username,display_name,status", [status, id]);
          if (!r.rowCount) return sendJson(res, 404, { ok: false, message: "Player not found" });
          return sendJson(res, 200, { ok: true, player: r.rows[0] });
        }

        if (action === "prediction_match_status") {
          const matchId = Number(body.match_id);
          const nextStatus = String(body.status || "").toUpperCase();
          if (!Number.isSafeInteger(matchId) || matchId < 1 || !["UPCOMING", "LOCKED"].includes(nextStatus)) {
            return sendJson(res, 400, { ok: false, message: "Choose UPCOMING or LOCKED for an open match" });
          }
          const client = await pool.connect();
          let updated;
          try {
            await client.query("BEGIN");
            const cur = await client.query("SELECT id,title,status,result_side FROM sp_prediction_matches WHERE id=$1 FOR UPDATE", [matchId]);
            if (!cur.rowCount) { await client.query("ROLLBACK"); return sendJson(res, 404, { ok: false, message: "Match not found" }); }
            if (cur.rows[0].result_side || !["UPCOMING", "LOCKED"].includes(cur.rows[0].status)) {
              await client.query("ROLLBACK");
              return sendJson(res, 409, { ok: false, message: "Completed or cancelled match predictions cannot be changed" });
            }
            const resUpdate = await client.query(
              "UPDATE sp_prediction_matches SET status=$1,updated_at=NOW() WHERE id=$2 RETURNING id,title,status",
              [nextStatus, matchId]
            );
            updated = resUpdate.rows[0];
            await client.query(
              "INSERT INTO sp_prediction_audit_logs(match_id,event_type,event_note,event_data) VALUES($1,$2,$3,$4::jsonb)",
              [
                matchId,
                nextStatus === "LOCKED" ? "MATCH_LOCKED" : "MATCH_REOPENED",
                nextStatus === "LOCKED" ? "Admin locked predictions for match" : "Admin reopened predictions for match",
                JSON.stringify({ match_id: matchId, previous_status: cur.rows[0].status, status: nextStatus, admin: admin.user_id || admin.username || "GAMING_ADMIN" })
              ]
            );
            await client.query("COMMIT");
          } catch (e) {
            await client.query("ROLLBACK").catch(() => {});
            throw e;
          } finally { client.release(); }
          return sendJson(res, 200, { ok: true, match: updated, message: nextStatus === "LOCKED" ? "Predictions locked for this match." : "Predictions reopened for this match." });
        }

        return sendJson(res, 400, { ok: false, message: "Unknown PATCH action" });
      }

      const body = req.body || {};
      const action = body.action;

      if (action === "create_player") {
        const username = String(body.username || "").trim().toLowerCase();
        const displayName = String(body.display_name || "").trim();
        const password = String(body.password || "");
        if (!/^[a-z0-9_]{4,40}$/.test(username) || displayName.length < 2 || password.length < 6) {
          return sendJson(res, 400, { ok: false, message: "Username (4-40 chars a-z, 0-9, _), display name, and password (6+ chars) required" });
        }
        const hash = await bcrypt.hash(password, 10);
        const client = await pool.connect();
        try {
          await client.query("BEGIN");
          const ins = await client.query(
            "INSERT INTO sp_game_players(username,display_name,password_hash,status) VALUES($1,$2,$3,'ACTIVE') RETURNING id,username,display_name,status,created_at",
            [username, displayName, hash]
          );
          await client.query("INSERT INTO sp_game_wallets(player_id,virtual_coins) VALUES($1,1000)", [ins.rows[0].id]);
          await client.query(
            "INSERT INTO sp_game_coin_ledger(player_id,amount,entry_type,note) VALUES($1,1000,'INITIAL_CREDIT','Admin created player with starter balance')",
            [ins.rows[0].id]
          );
          await client.query("COMMIT");
          return sendJson(res, 201, { ok: true, player: ins.rows[0] });
        } catch (e) {
          await client.query("ROLLBACK").catch(() => {});
          if (e.code === "23505") return sendJson(res, 409, { ok: false, message: "Username already exists" });
          throw e;
        } finally { client.release(); }
      }

      if (action === "create_prediction_match") {
        const sport = String(body.sport || "CRICKET").toUpperCase();
        const title = String(body.title || "").trim();
        const sideA = String(body.side_a || "").trim() || "Team A";
        const sideB = String(body.side_b || "").trim() || "Team B";
        const oddsA = Math.max(1.1, Math.min(25, Number(body.odds_a || 1.90)));
        const oddsB = Math.max(1.1, Math.min(25, Number(body.odds_b || 1.90)));
        const scheduledAt = body.scheduled_at ? new Date(body.scheduled_at) : null;
        if (!title) return sendJson(res, 400, { ok: false, message: "Match title required" });
        const validDate = scheduledAt && !Number.isNaN(scheduledAt.getTime()) ? scheduledAt.toISOString() : null;
        const r = await pool.query(
          `INSERT INTO sp_prediction_matches(sport,provider_match_id,title,side_a,side_b,odds_a,odds_b,scheduled_at,status)
           VALUES($1,$2,$3,$4,$5,$6,$7,$8,'UPCOMING')
           RETURNING id,sport,title,side_a,side_b,odds_a,odds_b,scheduled_at,status`,
          [sport, "manual-" + Date.now() + "-" + Math.random().toString(36).slice(2, 7), title, sideA, sideB, oddsA, oddsB, validDate]
        );
        return sendJson(res, 201, { ok: true, match: r.rows[0] });
      }

      if (action === "manual_match_result") {
        const matchId = Number(body.match_id);
        const side = String(body.result_side || "").toUpperCase();
        if (!Number.isSafeInteger(matchId) || matchId < 1 || !["A", "B", "D"].includes(side)) {
          return sendJson(res, 400, { ok: false, message: "Choose A, B, or D" });
        }
        const client = await pool.connect();
        let summary, totalPayouts = 0;
        try {
          await client.query("BEGIN");
          const mRes = await client.query(
            "SELECT id,sport,title,side_a,side_b,COALESCE(odds_a,1.90) AS odds_a,COALESCE(odds_b,1.90) AS odds_b,result_side FROM sp_prediction_matches WHERE id=$1 FOR UPDATE",
            [matchId]
          );
          if (!mRes.rowCount) { await client.query("ROLLBACK"); return sendJson(res, 404, { ok: false, message: "Match not found" }); }
          if (mRes.rows[0].result_side) { await client.query("ROLLBACK"); return sendJson(res, 409, { ok: false, message: "Match result is already recorded" }); }
          const m = mRes.rows[0];
          const label = side === "A" ? m.side_a : (side === "B" ? m.side_b : "Draw / No Result");
          const winOdds = side === "A" ? Number(m.odds_a || 1.90) : Number(m.odds_b || 1.90);
          await client.query(
            "UPDATE sp_prediction_matches SET status='FINISHED',result_side=$1,result_label=$2,result_source='MANUAL',updated_at=NOW() WHERE id=$3",
            [side, label, matchId]
          );

          const picks = await client.query(
            "SELECT id,player_id,selection_side,COALESCE(stake_amount,0)::bigint AS stake_amount FROM sp_predictions WHERE match_id=$1 FOR UPDATE",
            [matchId]
          );
          let correct = 0, incorrect = 0, voided = 0;
          for (const pk of picks.rows) {
            const stake = Number(pk.stake_amount || 0);
            if (side === "D") {
              voided++;
              if (stake > 0) {
                await client.query("UPDATE sp_game_wallets SET virtual_coins = virtual_coins + $1, updated_at = NOW() WHERE player_id = $2", [stake, pk.player_id]);
                await client.query("INSERT INTO sp_game_coin_ledger(player_id,amount,entry_type,note) VALUES($1,$2,'PREDICTION_REFUND',$3)", [pk.player_id, stake, `Refund Draw/No Result: ${m.title}`]);
              }
              await client.query("UPDATE sp_predictions SET payout_amount=$1, settled=TRUE WHERE id=$2", [payout, pk.id]);
            } else {
              incorrect++;
              await client.query("UPDATE sp_predictions SET payout_amount=0, settled=TRUE WHERE id=$2", [0, pk.id]);
            }
          }

          await client.query(
            `INSERT INTO sp_prediction_settlements(match_id,prediction_count,correct_count,incorrect_count,void_count,result_side,result_source)
             VALUES($1,$2,$3,$4,$5,$6,'MANUAL')
             ON CONFLICT(match_id) DO UPDATE SET prediction_count=EXCLUDED.prediction_count,correct_count=EXCLUDED.correct_count,incorrect_count=EXCLUDED.incorrect_count,void_count=EXCLUDED.void_count,result_side=EXCLUDED.result_side,result_source='MANUAL',settled_at=NOW()`,
            [matchId, picks.rows.length, correct, incorrect, voided, side]
          );
          await client.query(
            "INSERT INTO sp_prediction_audit_logs(match_id,event_type,event_note,event_data) VALUES($1,'MANUAL_RESULT_SETTLED','Admin settled match & paid winners',$2::jsonb)",
            [matchId, JSON.stringify({ result_side: side, result_label: label, total: picks.rows.length, correct, incorrect, voided, total_payouts: totalPayouts })]
          );
          await client.query("COMMIT");
          summary = { total: picks.rows.length, correct, incorrect, voided, total_payouts: totalPayouts };
        } catch (e) {
          await client.query("ROLLBACK").catch(() => {});
          throw e;
        } finally { client.release(); }
        return sendJson(res, 200, { ok: true, predictions: summary, message: `Settled! ${summary.correct} winner(s) paid ₹${summary.total_payouts}.` });
      }
      if (action === "sync_match_results") {
        const apiKey = process.env.FOOTBALL_API_KEY;
        const openMatches = await pool.query(
          "SELECT id,sport,provider_match_id,title,side_a,side_b FROM sp_prediction_matches WHERE result_side IS NULL AND status IN ('UPCOMING','LOCKED','LIVE') ORDER BY id DESC LIMIT 30"
        );
        if (!openMatches.rows.length) return sendJson(res, 200, { ok: true, checked: 0, updated: 0, needs_manual_review: 0, errors: [] });
        let checked = 0, updated = 0, needsManualReview = 0;
        const errors = [];
        for (const m of openMatches.rows) {
          checked++;
          if (m.sport === "FOOTBALL" && apiKey && m.provider_match_id && !String(m.provider_match_id).startsWith("manual-")) {
            try {
              const r = await fetch("https://api.sportsapi.app/v2/matches/" + encodeURIComponent(m.provider_match_id), {
                headers: { Accept: "application/json", Authorization: "Bearer " + apiKey }
              });
              if (r.ok) {
                const payload = await r.json();
                const matchObj = payload.data || payload;
                const statusType = String(matchObj?.status?.type || "").toLowerCase();
                if (statusType === "finished") {
                  const hScore = Number(matchObj?.homeScore?.current ?? matchObj?.homeScore?.display ?? NaN);
                  const aScore = Number(matchObj?.awayScore?.current ?? matchObj?.awayScore?.display ?? NaN);
                  if (!Number.isNaN(hScore) && !Number.isNaN(aScore)) {
                    const winSide = hScore > aScore ? "A" : (aScore > hScore ? "B" : "D");
                    const winLabel = winSide === "A" ? m.side_a : (winSide === "B" ? m.side_b : "Draw");
                    await pool.query(
                      "UPDATE sp_prediction_matches SET status='FINISHED',result_side=$1,result_label=$2,result_source='API',updated_at=NOW() WHERE id=$3",
                      [winSide, winLabel, m.id]
                    );
                    await pool.query(
                      `INSERT INTO sp_prediction_settlements(match_id,prediction_count,correct_count,incorrect_count,void_count,result_side,result_source)
                       VALUES($1,0,0,0,0,$2,'API') ON CONFLICT(match_id) DO NOTHING`,
                      [m.id, winSide]
                    );
                    updated++;
                    continue;
                  }
                }
              }
            } catch (e) { errors.push(`${m.title}: ${e.message}`); }
          }
          needsManualReview++;
          await pool.query("UPDATE sp_prediction_matches SET result_source='API_REVIEW',updated_at=NOW() WHERE id=$1 AND result_source IS NULL", [m.id]);
        }
        return sendJson(res, 200, { ok: true, checked, updated, needs_manual_review: needsManualReview, errors });
      }

      if (action === "adjust_reserve") {
        const entryType = String(body.entry_type || "DEPOSIT").toUpperCase();
        const amount = Number(body.amount);
        const note = String(body.note || "").trim();
        if (!["DEPOSIT", "WITHDRAW", "SET_BALANCE"].includes(entryType)) return sendJson(res, 400, { ok: false, message: "Invalid reserve action type" });
        if (!Number.isFinite(amount) || amount < 0 || (entryType !== "SET_BALANCE" && amount <= 0)) {
          return sendJson(res, 400, { ok: false, message: "Enter a valid non-negative amount" });
        }
        const client = await pool.connect();
        let nextBalance, ledgerEntry;
        try {
          await client.query("BEGIN");
          const curRes = await client.query("SELECT reserve_balance FROM sp_game_reserve WHERE id=1 FOR UPDATE");
          const curBal = Number(curRes.rows[0]?.reserve_balance || 0);
          if (entryType === "DEPOSIT") nextBalance = Number((curBal + amount).toFixed(2));
          else if (entryType === "WITHDRAW") {
            if (amount > curBal) { await client.query("ROLLBACK"); return sendJson(res, 400, { ok: false, message: "Withdrawal cannot exceed current reserve" }); }
            nextBalance = Number((curBal - amount).toFixed(2));
          } else nextBalance = Number(amount.toFixed(2));

          await client.query("UPDATE sp_game_reserve SET reserve_balance=$1,updated_at=NOW() WHERE id=1", [nextBalance]);
          const ins = await client.query(
            "INSERT INTO sp_game_reserve_ledger(entry_type,amount,balance_after,note) VALUES($1,$2,$3,$4) RETURNING id,entry_type,amount,balance_after,note,created_at",
            [entryType, amount, nextBalance, note || `${entryType} via ParixBet Admin`]
          );
          ledgerEntry = ins.rows[0];
          await client.query(
            "INSERT INTO sp_prediction_audit_logs(match_id,event_type,event_note,event_data) VALUES(NULL,'RESERVE_UPDATED',$1,$2::jsonb)",
            [`Real reserve ${entryType}: ₹${amount} -> Balance ₹${nextBalance}`, JSON.stringify({ entry_type: entryType, amount, previous_balance: curBal, balance_after: nextBalance, note })]
          );
          await client.query("COMMIT");
        } catch (e) {
          await client.query("ROLLBACK").catch(() => {});
          throw e;
        } finally { client.release(); }
        return sendJson(res, 200, { ok: true, reserve_balance: nextBalance, ledger_entry: ledgerEntry, message: `Real reserve updated. Current balance: ₹${nextBalance.toLocaleString("en-IN")}` });
      }

      if (action === "update_monitor_settings") {
        const minPred = Number(body.min_predictions);
        const thresh = Number(body.imbalance_threshold_pct);
        if (!Number.isInteger(minPred) || minPred < 1 || minPred > 10000 || !Number.isFinite(thresh) || thresh < 50 || thresh > 95) {
          return sendJson(res, 400, { ok: false, message: "Minimum picks must be 1-10000 and imbalance threshold 50-95%" });
        }
        await pool.query(
          "INSERT INTO sp_prediction_monitor_settings(id,min_predictions,imbalance_threshold_pct,updated_at) VALUES(1,$1,$2,NOW()) ON CONFLICT(id) DO UPDATE SET min_predictions=EXCLUDED.min_predictions,imbalance_threshold_pct=EXCLUDED.imbalance_threshold_pct,updated_at=NOW()",
          [minPred, thresh]
        );
        return sendJson(res, 200, { ok: true, message: "Alert thresholds saved." });
      }

      if (action === "engine_pick") {
        const side = String(body.selection_side || "").toUpperCase();
        if (!["A", "B"].includes(side)) return sendJson(res, 400, { ok: false, message: "Choose A or B" });
        const client = await pool.connect();
        let formatted;
        try {
          await client.query("BEGIN");
          const cur = await getOrCreateActiveEngineSession(client);
          if (cur.status === "SETTLED") { await client.query("ROLLBACK"); return sendJson(res, 409, { ok: false, message: "Session already settled. Reset to start a new session." }); }
          const nextMode = body.engine_mode ? String(body.engine_mode).toUpperCase() : cur.engine_mode;
          const nextTier = body.risk_tier ? Number(body.risk_tier) : Number(cur.risk_tier);
          const nextA = Number(cur.picks_a || 0) + (side === "A" ? 1 : 0);
          const nextB = Number(cur.picks_b || 0) + (side === "B" ? 1 : 0);
          const m = computeEngineMetrics({ mode: nextMode, tier: nextTier, picksA: nextA, picksB: nextB, winnerSide: null });
          const upd = await client.query(
            `UPDATE sp_settlement_engine_sessions
             SET engine_mode=$1,risk_tier=$2,label_a=$3,label_b=$4,picks_a=$5,picks_b=$6,multiplier=$7,effective_score=$8
             WHERE id=$9 RETURNING *`,
            [m.mode, m.riskTier, body.label_a ? String(body.label_a).slice(0, 80) : cur.label_a, body.label_b ? String(body.label_b).slice(0, 80) : cur.label_b, nextA, nextB, m.multiplier, m.effectiveScore, cur.id]
          );
          await client.query("COMMIT");
          formatted = formatEngineSessionResponse(upd.rows[0]);
        } catch (e) {
          await client.query("ROLLBACK").catch(() => {});
          throw e;
        } finally { client.release(); }
        return sendJson(res, 200, { ok: true, session: formatted });
      }
      if (action === "engine_settle") {
        const winnerSide = String(body.winner_side || "").toUpperCase();
        if (!["A", "B"].includes(winnerSide)) return sendJson(res, 400, { ok: false, message: "Winner side must be A or B" });
        const client = await pool.connect();
        let formatted;
        try {
          await client.query("BEGIN");
          const cur = await getOrCreateActiveEngineSession(client);
          const total = Number(cur.picks_a || 0) + Number(cur.picks_b || 0);
          if (total < 1) { await client.query("ROLLBACK"); return sendJson(res, 400, { ok: false, message: "Record at least one pick before settling" }); }
          if (cur.status === "SETTLED") { await client.query("ROLLBACK"); return sendJson(res, 409, { ok: false, message: "Session is already settled" }); }
          const nextMode = body.engine_mode ? String(body.engine_mode).toUpperCase() : cur.engine_mode;
          const nextTier = body.risk_tier ? Number(body.risk_tier) : Number(cur.risk_tier);
          const m = computeEngineMetrics({ mode: nextMode, tier: nextTier, picksA: cur.picks_a, picksB: cur.picks_b, winnerSide });
          const upd = await client.query(
            `UPDATE sp_settlement_engine_sessions
             SET engine_mode=$1,risk_tier=$2,label_a=$3,label_b=$4,status='SETTLED',winner_side=$5,winning_picks=$6,multiplier=$7,effective_score=$8,settled_at=NOW()
             WHERE id=$9 RETURNING *`,
            [m.mode, m.riskTier, body.label_a ? String(body.label_a).slice(0, 80) : cur.label_a, body.label_b ? String(body.label_b).slice(0, 80) : cur.label_b, winnerSide, m.winningPicks, m.multiplier, m.effectiveScore, cur.id]
          );
          await client.query(
            "INSERT INTO sp_prediction_audit_logs(match_id,event_type,event_note,event_data) VALUES(NULL,'ENGINE_SETTLED',$1,$2::jsonb)",
            [`Session #${cur.id} settled for ${winnerSide} (${m.multiplier}x, score ${m.effectiveScore})`, JSON.stringify({ session_id: cur.id, winner_side: winnerSide, mode: m.mode, risk_tier: m.riskTier, multiplier: m.multiplier, effective_score: m.effectiveScore })]
          );
          await client.query("COMMIT");
          formatted = formatEngineSessionResponse(upd.rows[0]);
        } catch (e) {
          await client.query("ROLLBACK").catch(() => {});
          throw e;
        } finally { client.release(); }
        return sendJson(res, 200, { ok: true, session: formatted });
      }

      if (action === "engine_reset") {
        const client = await pool.connect();
        let formatted;
        try {
          await client.query("BEGIN");
          await client.query("UPDATE sp_settlement_engine_sessions SET status='ARCHIVED' WHERE status='OPEN'");
          const created = await client.query(
            `INSERT INTO sp_settlement_engine_sessions(engine_mode,risk_tier,label_a,label_b,picks_a,picks_b,status)
             VALUES('SCORE_POOL',3,'Team / Player A','Team / Player B',0,0,'OPEN') RETURNING *`
          );
          await client.query(
            "INSERT INTO sp_prediction_audit_logs(match_id,event_type,event_note,event_data) VALUES(NULL,'ENGINE_RESET',$1,$2::jsonb)",
            [`Started new engine session #${created.rows[0].id}`, JSON.stringify({ new_session_id: created.rows[0].id })]
          );
          await client.query("COMMIT");
          formatted = formatEngineSessionResponse(created.rows[0]);
        } catch (e) {
          await client.query("ROLLBACK").catch(() => {});
          throw e;
        } finally { client.release(); }
        return sendJson(res, 200, { ok: true, session: formatted });
      }

      return sendJson(res, 400, { ok: false, message: "Unknown gaming action" });
    } catch (err) {
      console.error("Gaming module error:", err.message);
      return sendJson(res, 500, { ok: false, message: "Gaming service error" });
    }
  }

  if (mod && mod !== "dashboard") {
    return sendJson(res, 404, { ok: false, message: "Unknown dashboard module" });
  }

  const admin = await getAdmin(req, res);
  if (!admin) return;
  return sendJson(res, 200, { ok: true, module: mod || "dashboard", admin: admin.user_id || admin.username || "ADMIN" });
};




