
const bcrypt = require("bcryptjs");
const { getPool } = require("./_lib/db");
const { sendJson, allowMethods } = require("./_lib/http");
const { createToken } = require("./_lib/auth");

function isTransientDbError(error) {
  const code = String(error && error.code || "");
  const message = String(error && error.message || "");
  return ["08000", "08003", "08006", "57P01", "ECONNRESET", "ECONNREFUSED", "ETIMEDOUT"].includes(code) ||
    /connection terminated unexpectedly|socket hang up|connection reset|server closed the connection/i.test(message);
}

async function queryWithRetry(pool, sql, params) {
  try {
    return await pool.query(sql, params);
  } catch (error) {
    if (!isTransientDbError(error)) throw error;
    await new Promise(resolve => setTimeout(resolve, 250));
    return pool.query(sql, params);
  }
}

module.exports = async (req, res) => {
  if (!allowMethods(req, res, ["POST"])) return;

  try {
    const { user_id, password, login_type, display_name } = req.body || {};
    if (login_type === "gaming_admin") {
      const adminUser = process.env.GAMING_ADMIN_USERNAME;
      const adminPass = process.env.GAMING_ADMIN_PASSWORD;
      if (!adminUser || !adminPass) {
        return sendJson(res, 503, { ok: false, message: "ParixBet Admin login is not configured." });
      }
      if (typeof user_id !== "string" || typeof password !== "string" ||
          user_id.trim().toLowerCase() !== adminUser.trim().toLowerCase() || password !== adminPass) {
        return sendJson(res, 401, { ok: false, message: "Invalid ParixBet Admin username or password." });
      }

      const pool = getPool();
      await queryWithRetry(
        pool,
        `INSERT INTO sp_gaming_admins (username, display_name)
         VALUES ($1, 'ParixBet Admin')
         ON CONFLICT (username) DO NOTHING`,
        [adminUser.trim().toLowerCase()]
      );
      const adminResult = await queryWithRetry(
        pool,
        `SELECT id, username, display_name, status, token_version
         FROM sp_gaming_admins
         WHERE username = $1
         LIMIT 1`,
        [adminUser.trim().toLowerCase()]
      );
      const adminRecord = adminResult.rows[0];
      if (!adminRecord || adminRecord.status !== "ACTIVE") {
        return sendJson(res, 403, { ok: false, message: "ParixBet Admin account is inactive or unavailable." });
      }

      const admin = {
        id: adminRecord.id,
        user_id: adminRecord.username,
        display_name: adminRecord.display_name,
        role: "GAMING_ADMIN",
        token_version: Number(adminRecord.token_version)
      };
      return sendJson(res, 200, {
        ok: true,
        message: "ParixBet Admin login successful",
        token: createToken(admin),
        user: { id: admin.id, user_id: admin.user_id, display_name: admin.display_name, role: admin.role }
      });
    }
    if (login_type === "gaming_register" || login_type === "gaming") {
      const pool = getPool();
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
        CREATE TABLE IF NOT EXISTS sp_game_coin_ledger (
          id BIGSERIAL PRIMARY KEY,
          player_id BIGINT NOT NULL REFERENCES sp_game_players(id) ON DELETE CASCADE,
          amount BIGINT NOT NULL,
          entry_type VARCHAR(24) NOT NULL,
          note VARCHAR(240),
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);
      const username = String(user_id || "").trim().toLowerCase();
      if (!/^[a-z0-9_]{4,40}$/.test(username) || typeof password !== "string" || password.length < 8) {
        return sendJson(res, 400, { ok: false, message: "Username 4-40 letters/numbers/_ and password 8+ characters are required." });
      }
      if (login_type === "gaming_register") {
        const name = String(display_name || username).trim().slice(0,100);
        if (name.length < 2) return sendJson(res,400,{ok:false,message:"Enter your display name."});
        const hash = await bcrypt.hash(password,12);
        const client = await pool.connect();
        try {
          await client.query("BEGIN");
          const created = await client.query(
            "INSERT INTO sp_game_players (username,display_name,password_hash) VALUES ($1,$2,$3) RETURNING id,username",
            [username,name,hash]
          );
          await client.query("INSERT INTO sp_game_wallets (player_id,virtual_coins) VALUES ($1,1000)",[created.rows[0].id]);
          await client.query("INSERT INTO sp_game_coin_ledger (player_id,amount,entry_type,note) VALUES ($1,1000,'WELCOME','Starting virtual points')",[created.rows[0].id]);
          await client.query("COMMIT");
          const player={id:created.rows[0].id,user_id:username,display_name:name,role:"GAMING_PLAYER"};
          return sendJson(res,201,{ok:true,token:createToken(player),user:player});
        } catch(e) {
          await client.query("ROLLBACK");
          if(e.code==="23505")return sendJson(res,409,{ok:false,message:"This username is already taken."});
          throw e;
        } finally {client.release();}
      }
      const found = await pool.query(
        "SELECT id,username,display_name,password_hash,status FROM sp_game_players WHERE username=$1 LIMIT 1",
        [username]
      );
      if (!found.rows.length || !(await bcrypt.compare(password,found.rows[0].password_hash))) {
        return sendJson(res,401,{ok:false,message:"Invalid gaming username or password."});
      }
      const player=found.rows[0];
      if(player.status!=="ACTIVE")return sendJson(res,403,{ok:false,message:"This gaming account is suspended."});
      const sessionUser={id:player.id,user_id:player.username,display_name:player.display_name,role:"GAMING_PLAYER"};
      return sendJson(res,200,{ok:true,token:createToken(sessionUser),user:sessionUser});
    }

    if (
      !["standard", "super_admin"].includes(login_type) ||
      typeof user_id !== "string" ||
      typeof password !== "string" ||
      !user_id.trim() ||
      !password
    ) {
      return sendJson(res, 400, {
        ok: false,
        message: "User ID and password are required"
      });
    }

    const result = await getPool().query(
      `SELECT id, user_id, display_name, password_hash, role, status
       FROM sp_users
       WHERE LOWER(user_id) = LOWER($1)
       LIMIT 1`,
      [user_id.trim()]
    );

    if (!result.rows.length) {
      return sendJson(res, 401, {
        ok: false,
        message: "Invalid User ID or password"
      });
    }

    const user = result.rows[0];

    if (user.status !== "ACTIVE") {
      return sendJson(res, 403, {
        ok: false,
        message: "Account is inactive"
      });
    }

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return sendJson(res, 401, {
        ok: false,
        message: "Invalid User ID or password"
      });
    }

    if (login_type === "super_admin" && user.role !== "SUPER_ADMIN") {
      return sendJson(res, 403, { ok: false, message: "This account is not a Super Admin account. Use the normal login." });
    }
    if (login_type === "standard" && user.role === "SUPER_ADMIN") {
      return sendJson(res, 403, { ok: false, message: "Super Admin must use the separate Super Admin Login." });
    }

    const token = createToken(user);

    return sendJson(res, 200, {
      ok: true,
      message: "Login successful",
      token,
      user: {
        id: user.id,
        user_id: user.user_id,
        display_name: user.display_name,
        role: user.role
      }
    });

  } catch (error) {
    console.error("Login error:", error.message);

    return sendJson(res, 500, {
      ok: false,
      message: "Login service unavailable"
    });
  }
};
