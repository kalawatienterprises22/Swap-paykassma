const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { getPool } = require("../_lib/db");
const { sendJson, allowMethods } = require("../_lib/http");
const { verifyToken } = require("../_lib/auth");

function authenticate(req, res) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) { sendJson(res, 401, { ok: false, message: "Authentication required" }); return null; }
  try {
    const user = verifyToken(token);
    if (!["SUPER_ADMIN", "ADMIN"].includes(user.role)) {
      sendJson(res, 403, { ok: false, message: "Admin access required" });
      return null;
    }
    return user;
  } catch {
    sendJson(res, 401, { ok: false, message: "Invalid or expired session" });
    return null;
  }
}

module.exports = async (req, res) => {
  if (!allowMethods(req, res, ["GET", "POST", "PATCH"])) return;

    // Public referral registration: the referral code permanently assigns the new Merchant
    // to the referring Admin. The submitted parent ID is never trusted.
    if (req.method === "POST" && req.body?.action === "register_referral") {
      const pool = getPool();
      const { referral_code, user_id, display_name, email, password } = req.body || {};
      const code = String(referral_code || "").trim();
      const accountId = typeof user_id === "string" ? user_id.trim() : "";
      const name = typeof display_name === "string" ? display_name.trim() : "";
      const accountEmail = typeof email === "string" && email.trim() ? email.trim().toLowerCase() : null;
      if (!/^[A-Za-z0-9_-]{20,100}$/.test(code)) return sendJson(res, 400, { ok: false, message: "Invalid referral link" });
      if (!/^[a-zA-Z0-9_-]{4,32}$/.test(accountId)) return sendJson(res, 400, { ok: false, message: "User ID must be 4-32 characters" });
      if (name.length < 2 || name.length > 80) return sendJson(res, 400, { ok: false, message: "Name must be 2-80 characters" });
      if (accountEmail && (accountEmail.length > 254 || !/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(accountEmail))) return sendJson(res, 400, { ok: false, message: "Enter a valid email address" });
      if (typeof password !== "string" || password.length < 12 || password.length > 72) return sendJson(res, 400, { ok: false, message: "Password must be 12-72 characters" });
      const referral = await pool.query(
        "SELECT r.admin_id,a.user_id AS admin_user_id FROM sp_admin_referrals r JOIN sp_users a ON a.id=r.admin_id WHERE r.code=$1 AND r.active=TRUE AND a.role='ADMIN' AND a.status='ACTIVE'",
        [code]
      );
      if (!referral.rowCount) return sendJson(res, 404, { ok: false, message: "This referral link is invalid or inactive" });
      const passwordHash = await bcrypt.hash(password, 12);
      const created = await pool.query(
        "INSERT INTO sp_users(id,user_id,email,password_hash,display_name,role,status,parent_admin_id) VALUES($1,$2,$3,$4,$5,'MERCHANT','SUSPENDED',$6) RETURNING id,user_id,display_name,role,status",
        [crypto.randomUUID(), accountId, accountEmail, passwordHash, name, referral.rows[0].admin_id]
      );
      await pool.query("INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,'MERCHANT_REFERRED_SIGNUP','MERCHANT',$2,$3)",
        [referral.rows[0].admin_id, created.rows[0].id, JSON.stringify({ merchant_user_id: accountId, referral_admin_user_id: referral.rows[0].admin_user_id })]);
      await pool.query("INSERT INTO sp_notifications(user_id,title,message,category) SELECT id,'New Merchant referral signup',$1,'MERCHANT_SIGNUP' FROM sp_users WHERE (id=$2 OR role='SUPER_ADMIN') AND status='ACTIVE'",
        [`Merchant ${accountId} joined through Admin ${referral.rows[0].admin_user_id} referral. Approval is required before login.`, referral.rows[0].admin_id]);
      return sendJson(res, 201, { ok: true, message: "Signup received. Super Admin approval is required before login.", merchant: created.rows[0] });
    }
\n  const actor = authenticate(req, res);
  if (!actor) return;

  try {
    const pool = getPool();
    const activeActor = await pool.query(
      "SELECT id, role, status FROM sp_users WHERE id=$1",
      [actor.sub]
    );
    if (!activeActor.rowCount || activeActor.rows[0].status !== "ACTIVE" ||
        activeActor.rows[0].role !== actor.role) {
      return sendJson(res, 403, { ok: false, message: "Your account is not active" });
    }

    if (req.method === "GET") {

      if (actor.role === "ADMIN" && req.query?.action === "referral_link") {
        let referral = await pool.query("SELECT code FROM sp_admin_referrals WHERE admin_id=$1 AND active=TRUE", [actor.sub]);
        if (!referral.rowCount) {
          const code = crypto.randomBytes(24).toString("hex");
          referral = await pool.query(
            "INSERT INTO sp_admin_referrals(admin_id,code,active) VALUES($1,$2,TRUE) RETURNING code",
            [actor.sub, code]
          );
        }
        return sendJson(res, 200, { ok: true, referral_code: referral.rows[0].code });
      }
\n      const search = String(req.query?.q || "").trim();
      const requestedRole = String(req.query?.role || "MERCHANT").toUpperCase();
      if (!["MERCHANT", "ADMIN"].includes(requestedRole)) {
        return sendJson(res, 400, { ok: false, message: "Invalid account role" });
      }
      if (actor.role === "ADMIN" && requestedRole !== "MERCHANT") {
        return sendJson(res, 403, { ok: false, message: "Admins can only view their own merchants" });
      }
      const values = [search, `%${search}%`, requestedRole];
      let scope = "";
      if (actor.role === "ADMIN") {
        values.push(actor.sub);
        scope = " AND parent_admin_id=$4";
      }
      const result = await pool.query(
        `SELECT id, user_id, email, display_name, role, status, created_at,
                parent_admin_id
         FROM sp_users
         WHERE role=$3
           AND ($1='' OR user_id ILIKE $2 OR display_name ILIKE $2 OR COALESCE(email,'') ILIKE $2)
           ${scope}
         ORDER BY created_at DESC LIMIT 300`,
        values
      );
      return sendJson(res, 200, {
        ok: true, accounts: result.rows,
        merchants: requestedRole === "MERCHANT" ? result.rows : undefined
      });
    }

    if (req.method === "POST") {
      const { user_id, display_name, email, password } = req.body || {};
      const requestedRole = actor.role === "ADMIN" ? "MERCHANT" : String(req.body?.role || "MERCHANT").toUpperCase();
      if (!["MERCHANT", "ADMIN"].includes(requestedRole)) {
        return sendJson(res, 400, { ok: false, message: "Only Admin or Merchant accounts can be created here" });
      }
      const accountId = typeof user_id === "string" ? user_id.trim() : "";
      const name = typeof display_name === "string" ? display_name.trim() : "";
      const accountEmail = typeof email === "string" && email.trim() ? email.trim().toLowerCase() : null;
      if (!/^[a-zA-Z0-9_-]{4,32}$/.test(accountId)) return sendJson(res, 400, { ok: false, message: "User ID must be 4-32 characters (letters, numbers, _ or -)" });
      if (name.length < 2 || name.length > 80) return sendJson(res, 400, { ok: false, message: "Name must be 2-80 characters" });
      if (accountEmail && (accountEmail.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(accountEmail))) return sendJson(res, 400, { ok: false, message: "Enter a valid email address" });
      if (typeof password !== "string" || password.length < 12 || password.length > 72) return sendJson(res, 400, { ok: false, message: "Password must be 12-72 characters" });

      let parentAdminId = null;
      if (requestedRole === "MERCHANT") {
        if (actor.role === "ADMIN") parentAdminId = actor.sub;
        else if (req.body?.parent_admin_id) {
          const parent = await pool.query("SELECT id FROM sp_users WHERE id=$1 AND role='ADMIN' AND status='ACTIVE'", [req.body.parent_admin_id]);
          if (!parent.rowCount) return sendJson(res, 400, { ok: false, message: "Choose an active Admin" });
          parentAdminId = parent.rows[0].id;
        }
      }
      const passwordHash = await bcrypt.hash(password, 12);
      const result = await pool.query(
        `INSERT INTO sp_users (id,user_id,email,password_hash,display_name,role,status,parent_admin_id)
         VALUES ($1,$2,$3,$4,$5,$6,'ACTIVE',$7)
         RETURNING id,user_id,email,display_name,role,status,created_at,parent_admin_id`,
        [crypto.randomUUID(), accountId, accountEmail, passwordHash, name, requestedRole, parentAdminId]
      );
      await pool.query(
        "INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,$2,$3,$4,$5)",
        [actor.sub, requestedRole + "_CREATED", requestedRole, result.rows[0].id,
          JSON.stringify({ user_id: accountId, display_name: name, parent_admin_id: parentAdminId })]
      );
      return sendJson(res, 201, { ok: true, merchant: result.rows[0] });
    }

    const { id, status, action, password } = req.body || {};
    if (typeof id !== "string" || !/^[0-9a-f-]{36}$/i.test(id)) return sendJson(res, 400, { ok: false, message: "Invalid account" });

    if (action === "transfer_merchant") {
      if (actor.role !== "SUPER_ADMIN") return sendJson(res, 403, { ok: false, message: "Super Admin access required for transfers" });
      const newParent = req.body?.parent_admin_id ? String(req.body.parent_admin_id) : null;
      if (newParent && !/^[0-9a-f-]{36}$/i.test(newParent)) return sendJson(res, 400, { ok: false, message: "Invalid Admin selection" });
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const target = await client.query("SELECT id,user_id,display_name,parent_admin_id FROM sp_users WHERE id=$1 AND role='MERCHANT' FOR UPDATE", [id]);
        if (!target.rowCount) { await client.query("ROLLBACK"); return sendJson(res, 404, { ok: false, message: "Merchant not found" }); }
        if (newParent) {
          const parent = await client.query("SELECT id FROM sp_users WHERE id=$1 AND role='ADMIN' AND status='ACTIVE'", [newParent]);
          if (!parent.rowCount) { await client.query("ROLLBACK"); return sendJson(res, 400, { ok: false, message: "Selected Admin is not active" }); }
        }
        const previousParent = target.rows[0].parent_admin_id;
        await client.query("UPDATE sp_users SET parent_admin_id=$1,updated_at=now() WHERE id=$2", [newParent, id]);
        await client.query(
          "INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,$2,'MERCHANT',$3,$4)",
          [actor.sub, newParent ? "MERCHANT_TRANSFERRED" : "MERCHANT_UNASSIGNED", id,
            JSON.stringify({ merchant_user_id: target.rows[0].user_id, previous_parent_admin_id: previousParent, new_parent_admin_id: newParent })]
        );
        await client.query("COMMIT");
        return sendJson(res, 200, { ok: true, message: newParent ? "Merchant transferred successfully" : "Merchant unassigned successfully", merchant_id: id, parent_admin_id: newParent });
      } catch (e) {
        await client.query("ROLLBACK");
        throw e;
      } finally { client.release(); }
    }

    const targetRole = String(req.body?.role || "MERCHANT").toUpperCase();
    if (!["MERCHANT", "ADMIN"].includes(targetRole) || (actor.role === "ADMIN" && targetRole !== "MERCHANT")) {
      return sendJson(res, 403, { ok: false, message: "You cannot manage this account type" });
    }
    const scope = actor.role === "ADMIN" ? " AND parent_admin_id=$4" : "";
    const params = [id, targetRole];
    if (actor.role === "ADMIN") params.push(actor.sub);

    if (action === "reset_password") {
      if (typeof password !== "string" || password.length < 12 || password.length > 72) return sendJson(res, 400, { ok: false, message: "New password must be 12-72 characters" });
      const passwordHash = await bcrypt.hash(password, 12);
      const result = await pool.query(
        `UPDATE sp_users SET password_hash=$1,updated_at=now()
         WHERE id=$2 AND role=$3${scope}
         RETURNING id,user_id,email,display_name,role,status,created_at`,
        [passwordHash, ...params]
      );
      if (!result.rowCount) return sendJson(res, 404, { ok: false, message: "Account not found in your assigned scope" });
      await pool.query("INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,$2,$3,$4,$5)",
        [actor.sub, targetRole + "_PASSWORD_RESET", targetRole, id, JSON.stringify({ user_id: result.rows[0].user_id })]);
      return sendJson(res, 200, { ok: true, merchant: result.rows[0] });
    }

    if (!["ACTIVE", "SUSPENDED"].includes(status)) return sendJson(res, 400, { ok: false, message: "Invalid account status" });
    const result = await pool.query(
      `UPDATE sp_users SET status=$1,updated_at=now()
       WHERE id=$2 AND role=$3${scope}
       RETURNING id,user_id,email,display_name,role,status,created_at`,
      [status, ...params]
    );
    if (!result.rowCount) return sendJson(res, 404, { ok: false, message: "Account not found in your assigned scope" });
    await pool.query("INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,$2,$3,$4,$5)",
      [actor.sub, targetRole + "_STATUS_CHANGED", targetRole, id, JSON.stringify({ status })]);
    return sendJson(res, 200, { ok: true, merchant: result.rows[0] });
  } catch (error) {
    if (error.code === "23505") return sendJson(res, 409, { ok: false, message: "User ID or email already exists" });
    console.error("Merchant API error:", error.message);
    return sendJson(res, 500, { ok: false, message: error.code === "42703" ? "Run the latest parent-admin migration in Neon SQL Editor first." : "Merchant operation failed" });
  }
};
