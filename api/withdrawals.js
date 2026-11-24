const { getPool } = require("./_lib/db");
const { sendJson, allowMethods } = require("./_lib/http");
const { verifyToken } = require("./_lib/auth");

function authenticate(req, res) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) { sendJson(res, 401, { ok: false, message: "Authentication required" }); return null; }
  try { return verifyToken(token); }
  catch { sendJson(res, 401, { ok: false, message: "Invalid or expired session" }); return null; }
}

module.exports = async (req, res) => {
  if (!allowMethods(req, res, ["GET", "POST", "PATCH"])) return;
  const actor = authenticate(req, res);
  if (!actor) return;
  if (!["MERCHANT", "ADMIN", "SUPER_ADMIN"].includes(actor.role)) {
    return sendJson(res, 403, { ok: false, message: "Access denied" });
  }

  const pool = getPool();
  try {
    if (req.method === "GET") {
      const scope = actor.role === "MERCHANT"
        ? "w.merchant_id=$1"
        : actor.role === "ADMIN" ? "u.parent_admin_id=$1" : "TRUE";
      const values = actor.role === "SUPER_ADMIN" ? [] : [actor.sub];
      const result = await pool.query(
        `SELECT w.id,w.merchant_id,u.user_id,u.display_name,w.account_id,
                a.account_name,a.provider_label,a.account_details,w.amount_inr,
                w.status,w.requested_at,w.reviewed_at,w.review_note,
                w.payout_reference,w.paid_at
         FROM sp_withdrawal_requests w
         JOIN sp_users u ON u.id=w.merchant_id
         JOIN sp_merchant_accounts a ON a.id=w.account_id
         WHERE ${scope}
         ORDER BY w.requested_at DESC LIMIT 300`,
        values
      );
      return sendJson(res, 200, { ok: true, requests: result.rows });
    }

    if (req.method === "POST") {
      if (actor.role !== "MERCHANT") return sendJson(res, 403, { ok: false, message: "Only Merchants can request withdrawals" });
      const accountId = String(req.body?.account_id || "");
      const amount = Number(req.body?.amount_inr);
      if (!/^[0-9a-f-]{36}$/i.test(accountId) || !Number.isFinite(amount) || amount <= 0 || amount > 100000000000) {
        return sendJson(res, 400, { ok: false, message: "Select an approved account and enter a valid amount" });
      }
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const account = await client.query(
          "SELECT id FROM sp_merchant_accounts WHERE id=$1 AND merchant_id=$2 AND status='APPROVED' FOR UPDATE",
          [accountId, actor.sub]
        );
        if (!account.rowCount) { await client.query("ROLLBACK"); return sendJson(res, 400, { ok: false, message: "Choose an approved withdrawal account" }); }
        await client.query("SELECT id FROM sp_users WHERE id=$1 AND role='MERCHANT' AND status='ACTIVE' FOR UPDATE", [actor.sub]);
        const balance = await client.query("SELECT COALESCE(SUM(amount_inr),0)::numeric AS balance FROM sp_ledger WHERE merchant_id=$1", [actor.sub]);
        const reserved = await client.query(
          "SELECT COALESCE(SUM(amount_inr),0)::numeric AS reserved FROM sp_withdrawal_requests WHERE merchant_id=$1 AND status IN ('PENDING','APPROVED')",
          [actor.sub]
        );
        const available = Number(balance.rows[0].balance) - Number(reserved.rows[0].reserved);
        if (amount > available + 0.000001) {
          await client.query("ROLLBACK");
          return sendJson(res, 409, { ok: false, message: "Insufficient available balance after pending withdrawal reservations", available_inr: Math.max(0, available) });
        }
        const saved = await client.query(
          "INSERT INTO sp_withdrawal_requests(merchant_id,account_id,amount_inr) VALUES($1,$2,$3) RETURNING id,amount_inr,status,requested_at",
          [actor.sub, accountId, amount.toFixed(2)]
        );
        await client.query(
          "INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,'WITHDRAWAL_REQUESTED','WITHDRAWAL',$2,$3)",
          [actor.sub, saved.rows[0].id, JSON.stringify({ account_id: accountId, amount_inr: amount })]
        );
        await client.query("COMMIT");
        return sendJson(res, 201, { ok: true, request: saved.rows[0], message: "Withdrawal request submitted for Admin review. No money has been transferred." });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally { client.release(); }
    }

    if (actor.role === "MERCHANT") return sendJson(res, 403, { ok: false, message: "Admin review required" });
    const id = String(req.body?.id || "");
    const action = String(req.body?.action || "");
    const note = String(req.body?.review_note || "").trim().slice(0, 500);
    if (!/^[0-9a-f-]{36}$/i.test(id) || !["approve", "reject", "mark_paid"].includes(action)) {
      return sendJson(res, 400, { ok: false, message: "Invalid withdrawal review action" });
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const request = await client.query(
        `SELECT w.*,u.parent_admin_id
         FROM sp_withdrawal_requests w JOIN sp_users u ON u.id=w.merchant_id
         WHERE w.id=$1 AND ($2='SUPER_ADMIN' OR ($2='ADMIN' AND u.parent_admin_id=$3))
         FOR UPDATE OF w,u`,
        [id, actor.role, actor.sub]
      );
      if (!request.rowCount) { await client.query("ROLLBACK"); return sendJson(res, 404, { ok: false, message: "Withdrawal request not found in your assigned scope" }); }
      const w = request.rows[0];

      if (action === "approve" || action === "reject") {
        if (w.status !== "PENDING") { await client.query("ROLLBACK"); return sendJson(res, 409, { ok: false, message: "Only pending requests can be approved or rejected" }); }
        const next = action === "approve" ? "APPROVED" : "REJECTED";
        const saved = await client.query(
          "UPDATE sp_withdrawal_requests SET status=$1,reviewed_by=$2,reviewed_at=now(),review_note=$3 WHERE id=$4 RETURNING id,status,amount_inr",
          [next, actor.sub, note, id]
        );
        await client.query(
          "INSERT INTO sp_notifications(user_id,title,message,category) VALUES($1,$2,$3,'WITHDRAWAL')",
          [w.merchant_id, next === "APPROVED" ? "Withdrawal approved" : "Withdrawal rejected",
           next === "APPROVED" ? "Your withdrawal request was approved. Payout is not yet confirmed." : "Your withdrawal request was rejected. " + note]
        );
        await client.query(
          "INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,$2,'WITHDRAWAL',$3,$4)",
          [actor.sub, "WITHDRAWAL_" + next, id, JSON.stringify({ amount_inr: w.amount_inr, review_note: note })]
        );
        await client.query("COMMIT");
        return sendJson(res, 200, { ok: true, request: saved.rows[0] });
      }

      if (w.status !== "APPROVED") { await client.query("ROLLBACK"); return sendJson(res, 409, { ok: false, message: "Only approved requests can be marked paid" }); }
      const payoutReference = String(req.body?.payout_reference || "").trim();
      if (payoutReference.length < 4 || payoutReference.length > 120) {
        await client.query("ROLLBACK");
        return sendJson(res, 400, { ok: false, message: "Enter the external bank / UPI transfer reference after completing the transfer" });
      }
      await client.query("SELECT id FROM sp_users WHERE id=$1 FOR UPDATE", [w.merchant_id]);
      const balance = await client.query("SELECT COALESCE(SUM(amount_inr),0)::numeric AS balance FROM sp_ledger WHERE merchant_id=$1", [w.merchant_id]);
      const reserved = await client.query(
        "SELECT COALESCE(SUM(amount_inr),0)::numeric AS reserved FROM sp_withdrawal_requests WHERE merchant_id=$1 AND status IN ('PENDING','APPROVED') AND id<>$2",
        [w.merchant_id, id]
      );
      if (Number(balance.rows[0].balance) - Number(reserved.rows[0].reserved) < Number(w.amount_inr) - 0.000001) {
        await client.query("ROLLBACK");
        return sendJson(res, 409, { ok: false, message: "Available balance is no longer sufficient to complete this payout" });
      }
      const ledgerReference = "WITHDRAWAL-" + id;
      await client.query(
        "INSERT INTO sp_ledger(merchant_id,reference,entry_type,amount_inr,description,created_by) VALUES($1,$2,'PAYMENT',$3,$4,$5)",
        [w.merchant_id, ledgerReference, -Number(w.amount_inr), "Withdrawal payout · " + payoutReference, actor.sub]
      );
      const saved = await client.query(
        "UPDATE sp_withdrawal_requests SET status='PAID',reviewed_by=$1,reviewed_at=COALESCE(reviewed_at,now()),payout_reference=$2,paid_at=now(),review_note=$3 WHERE id=$4 RETURNING id,status,amount_inr,payout_reference,paid_at",
        [actor.sub, payoutReference, note, id]
      );
      await client.query(
        "INSERT INTO sp_notifications(user_id,title,message,category) VALUES($1,'Withdrawal paid',$2,'WITHDRAWAL')",
        [w.merchant_id, "Your withdrawal of INR " + Number(w.amount_inr).toFixed(2) + " was marked paid. Reference: " + payoutReference]
      );
      await client.query(
        "INSERT INTO sp_audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,'WITHDRAWAL_PAID','WITHDRAWAL',$2,$3)",
        [actor.sub, id, JSON.stringify({ amount_inr: w.amount_inr, payout_reference: payoutReference, ledger_reference: ledgerReference })]
      );
      await client.query("COMMIT");
      return sendJson(res, 200, { ok: true, request: saved.rows[0], message: "Payout recorded. This endpoint does not initiate a bank transfer." });
    } catch (error) {
      await client.query("ROLLBACK");
      if (error.code === "23505") return sendJson(res, 409, { ok: false, message: "This payout reference or ledger entry has already been used" });
      throw error;
    } finally { client.release(); }
  } catch (error) {
    console.error("Withdrawal API error:", error.message);
    return sendJson(res, 500, { ok: false, message: error.code === "42P01" ? "Withdrawal table is missing. Apply db/withdrawal-requests.sql first." : "Unable to process withdrawal request" });
  }
};
