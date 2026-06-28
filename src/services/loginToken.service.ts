import crypto from "crypto";
import { db } from "../config/database";

const hashToken = (token: string) => {
  return crypto.createHash("sha256").update(token).digest("hex");
};

export const createLoginTwoFactorToken = async (userId: number) => {
  const token = crypto.randomBytes(32).toString("hex");
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  await db.query(
    `INSERT INTO login_2fa_tokens (user_id, token_hash, expires_at)
     VALUES (?, ?, ?)`,
    [userId, tokenHash, expiresAt]
  );

  return token;
};

export const consumeLoginTwoFactorToken = async (token: string) => {
  const tokenHash = hashToken(token);

  const [rows]: any = await db.query(
    `SELECT * FROM login_2fa_tokens
     WHERE token_hash = ?
     AND used_at IS NULL
     AND expires_at > NOW()
     LIMIT 1`,
    [tokenHash]
  );

  if (rows.length === 0) {
    return { error: "Invalid or expired login token" };
  }

  await db.query("UPDATE login_2fa_tokens SET used_at = NOW() WHERE id = ?", [
    rows[0].id
  ]);

  return {
    success: true,
    userId: rows[0].user_id
  };
};