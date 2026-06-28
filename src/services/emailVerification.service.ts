import crypto from "crypto";
import { db } from "../config/database";
import { sendEmail } from "./email.service";

const hashToken = (token: string) => {
  return crypto.createHash("sha256").update(token).digest("hex");
};

export const sendVerificationEmail = async (userId: number, email: string) => {
  const token = crypto.randomBytes(32).toString("hex");
  const tokenHash = hashToken(token);

  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

  await db.query(
    `INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
     VALUES (?, ?, ?)`,
    [userId, tokenHash, expiresAt]
  );

  const verificationLink = `${process.env.APP_URL}/api/auth/verify-email?token=${token}`;

  await sendEmail(
    email,
    "Verify your email address",
    `
      <h2>Email Verification</h2>
      <p>Please verify your email by clicking the link below:</p>
      <a href="${verificationLink}">Verify Email</a>
      <p>This link expires in 15 minutes.</p>
    `
  );
};

export const verifyEmailToken = async (token: string) => {
  const tokenHash = hashToken(token);

  const [rows]: any = await db.query(
    `SELECT * FROM email_verification_tokens
     WHERE token_hash = ?
     AND used_at IS NULL
     AND expires_at > NOW()
     LIMIT 1`,
    [tokenHash]
  );

  if (rows.length === 0) {
    return { error: "Invalid or expired verification link" };
  }

  const verification = rows[0];

  await db.query("UPDATE users SET email_verified = TRUE WHERE id = ?", [
    verification.user_id
  ]);

  await db.query(
    "UPDATE email_verification_tokens SET used_at = NOW() WHERE id = ?",
    [verification.id]
  );

  return { success: true, userId: verification.user_id };
};