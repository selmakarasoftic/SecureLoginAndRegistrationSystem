import crypto from "crypto";
import { db } from "../config/database";
import { config } from "../config";
import { sendEmail } from "./email.service";
import { validatePassword } from "../validators/password.validator";
import { isPasswordPwned } from "./hibp.service";
import { hashPassword } from "../utils/password";

function hashToken(token: string) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export async function createPasswordResetToken(userId: number, email: string) {
  const token = crypto.randomBytes(32).toString("hex");
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

  await db.query(
    `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
     VALUES (?, ?, ?)`,
    [userId, tokenHash, expiresAt]
  );

  const resetLink = `${config.appUrl}/front?resetToken=${token}`;

  await sendEmail(
    email,
    "Password reset request",
    `
      <h2>Password Reset</h2>
      <p>You requested a password reset.</p>
      <p>Click the link below to reset your password:</p>
      <a href="${resetLink}">Reset Password</a>
      <p>This link expires in 5 minutes and can only be used once.</p>
    `
  );

  return { success: true };
}

export async function resetPasswordWithToken(
  token: string,
  newPassword: string
) {
  if (!token || !newPassword) {
    return { error: "Token and new password are required" };
  }

  const tokenHash = hashToken(token);

  const [rows]: any = await db.query(
    `SELECT prt.*, u.email, u.role, u.email_verified, u.is_blocked
     FROM password_reset_tokens prt
     JOIN users u ON u.id = prt.user_id
     WHERE prt.token_hash = ?
     LIMIT 1`,
    [tokenHash]
  );

  if (rows.length === 0) {
    return { error: "Invalid password reset token" };
  }

  const resetToken = rows[0];

  if (resetToken.used_at !== null) {
    return { error: "Password reset link has already been used" };
  }

  if (new Date(resetToken.expires_at) < new Date()) {
    return { error: "Password reset link has expired" };
  }

  if (!resetToken.email_verified) {
    return { error: "Unverified accounts cannot recover passwords" };
  }

  if (resetToken.is_blocked) {
    return { error: "Blocked accounts cannot recover passwords" };
  }

  const windowStart = resetToken.attempt_window_start
    ? new Date(resetToken.attempt_window_start)
    : null;

  const windowExpired =
    !windowStart || windowStart.getTime() < Date.now() - 10 * 60 * 1000;

  const currentAttemptCount = windowExpired ? 0 : Number(resetToken.attempt_count);

  if (currentAttemptCount >= 2) {
    await db.query(
      `UPDATE password_reset_tokens
       SET used_at = NOW()
       WHERE id = ?`,
      [resetToken.id]
    );

    return {
      error:
        "Too many password reset attempts. Please initiate password reset again.",
    };
  }

  const passwordErrors = validatePassword(newPassword);

  if (passwordErrors.length > 0) {
    await recordFailedResetAttempt(resetToken.id, windowExpired);
    return { error: passwordErrors.join(", ") };
  }

  const pwned = await isPasswordPwned(newPassword);

  if (pwned) {
    await recordFailedResetAttempt(resetToken.id, windowExpired);
    return { error: "Password is compromised, choose another one" };
  }

  const passwordHash = await hashPassword(newPassword);

  const connection = await db.getConnection();

  try {
    await connection.beginTransaction();

    await connection.query(
      `UPDATE users
       SET password_hash = ?
       WHERE id = ?`,
      [passwordHash, resetToken.user_id]
    );

    await connection.query(
      `UPDATE password_reset_tokens
       SET used_at = NOW()
       WHERE id = ?`,
      [resetToken.id]
    );

    await connection.query(
      `UPDATE sessions
       SET revoked_at = NOW()
       WHERE user_id = ? AND revoked_at IS NULL`,
      [resetToken.user_id]
    );

    await connection.query(
      `UPDATE refresh_tokens
       SET revoked_at = NOW()
       WHERE user_id = ? AND revoked_at IS NULL`,
      [resetToken.user_id]
    );

    await connection.commit();
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }

  await sendEmail(
    resetToken.email,
    "Password changed successfully",
    `
      <h2>Password Changed</h2>
      <p>Your password was changed successfully.</p>
      <p>If this was not you, contact support immediately.</p>
    `
  );

  return {
    success: true,
    userId: resetToken.user_id,
    email: resetToken.email,
    role: resetToken.role || "user",
  };
}

async function recordFailedResetAttempt(
  resetTokenId: number,
  windowExpired: boolean
) {
  if (windowExpired) {
    await db.query(
      `UPDATE password_reset_tokens
       SET attempt_count = 1,
           attempt_window_start = NOW()
       WHERE id = ?`,
      [resetTokenId]
    );

    return;
  }

  await db.query(
    `UPDATE password_reset_tokens
     SET attempt_count = attempt_count + 1
     WHERE id = ?`,
    [resetTokenId]
  );
}