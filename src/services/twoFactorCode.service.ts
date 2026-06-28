import crypto from "crypto";
import { db } from "../config/database";
import { sendEmail } from "./email.service";
import { sendSms } from "./smsService";

const hashValue = (value: string) => {
  return crypto.createHash("sha256").update(value).digest("hex");
};

const generateCode = () => {
  return crypto.randomInt(100000, 1000000).toString();
};

export const sendEmailTwoFactorCode = async (userId: number, email: string) => {
  const code = generateCode();
  const codeHash = hashValue(code);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  await db.query(
    `INSERT INTO two_factor_codes (user_id, method, code_hash, expires_at)
     VALUES (?, 'email', ?, ?)`,
    [userId, codeHash, expiresAt]
  );

  await sendEmail(
    email,
    "Your 2FA verification code",
    `<h2>Your verification code is: ${code}</h2><p>This code expires in 10 minutes.</p>`
  );
};

export const sendSmsTwoFactorCode = async (userId: number, phone: string) => {
  const code = generateCode();
  const codeHash = hashValue(code);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  await db.query(
    `INSERT INTO two_factor_codes (user_id, method, code_hash, expires_at)
     VALUES (?, 'sms', ?, ?)`,
    [userId, codeHash, expiresAt]
  );

  await sendSms(phone, `Your SSSD verification code is: ${code}`);
};

export const verifyTwoFactorCode = async (
  userId: number,
  method: "email" | "sms",
  code: string
) => {
  const codeHash = hashValue(code.trim());

  const [rows]: any = await db.query(
    `SELECT id FROM two_factor_codes
     WHERE user_id = ?
     AND method = ?
     AND code_hash = ?
     AND used_at IS NULL
     AND expires_at > NOW()
     ORDER BY created_at DESC
     LIMIT 1`,
    [userId, method, codeHash]
  );

  if (rows.length === 0) {
    return { error: "Invalid or expired 2FA code" };
  }

  await db.query("UPDATE two_factor_codes SET used_at = NOW() WHERE id = ?", [
    rows[0].id
  ]);

  return { success: true };
};