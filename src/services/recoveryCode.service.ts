import crypto from "crypto";
import { db } from "../config/database";

const hashCode = (code: string) => {
  return crypto.createHash("sha256").update(code).digest("hex");
};

const normalizeRecoveryCode = (code: string) => {
  return code.trim().toUpperCase().replace(/\s+/g, "");
};

const generateRecoveryCode = () => {
  const raw = crypto.randomBytes(6).toString("hex").toUpperCase();
  return `${raw.slice(0, 6)}-${raw.slice(6)}`;
};

export const generateRecoveryCodes = async (userId: number) => {
  const codes: string[] = [];

  await db.query(
    "DELETE FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
    [userId]
  );

  for (let i = 0; i < 8; i++) {
    const code = generateRecoveryCode();
    codes.push(code);

    await db.query(
      `INSERT INTO recovery_codes (user_id, code_hash)
       VALUES (?, ?)`,
      [userId, hashCode(normalizeRecoveryCode(code))]
    );
  }

  return codes;
};

export const verifyRecoveryCode = async (userId: number, code: string) => {
  const normalizedCode = normalizeRecoveryCode(code);
  const codeHash = hashCode(normalizedCode);

  const [rows]: any = await db.query(
    `SELECT id FROM recovery_codes
     WHERE user_id = ?
     AND code_hash = ?
     AND used_at IS NULL
     LIMIT 1`,
    [userId, codeHash]
  );

  if (rows.length === 0) {
    return { error: "Invalid or already used recovery code" };
  }

  await db.query(
    "UPDATE recovery_codes SET used_at = NOW() WHERE id = ?",
    [rows[0].id]
  );

  return { success: true };
};