import { db } from "../config/database";

function normalize(value: string | undefined | null) {
  return value ? value.toLowerCase().trim() : "";
}

export async function isLoginCaptchaRequired(
  identifier: string | undefined,
  ipAddress: string | undefined
): Promise<boolean> {
  const normalizedIdentifier = normalize(identifier);

  const [rows]: any = await db.query(
    `SELECT COUNT(*) AS count
     FROM audit_logs
     WHERE action = 'LOGIN_FAILED'
       AND created_at >= NOW() - INTERVAL 10 MINUTE
       AND (
         JSON_UNQUOTE(JSON_EXTRACT(request_data, '$.usernameOrEmail')) = ?
         OR ip_address = ?
       )`,
    [normalizedIdentifier, ipAddress || ""]
  );

  return Number(rows[0].count) >= 3;
}

export async function isPasswordResetCaptchaRequired(
  email: string | undefined,
  ipAddress: string | undefined
): Promise<boolean> {
  const normalizedEmail = normalize(email);

  const [rows]: any = await db.query(
    `SELECT COUNT(*) AS count
     FROM audit_logs
     WHERE action IN ('PASSWORD_RESET_REQUEST_FAILED', 'PASSWORD_RESET_REQUESTED')
       AND created_at >= NOW() - INTERVAL 10 MINUTE
       AND (
         JSON_UNQUOTE(JSON_EXTRACT(request_data, '$.email')) = ?
         OR ip_address = ?
       )`,
    [normalizedEmail, ipAddress || ""]
  );

  return Number(rows[0].count) >= 2;
}