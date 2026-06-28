import { Request } from "express";
import { db } from "../config/database";
import { config } from "../config";
import { sendEmail } from "./email.service";

async function sendSecurityAlert(subject: string, message: string) {
  const adminEmail = config.adminAlertEmail || config.testEmail;

  if (!adminEmail) {
    console.warn("Security alert skipped: admin email is not configured.");
    return;
  }

  await sendEmail(
    adminEmail,
    subject,
    `
      <h2>${subject}</h2>
      <p>${message}</p>
      <p><strong>Time:</strong> ${new Date().toISOString()}</p>
    `
  );
}

export async function checkCredentialStuffing(
  identifier: string | undefined,
  req: Request
) {
  if (!identifier) return;

  const [rows]: any = await db.query(
    `SELECT COUNT(*) AS count
     FROM audit_logs
     WHERE action = 'LOGIN_FAILED'
       AND JSON_UNQUOTE(JSON_EXTRACT(request_data, '$.usernameOrEmail')) = ?
       AND created_at >= NOW() - INTERVAL 1 MINUTE`,
    [identifier]
  );

  if (rows[0].count >= 5) {
    await sendSecurityAlert(
      "HIGH Alert: Credential stuffing detected",
      `There were ${rows[0].count} failed login attempts for identifier "${identifier}" within 1 minute. IP: ${req.ip}`
    );
  }
}

export async function checkBruteForce(ipAddress: string | undefined, req: Request) {
  if (!ipAddress) return;

  const [rows]: any = await db.query(
    `SELECT COUNT(*) AS count
     FROM audit_logs
     WHERE action = 'LOGIN_FAILED'
       AND ip_address = ?
       AND created_at >= NOW() - INTERVAL 1 MINUTE`,
    [ipAddress]
  );

  if (rows[0].count >= 10) {
    await sendSecurityAlert(
      "HIGH Alert: Brute force detected",
      `There were ${rows[0].count} failed login attempts from IP ${ipAddress} within 1 minute. User-Agent: ${req.headers["user-agent"]}`
    );
  }
}

export async function checkCoordinatedAbuse(
  ipAddress: string | undefined,
  req: Request
) {
  if (!ipAddress) return;

  const [rows]: any = await db.query(
    `SELECT COUNT(*) AS count
     FROM audit_logs
     WHERE action IN ('RATE_LIMIT_AUTH', 'RATE_LIMIT_SENSITIVE', 'RATE_LIMIT_GLOBAL')
       AND ip_address = ?
       AND created_at >= NOW() - INTERVAL 5 MINUTE`,
    [ipAddress]
  );

  if (rows[0].count >= 20) {
    await sendSecurityAlert(
      "HIGH Alert: Coordinated abuse detected",
      `There were ${rows[0].count} rate-limit hits from IP ${ipAddress} within 5 minutes. User-Agent: ${req.headers["user-agent"]}`
    );
  }
}

export async function alertRefreshTokenReuse(
  userId: number | null,
  oldJti: string,
  replacedBy: string | null,
  req: Request
) {
  await sendSecurityAlert(
    "CRITICAL Alert: Refresh token reuse detected",
    `A revoked/replaced refresh token was used again.
User ID: ${userId ?? "unknown"}
Old token JTI: ${oldJti}
Replaced by: ${replacedBy ?? "none"}
IP: ${req.ip}
User-Agent: ${req.headers["user-agent"]}`
  );
}

export async function checkPrivilegeEscalationAttempt(
  userId: number | null,
  req: Request
) {
  if (!userId) return;

  const [rows]: any = await db.query(
    `SELECT COUNT(*) AS count
     FROM audit_logs
     WHERE action = 'FORBIDDEN_ROLE_ACCESS'
       AND actor_id = ?
       AND created_at >= NOW() - INTERVAL 5 MINUTE`,
    [userId]
  );

  if (rows[0].count >= 3) {
    await sendSecurityAlert(
      "CRITICAL Alert: Privilege escalation attempt",
      `User ID ${userId} had ${rows[0].count} forbidden role access attempts within 5 minutes. IP: ${req.ip}`
    );
  }
}