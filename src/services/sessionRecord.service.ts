import { Request } from "express";
import { db } from "../config/database";

export async function createSessionRecord(
  userId: number,
  req: Request,
  expiresAt: Date,
  trustedDeviceId?: number | null
): Promise<number> {
  const [result]: any = await db.query(
    `INSERT INTO sessions
       (user_id, trusted_device_id, user_agent, ip_address, expires_at)
     VALUES (?, ?, ?, ?, ?)`,
    [
      userId,
      trustedDeviceId ?? null,
      req.headers["user-agent"] || null,
      req.ip || null,
      expiresAt,
    ]
  );

  return result.insertId;
}

export async function getSessionByRefreshTokenJti(refreshTokenJti: string) {
  const [rows]: any = await db.query(
    `SELECT s.*
     FROM sessions s
     JOIN refresh_tokens rt ON rt.session_id = s.id
     WHERE rt.jti = ?
     LIMIT 1`,
    [refreshTokenJti]
  );

  return rows.length > 0 ? rows[0] : null;
}

export async function isSessionActive(sessionId: number): Promise<boolean> {
  const [rows]: any = await db.query(
    `SELECT id
     FROM sessions
     WHERE id = ?
       AND revoked_at IS NULL
       AND expires_at > NOW()
     LIMIT 1`,
    [sessionId]
  );

  return rows.length > 0;
}

export async function revokeSession(sessionId: number): Promise<void> {
  await db.query(
    `UPDATE sessions
     SET revoked_at = NOW()
     WHERE id = ?
       AND revoked_at IS NULL`,
    [sessionId]
  );

  await db.query(
    `UPDATE refresh_tokens
     SET revoked_at = NOW()
     WHERE session_id = ?
       AND revoked_at IS NULL`,
    [sessionId]
  );
}

export async function revokeSessionByRefreshTokenJti(
  refreshTokenJti: string
): Promise<void> {
  const session = await getSessionByRefreshTokenJti(refreshTokenJti);

  if (!session) return;

  await revokeSession(session.id);
}

export async function revokeAllUserSessions(userId: number): Promise<void> {
  await db.query(
    `UPDATE sessions
     SET revoked_at = NOW()
     WHERE user_id = ?
       AND revoked_at IS NULL`,
    [userId]
  );

  await db.query(
    `UPDATE refresh_tokens
     SET revoked_at = NOW()
     WHERE user_id = ?
       AND revoked_at IS NULL`,
    [userId]
  );
}

export async function getActiveSessions(userId: number) {
  const [rows]: any = await db.query(
    `SELECT
        s.id,
        s.trusted_device_id,
        s.user_agent,
        s.ip_address,
        s.created_at,
        s.expires_at,
        s.revoked_at,
        td.expires_at AS trusted_device_expires_at,
        td.revoked_at AS trusted_device_revoked_at
     FROM sessions s
     LEFT JOIN trusted_devices td ON td.id = s.trusted_device_id
     WHERE s.user_id = ?
       AND s.revoked_at IS NULL
       AND s.expires_at > NOW()
     ORDER BY s.created_at DESC`,
    [userId]
  );

  return rows;
}

export async function revokeUserSession(
  userId: number,
  sessionId: number
): Promise<boolean> {
  const [result]: any = await db.query(
    `UPDATE sessions
     SET revoked_at = NOW()
     WHERE id = ?
       AND user_id = ?
       AND revoked_at IS NULL`,
    [sessionId, userId]
  );

  await db.query(
    `UPDATE refresh_tokens
     SET revoked_at = NOW()
     WHERE session_id = ?
       AND revoked_at IS NULL`,
    [sessionId]
  );

  return result.affectedRows > 0;
}

export async function revokeSessionsForTrustedDevice(
  userId: number,
  trustedDeviceId: number
): Promise<void> {
  await db.query(
    `UPDATE sessions
     SET revoked_at = NOW()
     WHERE user_id = ?
       AND trusted_device_id = ?
       AND revoked_at IS NULL`,
    [userId, trustedDeviceId]
  );

  await db.query(
    `UPDATE refresh_tokens rt
     JOIN sessions s ON s.id = rt.session_id
     SET rt.revoked_at = NOW()
     WHERE s.user_id = ?
       AND s.trusted_device_id = ?
       AND rt.revoked_at IS NULL`,
    [userId, trustedDeviceId]
  );
}
