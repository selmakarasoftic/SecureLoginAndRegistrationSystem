import crypto from "crypto";
import { Request, Response } from "express";
import { db } from "../config/database";
import { config } from "../config";

export const TRUSTED_DEVICE_COOKIE = "trusted_device";

function hashDeviceToken(token: string) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function trustedDeviceCookieOptions(expires: Date) {
  return {
    httpOnly: true,
    secure: config.nodeEnv === "production",
    sameSite: "lax" as const,
    path: "/api",
    expires,
  };
}

export async function createTrustedDevice(
  userId: number,
  req: Request,
  res: Response
) {
  const deviceToken = crypto.randomBytes(32).toString("hex");
  const deviceHash = hashDeviceToken(deviceToken);
  const expiresAt = new Date(Date.now() + 10 * 24 * 60 * 60 * 1000);

  const [result]: any = await db.query(
    `INSERT INTO trusted_devices
       (user_id, device_hash, user_agent, ip_address, expires_at)
     VALUES (?, ?, ?, ?, ?)`,
    [
      userId,
      deviceHash,
      req.headers["user-agent"] || null,
      req.ip || null,
      expiresAt,
    ]
  );

  res.cookie(
    TRUSTED_DEVICE_COOKIE,
    deviceToken,
    trustedDeviceCookieOptions(expiresAt)
  );

  return {
    id: result.insertId,
    expiresAt,
  };
}

export async function isTrustedDeviceValid(
  userId: number,
  req: Request
): Promise<boolean> {
  const deviceToken = req.cookies?.[TRUSTED_DEVICE_COOKIE];

  if (!deviceToken) {
    return false;
  }

  const deviceHash = hashDeviceToken(deviceToken);

  const [rows]: any = await db.query(
    `SELECT id
     FROM trusted_devices
     WHERE user_id = ?
       AND device_hash = ?
       AND revoked_at IS NULL
       AND expires_at > NOW()
     LIMIT 1`,
    [userId, deviceHash]
  );

  return rows.length > 0;
}


export async function getValidTrustedDevice(userId: number, req: Request) {
  const deviceToken = req.cookies?.[TRUSTED_DEVICE_COOKIE];

  if (!deviceToken) {
    return null;
  }

  const deviceHash = hashDeviceToken(deviceToken);

  const [rows]: any = await db.query(
    `SELECT id, user_id, expires_at, user_agent, ip_address
     FROM trusted_devices
     WHERE user_id = ?
       AND device_hash = ?
       AND revoked_at IS NULL
       AND expires_at > NOW()
     LIMIT 1`,
    [userId, deviceHash]
  );

  return rows.length > 0 ? rows[0] : null;
}

export async function getTrustedDevices(userId: number) {
  const [rows]: any = await db.query(
    `SELECT id, user_agent, ip_address, expires_at, revoked_at, created_at
     FROM trusted_devices
     WHERE user_id = ?
     ORDER BY created_at DESC`,
    [userId]
  );

  return rows;
}

export async function revokeTrustedDevice(userId: number, deviceId: number) {
  const [result]: any = await db.query(
    `UPDATE trusted_devices
     SET revoked_at = NOW()
     WHERE id = ?
       AND user_id = ?
       AND revoked_at IS NULL`,
    [deviceId, userId]
  );

  return result.affectedRows > 0;
}

export async function revokeExpiredTrustedDevices() {
  await db.query(
    `UPDATE trusted_devices
     SET revoked_at = NOW()
     WHERE expires_at <= NOW()
       AND revoked_at IS NULL`
  );
}