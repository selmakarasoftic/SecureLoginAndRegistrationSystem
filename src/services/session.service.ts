import jwt, { SignOptions } from "jsonwebtoken";
import { createHash, randomUUID } from "crypto";
import { config } from "../config";

export interface SessionUser {
  id: number;
  username: string;
  email: string;
  role?: string;
  sessionId?: number;
}

export interface SessionPayload {
  sub: number;
  username: string;
  email: string;
  role?: string;
  sessionId: number;
}

export interface RefreshPayload {
  sub: number;
  jti: string;
}

export const REFRESH_COOKIE = "refresh_token";
export const ACCESS_COOKIE = "access_token";

export function hashRefreshToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function signAccessToken(user: SessionUser): string {
  if (!config.session.accessSecret) {
    throw new Error("JWT_ACCESS_SECRET is missing");
  }

  if (!user.sessionId) {
    throw new Error("sessionId is required for access token signing");
  }

  const payload: SessionPayload = {
    sub: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
    sessionId: user.sessionId,
  };

  const options: SignOptions = {
    expiresIn: config.session.accessTtl as SignOptions["expiresIn"],
  };

  return jwt.sign(payload, config.session.accessSecret, options);
}

export function signRefreshToken(
  userId: number,
  ttl: SignOptions["expiresIn"] = config.session.refreshTtl as SignOptions["expiresIn"]
) {
  if (!config.session.refreshSecret) {
    throw new Error("JWT_REFRESH_SECRET is missing");
  }

  const jti = randomUUID();

  const options: SignOptions = {
    expiresIn: ttl,
    jwtid: jti,
  };

  const token = jwt.sign({ sub: userId }, config.session.refreshSecret, options);

  const decoded = jwt.decode(token) as { exp?: number } | null;

  if (!decoded?.exp) {
    throw new Error("Could not decode refresh token expiration");
  }

  return {
    token,
    tokenHash: hashRefreshToken(token),
    jti,
    expiresAt: new Date(decoded.exp * 1000),
  };
}

export function verifyAccessToken(token: string): SessionPayload {
  if (!config.session.accessSecret) {
    throw new Error("JWT_ACCESS_SECRET is missing");
  }

  const payload = jwt.verify(token, config.session.accessSecret);

  if (typeof payload === "string") {
    throw new Error("Invalid access token payload");
  }

  const sessionPayload = payload as unknown as SessionPayload;

  if (!sessionPayload.sessionId) {
    throw new Error("Access token is missing sessionId");
  }

  return sessionPayload;
}

export function verifyRefreshToken(token: string): RefreshPayload {
  if (!config.session.refreshSecret) {
    throw new Error("JWT_REFRESH_SECRET is missing");
  }

  const payload = jwt.verify(token, config.session.refreshSecret);

  if (typeof payload === "string") {
    throw new Error("Invalid refresh token payload");
  }

  return payload as unknown as RefreshPayload;
}

export function refreshCookieOptions(expires: Date) {
  return {
    httpOnly: true,
    secure: config.nodeEnv === "production",
    sameSite: "lax" as const,
    path: "/api",
    expires,
  };
}

export function clearRefreshCookieOptions() {
  return {
    httpOnly: true,
    secure: config.nodeEnv === "production",
    sameSite: "lax" as const,
    path: "/api",
  };
}

export function accessCookieOptions() {
  return {
    httpOnly: true,
    secure: config.nodeEnv === "production",
    sameSite: "lax" as const,
    path: "/api",
    maxAge: 15 * 60 * 1000,
  };
}

export function clearAccessCookieOptions() {
  return {
    httpOnly: true,
    secure: config.nodeEnv === "production",
    sameSite: "lax" as const,
    path: "/api",
  };
}
