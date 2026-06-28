import { Request, Response, NextFunction } from "express";
import {
  ACCESS_COOKIE,
  verifyAccessToken,
  SessionPayload,
} from "../services/session.service";
import { auditLog } from "../services/audit.service";
import { checkPrivilegeEscalationAttempt } from "../services/alert.service";
import { isSessionActive } from "../services/sessionRecord.service";

declare global {
  namespace Express {
    interface Request {
      user?: SessionPayload;
    }
  }
}

function getAccessTokenFromRequest(req: Request): string | null {
  const authHeader = req.headers.authorization;

  if (authHeader?.startsWith("Bearer ")) {
    return authHeader.slice("Bearer ".length).trim();
  }

  return req.cookies?.[ACCESS_COOKIE] || null;
}

export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const token = getAccessTokenFromRequest(req);

  if (!token) {
    return res.status(401).json({ error: "not_authenticated" });
  }

  try {
    const payload = verifyAccessToken(token);
    const active = await isSessionActive(payload.sessionId);

    if (!active) {
      await auditLog({
        action: "ACCESS_TOKEN_SESSION_INVALID",
        actorId: payload.sub,
        actorRole: payload.role || "user",
        object: "session",
        objectId: payload.sessionId,
        requestData: {
          reason:
            "Access token signature is valid, but the session is revoked, expired, or its trusted device is no longer valid.",
        },
        req,
      });

      return res.status(401).json({ error: "session_inactive" });
    }

    req.user = payload;
    return next();
  } catch (err: any) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ error: "token_expired" });
    }

    return res.status(401).json({ error: "invalid_token" });
  }
}

export function requireRole(...allowedRoles: string[]) {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      await auditLog({
        action: "AUTH_REQUIRED",
        object: "authorization",
        requestData: {
          path: req.originalUrl,
          method: req.method,
          requiredRoles: allowedRoles,
          reason: "User is not authenticated",
        },
        req,
      });

      return res.status(401).json({ error: "not_authenticated" });
    }

    const userId = req.user.sub;
    const userRole = req.user.role || "user";

    if (!allowedRoles.includes(userRole)) {
      await auditLog({
        action: "FORBIDDEN_ROLE_ACCESS",
        actorId: userId,
        actorRole: userRole,
        object: "authorization",
        requestData: {
          path: req.originalUrl,
          method: req.method,
          requiredRoles: allowedRoles,
          actualRole: userRole,
        },
        req,
      });

      await checkPrivilegeEscalationAttempt(userId, req);

      return res.status(403).json({ error: "forbidden" });
    }

    return next();
  };
}
