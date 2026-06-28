import rateLimit from "express-rate-limit";
import { auditLog } from "../services/audit.service";
import { checkCoordinatedAbuse } from "../services/alert.service";

interface RateLimiterOptions {
  windowMs: number;
  limit: number;
  action: string;
  message?: string;
}

export function createRateLimiter(options: RateLimiterOptions) {
  return rateLimit({
    windowMs: options.windowMs,
    limit: options.limit,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: {
      error: options.message || "Too many requests, please try again later.",
    },
    handler: async (req, res, _next, rateLimitOptions) => {
      await auditLog({
        action: options.action,
        object: "rate_limit",
        requestData: {
          method: req.method,
          path: req.originalUrl,
          limit: options.limit,
          windowMs: options.windowMs,
        },
        req,
      });

      await checkCoordinatedAbuse(req.ip, req);

      return res.status(rateLimitOptions.statusCode).json(
        rateLimitOptions.message
      );
    },
  });
}

export const globalLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  limit: 100,
  action: "RATE_LIMIT_GLOBAL",
});

export const authLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  limit: 10,
  action: "RATE_LIMIT_AUTH",
  message: "Too many authentication attempts. Please try again later.",
});

export const sensitiveLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  limit: 20,
  action: "RATE_LIMIT_SENSITIVE",
  message: "Too many sensitive requests. Please try again later.",
});