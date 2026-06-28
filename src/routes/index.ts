import { Router } from "express";
import { google } from "googleapis";
import crypto from "crypto";

import { registerUser, loginUser } from "../services/authSevice";
import { comparePassword, hashPassword } from "../utils/password";
import { validatePassword } from "../validators/password.validator";
import { isPasswordPwned } from "../services/hibp.service";
import { setupTwoFactor } from "../controllers/twoFactor.controller";
import { sendEmail } from "../services/email.service";
import { verifyEmailToken } from "../services/emailVerification.service";
import {
  sendEmailTwoFactorCode,
  sendSmsTwoFactorCode,
  verifyTwoFactorCode,
} from "../services/twoFactorCode.service";
import {
  generateRecoveryCodes,
  verifyRecoveryCode,
} from "../services/recoveryCode.service";
import { verifyTotpToken } from "../services/totp.service";
import { db } from "../config/database";
import { verifyHCaptcha } from "../services/hcaptcha.service";
import { auditLog } from "../services/audit.service";
import { config } from "../config";
import {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
  hashRefreshToken,
  refreshCookieOptions,
  clearRefreshCookieOptions,
  REFRESH_COOKIE,
  ACCESS_COOKIE,
  accessCookieOptions,
  clearAccessCookieOptions,
} from "../services/session.service";
import { requireAuth, requireRole } from "../middlewares/auth.middleware";
import {
  authLimiter,
  sensitiveLimiter,
} from "../middlewares/rateLimit.middleware";
import {
  checkCredentialStuffing,
  checkBruteForce,
  alertRefreshTokenReuse,
} from "../services/alert.service";
import {
  isLoginCaptchaRequired,
  isPasswordResetCaptchaRequired,
} from "../services/captchaPolicy.service";
import {
  createPasswordResetToken,
  resetPasswordWithToken,
} from "../services/passwordReset.service";
import {
  createTrustedDevice,
  getValidTrustedDevice,
  getTrustedDevices,
  revokeTrustedDevice,
} from "../services/trustedDevice.service";
import {
  createSessionRecord,
  getActiveSessions,
  isSessionActive,
  revokeSession,
  revokeSessionByRefreshTokenJti,
  revokeSessionsForTrustedDevice,
  revokeUserSession,
  revokeAllUserSessions,
} from "../services/sessionRecord.service";

export const router = Router();

const issuedGoogleStates = new Set<string>();
const issuedGithubStates = new Set<string>();

type TwoFactorMethod = "email" | "sms" | "totp";

const isTwoFactorMethod = (method: string): method is TwoFactorMethod => {
  return ["email", "sms", "totp"].includes(method);
};

const getUserById = async (userId: number) => {
  const [rows]: any = await db.query(
    `SELECT id, full_name, email, username, phone, role,
            email_verified, is_blocked,
            two_factor_secret, two_factor_enabled, two_factor_method
     FROM users
     WHERE id = ?
     LIMIT 1`,
    [userId]
  );

  return rows.length > 0 ? rows[0] : null;
};

const getUserByEmail = async (email: string) => {
  const [rows]: any = await db.query(
    `SELECT id, full_name, email, username, phone, role,
            email_verified, is_blocked,
            two_factor_secret, two_factor_enabled, two_factor_method
     FROM users
     WHERE email = ?
     LIMIT 1`,
    [email.toLowerCase()]
  );

  return rows.length > 0 ? rows[0] : null;
};


const sendLoginTwoFactorCodeForUser = async (user: any, req: any) => {
  console.log("===== LOGIN 2FA CODE FLOW STARTED =====");
  console.log("USER ID:", user?.id);
  console.log("2FA ENABLED:", user?.two_factor_enabled);
  console.log("2FA METHOD:", user?.two_factor_method);
  console.log("PHONE:", user?.phone);
  console.log("EMAIL:", user?.email);

  if (!user.two_factor_enabled || !user.two_factor_method) {
    throw new Error("2FA is not enabled for this user.");
  }

  if (user.two_factor_method === "email") {
    console.log("LOGIN 2FA: sending EMAIL code...");
    await sendEmailTwoFactorCode(user.id, user.email);
    console.log("LOGIN 2FA: EMAIL code function finished.");
    return { codeSent: true, method: "email" as const };
  }

  if (user.two_factor_method === "sms") {
    if (!user.phone) {
      throw new Error("User does not have a phone number for SMS 2FA.");
    }

    console.log("LOGIN 2FA: sending SMS code...");
    await sendSmsTwoFactorCode(user.id, user.phone);
    console.log("LOGIN 2FA: SMS code function finished.");
    return { codeSent: true, method: "sms" as const };
  }

  if (user.two_factor_method === "totp") {
    console.log("LOGIN 2FA: TOTP selected, no email/SMS code is sent.");
    return { codeSent: false, method: "totp" as const };
  }

  throw new Error("Unsupported 2FA method.");
};

const enableTwoFactor = async (userId: number, method: TwoFactorMethod) => {
  await db.query(
    "UPDATE users SET two_factor_enabled = TRUE, two_factor_method = ? WHERE id = ?",
    [method, userId]
  );

  return generateRecoveryCodes(userId);
};

const issueSessionForUser = async (
  req: any,
  res: any,
  user: any,
  trustedDeviceId?: number | null
) => {
  const refreshTtl = trustedDeviceId ? "10d" : config.session.refreshTtl;
  const {
    token: refreshToken,
    tokenHash: refreshTokenHash,
    jti,
    expiresAt,
  } = signRefreshToken(user.id, refreshTtl as any);

  const sessionId = await createSessionRecord(
    user.id,
    req,
    expiresAt,
    trustedDeviceId ?? null
  );

  const accessToken = signAccessToken({
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role || "user",
    sessionId,
  });

  await db.query(
    `INSERT INTO refresh_tokens
       (jti, token_hash, user_id, session_id, expires_at, user_agent, ip)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [
      jti,
      refreshTokenHash,
      user.id,
      sessionId,
      expiresAt,
      req.headers["user-agent"] || null,
      req.ip || null,
    ]
  );

  res.cookie(REFRESH_COOKIE, refreshToken, refreshCookieOptions(expiresAt));
  res.cookie(ACCESS_COOKIE, accessToken, accessCookieOptions());

  return accessToken;
};

async function startTwoFactorAfterSso(
  provider: "google" | "github",
  user: any,
  email: string,
  req: any,
  res: any,
  frontUrl: string
) {
  if (!user.two_factor_enabled) {
    await auditLog({
      action: `SSO_${provider.toUpperCase()}_2FA_SETUP_REQUIRED`,
      actorId: user.id,
      actorRole: user.role || "user",
      object: "user",
      objectId: user.id,
      requestData: {
        provider,
        email,
      },
      req,
    });

    const params = new URLSearchParams({
      provider,
      status: "requires_2fa_setup",
      userId: String(user.id),
    });

    return res.redirect(`${frontUrl}?${params.toString()}`);
  }

  if (user.two_factor_method === "email") {
    await sendEmailTwoFactorCode(user.id, user.email);
  }

  if (user.two_factor_method === "sms") {
    await sendSmsTwoFactorCode(user.id, user.phone);
  }

  await auditLog({
    action: `SSO_${provider.toUpperCase()}_2FA_REQUIRED`,
    actorId: user.id,
    actorRole: user.role || "user",
    object: "user",
    objectId: user.id,
    requestData: {
      provider,
      email,
      twoFactorMethod: user.two_factor_method || null,
    },
    req,
  });

  const params = new URLSearchParams({
    provider,
    status: "requires_2fa",
    userId: String(user.id),
    twoFactorMethod: user.two_factor_method || "",
  });

  return res.redirect(`${frontUrl}?${params.toString()}`);
}

async function validateSsoLocalAccount(
  provider: "google" | "github",
  email: string,
  fullName: string,
  req: any,
  res: any,
  frontUrl: string
) {
  const user = await getUserByEmail(email);
  const providerUpper = provider.toUpperCase();

  if (!user) {
    await auditLog({
      action: `SSO_${providerUpper}_ACCOUNT_NOT_FOUND`,
      object: "user",
      requestData: {
        provider,
        email,
        fullName,
        reason: `No local account matches the ${provider} email address`,
      },
      req,
    });

    res.redirect(
      `${frontUrl}?provider=${provider}&status=error&reason=account_not_found`
    );
    return null;
  }

  if (user.is_blocked) {
    await auditLog({
      action: `SSO_${providerUpper}_BLOCKED_ACCOUNT`,
      actorId: user.id,
      actorRole: user.role || "user",
      object: "user",
      objectId: user.id,
      requestData: {
        provider,
        email,
        reason: "Blocked account attempted SSO login",
      },
      req,
    });

    res.redirect(
      `${frontUrl}?provider=${provider}&status=error&reason=account_blocked`
    );
    return null;
  }

  if (!user.email_verified) {
    await auditLog({
      action: `SSO_${providerUpper}_UNVERIFIED_ACCOUNT`,
      actorId: user.id,
      actorRole: user.role || "user",
      object: "user",
      objectId: user.id,
      requestData: {
        provider,
        email,
        reason: "Unverified account attempted SSO login",
      },
      req,
    });

    res.redirect(
      `${frontUrl}?provider=${provider}&status=error&reason=email_not_verified`
    );
    return null;
  }

  return user;
}

router.get("/health", (_req, res) => {
  return res.status(200).json({ status: "ok" });
});

router.get("/public-config", (_req, res) => {
  return res.json({
    hCaptchaSiteKey: config.hCaptcha.siteKey,
  });
});

router.get("/success", (_req, res) => {
  return res.send(`
    <html>
      <head><title>Login Successful</title></head>
      <body style="font-family: Arial; padding: 40px; background:#f4f7fb;">
        <div style="max-width:650px;margin:auto;background:white;padding:30px;border-radius:14px;box-shadow:0 4px 18px #0001;">
          <h1>Login successful</h1>
          <p>The user is logged in and 2FA is enabled.</p>
        </div>
      </body>
    </html>
  `);
});

router.get("/google-login", (_req, res) => {
  if (
    !config.google.clientId ||
    !config.google.clientSecret ||
    !config.google.redirectUri
  ) {
    return res.status(500).json({
      message: "Google SSO is not configured properly.",
    });
  }

  const state = crypto.randomBytes(16).toString("hex");
  issuedGoogleStates.add(state);

  const client = new google.auth.OAuth2(
    config.google.clientId,
    config.google.clientSecret,
    config.google.redirectUri
  );

  const authUrl = client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: ["openid", "email", "profile"],
    state,
  });

  return res.json({ authUrl });
});

router.get("/google-callback", async (req, res) => {
  const code = req.query.code as string | undefined;
  const state = req.query.state as string | undefined;
  const frontUrl = `${config.appUrl}/front`;

  if (!code) {
    return res.redirect(
      `${frontUrl}?provider=google&status=error&reason=missing_code`
    );
  }

  if (!state || !issuedGoogleStates.has(state)) {
    return res.redirect(
      `${frontUrl}?provider=google&status=error&reason=bad_state`
    );
  }

  issuedGoogleStates.delete(state);

  try {
    const client = new google.auth.OAuth2(
      config.google.clientId,
      config.google.clientSecret,
      config.google.redirectUri
    );

    const { tokens } = await client.getToken(code);
    client.setCredentials(tokens);

    const oauth2 = google.oauth2({ version: "v2", auth: client });
    const { data: userInfo } = await oauth2.userinfo.get();

    const email = (userInfo.email || "").toLowerCase();
    const firstName = userInfo.given_name || "";
    const lastName = userInfo.family_name || "";
    const fullName = `${firstName} ${lastName}`.trim();

    if (!email) {
      return res.redirect(
        `${frontUrl}?provider=google&status=error&reason=email_missing`
      );
    }

    const user = await validateSsoLocalAccount(
      "google",
      email,
      fullName,
      req,
      res,
      frontUrl
    );

    if (!user) return;

    return startTwoFactorAfterSso("google", user, email, req, res, frontUrl);
  } catch (error: any) {
    console.error("Google callback error:", error?.response?.data || error);
    return res.redirect(
      `${frontUrl}?provider=google&status=error&reason=oauth_failed`
    );
  }
});

router.get("/github-login", (_req, res) => {
  if (
    !config.github.clientId ||
    !config.github.clientSecret ||
    !config.github.redirectUri
  ) {
    return res.status(500).json({
      message: "GitHub SSO is not configured properly.",
    });
  }

  const state = crypto.randomBytes(16).toString("hex");
  issuedGithubStates.add(state);

  const params = new URLSearchParams({
    client_id: config.github.clientId,
    redirect_uri: config.github.redirectUri,
    scope: "read:user user:email",
    state,
    allow_signup: "false",
  });

  return res.json({
    authUrl: `https://github.com/login/oauth/authorize?${params.toString()}`,
  });
});

async function getGitHubPrimaryEmail(accessToken: string) {
  const emailRes = await fetch("https://api.github.com/user/emails", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "sssd-2026-project",
    },
  });

  if (!emailRes.ok) {
    return "";
  }

  const emails = (await emailRes.json()) as Array<{
    email: string;
    primary: boolean;
    verified: boolean;
  }>;

  const primaryVerified = emails.find((item) => item.primary && item.verified);
  const firstVerified = emails.find((item) => item.verified);

  return (primaryVerified?.email || firstVerified?.email || "").toLowerCase();
}

router.get("/github-callback", async (req, res) => {
  const code = req.query.code as string | undefined;
  const state = req.query.state as string | undefined;
  const frontUrl = `${config.appUrl}/front`;

  if (!code) {
    return res.redirect(
      `${frontUrl}?provider=github&status=error&reason=missing_code`
    );
  }

  if (!state || !issuedGithubStates.has(state)) {
    return res.redirect(
      `${frontUrl}?provider=github&status=error&reason=bad_state`
    );
  }

  issuedGithubStates.delete(state);

  try {
    const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        client_id: config.github.clientId,
        client_secret: config.github.clientSecret,
        code,
        redirect_uri: config.github.redirectUri,
      }),
    });

    const tokenData = (await tokenRes.json()) as { access_token?: string };

    if (!tokenData.access_token) {
      throw new Error("GitHub access token was not returned");
    }

    const userRes = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "sssd-2026-project",
      },
    });

    const githubUser = (await userRes.json()) as {
      login?: string;
      name?: string | null;
      email?: string | null;
    };

    const email = (
      githubUser.email || (await getGitHubPrimaryEmail(tokenData.access_token))
    ).toLowerCase();
    const fullName = githubUser.name || githubUser.login || "";

    if (!email) {
      return res.redirect(
        `${frontUrl}?provider=github&status=error&reason=email_missing`
      );
    }

    const user = await validateSsoLocalAccount(
      "github",
      email,
      fullName,
      req,
      res,
      frontUrl
    );

    if (!user) return;

    return startTwoFactorAfterSso("github", user, email, req, res, frontUrl);
  } catch (error) {
    console.error("GitHub callback error:", error);
    return res.redirect(
      `${frontUrl}?provider=github&status=error&reason=oauth_failed`
    );
  }
});

router.post("/register", async (req, res) => {
  try {
    const result = await registerUser(req.body);

    if (result.error) {
      return res.status(400).json({ message: result.error });
    }

    await auditLog({
      action: "USER_REGISTERED",
      object: "user",
      requestData: {
        email: req.body.email,
        username: req.body.username,
      },
      req,
    });

    return res.status(201).json({
      message: "Registration successful. Verification email sent.",
      user: result.data,
    });
  } catch (error) {
    console.error("Register error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

router.post("/login", authLimiter, async (req, res) => {
  try {
    const usernameOrEmail = req.body.usernameOrEmail;
    const captchaToken =
      req.body.captchaToken || req.body["h-captcha-response"];

    const captchaRequired = await isLoginCaptchaRequired(
      usernameOrEmail,
      req.ip
    );

    if (captchaRequired) {
      if (!captchaToken) {
        await auditLog({
          action: "LOGIN_CAPTCHA_REQUIRED",
          object: "captcha",
          requestData: {
            usernameOrEmail,
            reason: "Captcha token is required after repeated failed login attempts",
          },
          req,
        });

        return res.status(400).json({
          message:
            "Too many failed login attempts. Please complete the CAPTCHA before trying again.",
          captchaRequired: true,
        });
      }

      const captchaResult = await verifyHCaptcha(captchaToken);

      if (!captchaResult.success) {
        await auditLog({
          action: "LOGIN_CAPTCHA_FAILED",
          object: "captcha",
          requestData: {
            usernameOrEmail,
            reason: captchaResult.error || "Captcha verification failed",
          },
          req,
        });

        return res.status(400).json({
          message: captchaResult.error || "Captcha verification failed",
          captchaRequired: true,
        });
      }

      await auditLog({
        action: "LOGIN_CAPTCHA_PASSED",
        object: "captcha",
        requestData: { usernameOrEmail },
        req,
      });
    }

    const result = await loginUser(req.body);

    if (result.error === "usernameOrEmail and password are required") {
      await auditLog({
        action: "LOGIN_FAILED_MISSING_FIELDS",
        object: "user",
        requestData: {
          usernameOrEmail,
          reason: result.error,
        },
        req,
      });

      return res.status(400).json({
        message: result.error,
        captchaRequired,
      });
    }

    if (result.error) {
      await auditLog({
        action: "LOGIN_FAILED",
        object: "user",
        requestData: {
          usernameOrEmail,
          reason: result.error,
        },
        req,
      });

      await checkCredentialStuffing(usernameOrEmail, req);
      await checkBruteForce(req.ip, req);

      const captchaRequiredAfterFailure = await isLoginCaptchaRequired(
        usernameOrEmail,
        req.ip
      );

      const status = result.error === "User does not exist" ? 404 : 401;

      return res.status(status).json({
        message: result.error,
        captchaRequired: captchaRequiredAfterFailure,
      });
    }

    if (result.requiresTwoFactor && result.userId) {
      const trustedDevice = await getValidTrustedDevice(result.userId, req);

      if (trustedDevice) {
        await auditLog({
          action: "TRUSTED_DEVICE_2FA_BYPASS_USED",
          actorId: result.userId,
          actorRole: result.role || "user",
          object: "trusted_device",
          objectId: result.userId,
          requestData: {
            usernameOrEmail,
            reason: "Valid trusted device cookie found after credential login",
          },
          req,
        });

        const user = await getUserById(result.userId);

        if (!user) {
          return res.status(404).json({ message: "User does not exist" });
        }

        const accessToken = await issueSessionForUser(
          req,
          res,
          user,
          trustedDevice.id
        );

        return res.status(200).json({
          message:
            "Login successful. Trusted device recognized, 2FA was bypassed.",
          trustedDeviceUsed: true,
          captchaRequired: false,
          accessToken,
          redirectTo: "/api/success",
        });
      }
    }

    if (result.requiresTwoFactorSetup) {
      await auditLog({
        action: "LOGIN_CREDENTIALS_VALID_2FA_SETUP_REQUIRED",
        actorId: result.userId,
        actorRole: result.role || "user",
        object: "user",
        objectId: result.userId,
        req,
      });

      return res.status(200).json({
        message:
          "Credentials are correct. User must set up 2FA before accessing the system.",
        nextStep: "Choose one method: email, sms, or totp.",
        captchaRequired: false,
        ...result,
      });
    }

    const user = await getUserById(result.userId);

    if (!user) {
      return res.status(404).json({ message: "User does not exist" });
    }

    const twoFactorSendResult = await sendLoginTwoFactorCodeForUser(user, req);

    await auditLog({
      action: "LOGIN_CREDENTIALS_VALID_2FA_REQUIRED",
      actorId: result.userId,
      actorRole: result.role || "user",
      object: "user",
      objectId: result.userId,
      requestData: {
        twoFactorMethod: twoFactorSendResult.method,
        codeSentByBackend: twoFactorSendResult.codeSent,
      },
      req,
    });

    return res.status(200).json({
      message: twoFactorSendResult.codeSent
        ? "Credentials are correct. Two-factor code has been sent."
        : "Credentials are correct. Two-factor verification is required.",
      nextStep: "Verify the configured 2FA method or use a recovery code.",
      captchaRequired: false,
      codeSent: twoFactorSendResult.codeSent,
      ...result,
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

router.get("/test-email", async (_req, res) => {
  const testEmail = process.env.TEST_EMAIL;

  if (!testEmail) {
    return res.status(500).json({ message: "TEST_EMAIL not set" });
  }

  await sendEmail(testEmail, "SSSD Test Email", "<h1>Email sending works</h1>");

  return res.json({ message: "Email sent" });
});

router.get("/auth/verify-email", async (req, res) => {
  const token = req.query.token as string;

  if (!token) {
    return res.status(400).json({ message: "Token is required" });
  }

  const result = await verifyEmailToken(token);

  if (result.error) {
    return res.status(400).json({ message: result.error });
  }

  await auditLog({
    action: "EMAIL_VERIFIED",
    actorId: result.userId,
    actorRole: "user",
    object: "user",
    objectId: result.userId,
    requestData: { tokenUsed: true },
    req,
  });

  return res.status(200).send(`
    <html>
      <body style="font-family: Arial; padding: 40px;">
        <h1>Email verified successfully</h1>
        <p>You can now log in and set up two-factor authentication.</p>
      </body>
    </html>
  `);
});

router.post("/auth/2fa/setup", setupTwoFactor);

router.post("/auth/2fa/setup/send-code", authLimiter, async (req, res) => {
  const { userId, method } = req.body;

  if (!userId || !method || !["email", "sms"].includes(method)) {
    return res
      .status(400)
      .json({ message: "userId and method=email|sms are required" });
  }

  const user = await getUserById(Number(userId));

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  if (method === "email") {
    await sendEmailTwoFactorCode(user.id, user.email);
  } else {
    await sendSmsTwoFactorCode(user.id, user.phone);
  }

  await auditLog({
    action: "TWO_FACTOR_SETUP_CODE_SENT",
    actorId: user.id,
    actorRole: user.role || "user",
    object: "user",
    objectId: user.id,
    requestData: { method },
    req,
  });

  return res.json({ message: `${method.toUpperCase()} 2FA setup code sent` });
});

router.post("/auth/2fa/setup/verify", authLimiter, async (req, res) => {
  const { userId, method, code } = req.body;

  if (!userId || !method || !code || !isTwoFactorMethod(method)) {
    return res
      .status(400)
      .json({ message: "userId, method and code are required" });
  }

  const user = await getUserById(Number(userId));

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  let valid = false;

  if (method === "totp") {
    if (!user.two_factor_secret) {
      return res.status(400).json({ message: "TOTP setup was not generated" });
    }

    valid = await verifyTotpToken(code, user.two_factor_secret);
  } else {
    const result = await verifyTwoFactorCode(user.id, method, code);

    if (result.error) {
      return res.status(401).json({ message: result.error });
    }

    valid = true;
  }

  if (!valid) {
    await auditLog({
      action: "TWO_FACTOR_SETUP_FAILED",
      actorId: user.id,
      actorRole: user.role || "user",
      object: "user",
      objectId: user.id,
      requestData: { method },
      req,
    });

    return res.status(401).json({ message: "Invalid 2FA code" });
  }

  const recoveryCodes = await enableTwoFactor(user.id, method);

  await auditLog({
    action: "TWO_FACTOR_ENABLED",
    actorId: user.id,
    actorRole: user.role || "user",
    object: "user",
    objectId: user.id,
    requestData: { method },
    req,
  });

  return res.status(200).json({
    message: "2FA enabled successfully. Save your recovery codes now.",
    recoveryCodes,
  });
});

router.post("/auth/2fa/login/send-code", authLimiter, async (req, res) => {
  try {
    console.log("===== HIT /auth/2fa/login/send-code =====");
    console.log("BODY:", req.body);

    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ message: "userId is required" });
    }

    const user = await getUserById(Number(userId));

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const sendResult = await sendLoginTwoFactorCodeForUser(user, req);

    if (sendResult.method === "totp") {
      return res.status(400).json({
        message: "TOTP users should use their authenticator app code directly.",
      });
    }

    await auditLog({
      action: "TWO_FACTOR_LOGIN_CODE_SENT",
      actorId: user.id,
      actorRole: user.role || "user",
      object: "user",
      objectId: user.id,
      requestData: {
        method: sendResult.method,
        codeSent: sendResult.codeSent,
      },
      req,
    });

    return res.status(200).json({
      message: `${String(sendResult.method).toUpperCase()} login code sent`,
      codeSent: sendResult.codeSent,
      method: sendResult.method,
    });
  } catch (error: any) {
    console.error("Send login 2FA code error:", error);

    return res.status(500).json({
      message: error?.message || "Failed to send login 2FA code.",
    });
  }
});

router.post("/auth/2fa/login/verify", authLimiter, async (req, res) => {
  const { userId, code, ssoProvider } = req.body;
  const normalizedSsoProvider =
    ssoProvider === "google" || ssoProvider === "github" ? ssoProvider : null;

  if (!userId || !code) {
    return res.status(400).json({ message: "userId and code are required" });
  }

  const user = await getUserById(Number(userId));

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  if (!user.two_factor_enabled || !user.two_factor_method) {
    return res.status(400).json({ message: "2FA is not enabled" });
  }

  let valid = false;

  if (user.two_factor_method === "totp") {
    if (!user.two_factor_secret) {
      return res.status(400).json({ message: "TOTP is not configured" });
    }

    valid = await verifyTotpToken(code, user.two_factor_secret);
  } else {
    const result = await verifyTwoFactorCode(
      user.id,
      user.two_factor_method,
      code
    );

    if (result.error) {
      await auditLog({
        action: "TWO_FACTOR_LOGIN_FAILED",
        actorId: user.id,
        actorRole: user.role || "user",
        object: "user",
        objectId: user.id,
        requestData: {
          method: user.two_factor_method,
          reason: result.error,
        },
        req,
      });

      return res.status(401).json({ message: result.error });
    }

    valid = true;
  }

  if (!valid) {
    await auditLog({
      action: "TWO_FACTOR_LOGIN_FAILED",
      actorId: user.id,
      actorRole: user.role || "user",
      object: "user",
      objectId: user.id,
      requestData: { method: user.two_factor_method },
      req,
    });

    return res.status(401).json({ message: "Invalid 2FA code" });
  }

  let trustedDevice = null;
  let trustedDeviceId: number | null = null;

  if (req.body.trustDevice === true) {
    trustedDevice = await createTrustedDevice(user.id, req, res);
    trustedDeviceId = trustedDevice.id;

    await auditLog({
      action: "TRUSTED_DEVICE_CREATED",
      actorId: user.id,
      actorRole: user.role || "user",
      object: "trusted_device",
      objectId: trustedDevice.id,
      requestData: {
        expiresAt: trustedDevice.expiresAt,
        method: "2fa_login",
      },
      req,
    });
  }

  const accessToken = await issueSessionForUser(
    req,
    res,
    user,
    trustedDeviceId
  );

  await auditLog({
    action: normalizedSsoProvider
      ? `SSO_${normalizedSsoProvider.toUpperCase()}_LOGIN_SUCCESS`
      : "TWO_FACTOR_LOGIN_SUCCESS",
    actorId: user.id,
    actorRole: user.role || "user",
    object: "user",
    objectId: user.id,
    requestData: {
      provider: normalizedSsoProvider,
      twoFactorMethod: user.two_factor_method,
    },
    req,
  });

  return res.status(200).json({
    message: "Login successful. 2FA verified.",
    accessToken,
    trustedDevice,
    redirectTo: "/api/success",
  });
});

router.post("/auth/2fa/recovery/verify", authLimiter, async (req, res) => {
  const { userId, code } = req.body;

  if (!userId || !code) {
    return res.status(400).json({ message: "userId and code are required" });
  }

  const user = await getUserById(Number(userId));

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  if (!user.two_factor_enabled) {
    return res.status(400).json({ message: "2FA is not enabled" });
  }

  const result = await verifyRecoveryCode(user.id, code);

  if (result.error) {
    await auditLog({
      action: "RECOVERY_CODE_LOGIN_FAILED",
      actorId: user.id,
      actorRole: user.role || "user",
      object: "user",
      objectId: user.id,
      requestData: { reason: result.error },
      req,
    });

    return res.status(401).json({ message: result.error });
  }

  let trustedDevice = null;
  let trustedDeviceId: number | null = null;

  if (req.body.trustDevice === true) {
    trustedDevice = await createTrustedDevice(user.id, req, res);
    trustedDeviceId = trustedDevice.id;

    await auditLog({
      action: "TRUSTED_DEVICE_CREATED",
      actorId: user.id,
      actorRole: user.role || "user",
      object: "trusted_device",
      objectId: trustedDevice.id,
      requestData: {
        expiresAt: trustedDevice.expiresAt,
        method: "recovery_code",
      },
      req,
    });
  }

  const accessToken = await issueSessionForUser(
    req,
    res,
    user,
    trustedDeviceId
  );

  await auditLog({
    action: "RECOVERY_CODE_LOGIN_SUCCESS",
    actorId: user.id,
    actorRole: user.role || "user",
    object: "user",
    objectId: user.id,
    req,
  });

  return res.status(200).json({
    message:
      "Login successful with recovery code. This recovery code is now marked as used.",
    accessToken,
    trustedDevice,
    redirectTo: "/api/success",
  });
});

router.post("/password-reset/request", authLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || "").toLowerCase().trim();
    const captchaToken =
      req.body.captchaToken || req.body["h-captcha-response"];

    const captchaRequired = await isPasswordResetCaptchaRequired(email, req.ip);

    if (captchaRequired) {
      if (!captchaToken) {
        await auditLog({
          action: "PASSWORD_RESET_CAPTCHA_REQUIRED",
          object: "captcha",
          requestData: {
            email,
            reason: "Captcha token is required after repeated password reset attempts",
          },
          req,
        });

        return res.status(400).json({
          message:
            "Too many password reset attempts. Please complete the CAPTCHA before trying again.",
          captchaRequired: true,
        });
      }

      const captchaResult = await verifyHCaptcha(captchaToken);

      if (!captchaResult.success) {
        await auditLog({
          action: "PASSWORD_RESET_CAPTCHA_FAILED",
          object: "captcha",
          requestData: {
            email,
            reason: captchaResult.error || "Captcha verification failed",
          },
          req,
        });

        return res.status(400).json({
          message: captchaResult.error || "Captcha verification failed",
          captchaRequired: true,
        });
      }

      await auditLog({
        action: "PASSWORD_RESET_CAPTCHA_PASSED",
        object: "captcha",
        requestData: { email },
        req,
      });
    }

    if (!email) {
      await auditLog({
        action: "PASSWORD_RESET_REQUEST_FAILED",
        object: "user",
        requestData: {
          email,
          reason: "Email is required",
        },
        req,
      });

      return res.status(400).json({
        message: "Email is required",
        captchaRequired,
      });
    }

    const user = await getUserByEmail(email);

    if (!user) {
      await auditLog({
        action: "PASSWORD_RESET_REQUEST_FAILED",
        object: "user",
        requestData: {
          email,
          reason: "User does not exist",
        },
        req,
      });

      const captchaRequiredAfterFailure =
        await isPasswordResetCaptchaRequired(email, req.ip);

      return res.status(404).json({
        message: "User with this email does not exist",
        captchaRequired: captchaRequiredAfterFailure,
      });
    }

    if (!user.email_verified) {
      await auditLog({
        action: "PASSWORD_RESET_REQUEST_FAILED",
        actorId: user.id,
        actorRole: user.role || "user",
        object: "user",
        objectId: user.id,
        requestData: {
          email,
          reason: "Unverified account cannot recover password",
        },
        req,
      });

      const captchaRequiredAfterFailure =
        await isPasswordResetCaptchaRequired(email, req.ip);

      return res.status(403).json({
        message: "Unverified accounts cannot recover passwords",
        captchaRequired: captchaRequiredAfterFailure,
      });
    }

    if (user.is_blocked) {
      await auditLog({
        action: "PASSWORD_RESET_REQUEST_FAILED",
        actorId: user.id,
        actorRole: user.role || "user",
        object: "user",
        objectId: user.id,
        requestData: {
          email,
          reason: "Blocked account cannot recover password",
        },
        req,
      });

      return res.status(403).json({
        message: "Blocked accounts cannot recover passwords",
        captchaRequired,
      });
    }

    await createPasswordResetToken(user.id, user.email);

    await auditLog({
      action: "PASSWORD_RESET_REQUESTED",
      actorId: user.id,
      actorRole: user.role || "user",
      object: "password_reset",
      objectId: user.id,
      requestData: { email },
      req,
    });

    return res.status(200).json({
      message: "Password reset link was sent to your email.",
      captchaRequired: false,
    });
  } catch (error) {
    console.error("Password reset request error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

router.post("/password-reset/confirm", authLimiter, async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    const result = await resetPasswordWithToken(token, newPassword);

    if (result.error) {
      await auditLog({
        action: "PASSWORD_RESET_FAILED",
        object: "password_reset",
        requestData: { reason: result.error },
        req,
      });

      return res.status(400).json({ message: result.error });
    }

    await auditLog({
      action: "PASSWORD_RESET_SUCCESS",
      actorId: result.userId,
      actorRole: result.role || "user",
      object: "user",
      objectId: result.userId,
      requestData: {
        email: result.email,
        sessionsRevoked: true,
      },
      req,
    });

    return res.status(200).json({
      message:
        "Password was reset successfully. Please log in again with your new password.",
    });
  } catch (error) {
    console.error("Password reset confirm error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

router.post("/logout", sensitiveLimiter, async (req, res) => {
  const refreshToken = req.cookies?.[REFRESH_COOKIE];

  if (refreshToken) {
    try {
      const payload = verifyRefreshToken(refreshToken);

      await auditLog({
        action: "LOGOUT_SUCCESS",
        actorId: Number(payload.sub),
        object: "refresh_token",
        objectId: payload.jti,
        req,
      });

      if (payload.jti) {
        await revokeSessionByRefreshTokenJti(payload.jti);
      }
    } catch {
      // If the token is invalid or expired, still clear the cookie.
    }
  }

  res.clearCookie(REFRESH_COOKIE, clearRefreshCookieOptions());
  res.clearCookie(ACCESS_COOKIE, clearAccessCookieOptions());

  return res.status(200).json({
    message: "Logged out successfully. Refresh token revoked.",
  });
});

router.post("/refresh", sensitiveLimiter, async (req, res) => {
  const refreshToken = req.cookies?.[REFRESH_COOKIE];

  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh token is missing" });
  }

  let payload;

  try {
    payload = verifyRefreshToken(refreshToken);
  } catch {
    res.clearCookie(REFRESH_COOKIE, clearRefreshCookieOptions());
    return res.status(401).json({ message: "Invalid refresh token" });
  }

  const oldJti = payload.jti;
  const userId = Number(payload.sub);
  const presentedTokenHash = hashRefreshToken(refreshToken);

  const [rows]: any = await db.query(
    `SELECT rt.jti, rt.token_hash, rt.user_id, rt.session_id, rt.expires_at,
            rt.revoked_at, rt.replaced_by, s.trusted_device_id
     FROM refresh_tokens rt
     LEFT JOIN sessions s ON s.id = rt.session_id
     WHERE rt.jti = ?
     LIMIT 1`,
    [oldJti]
  );

  const oldToken = rows[0];

  if (oldToken && oldToken.token_hash !== presentedTokenHash) {
    await auditLog({
      action: "REFRESH_TOKEN_HASH_MISMATCH",
      actorId: userId,
      object: "refresh_token",
      objectId: oldJti,
      requestData: {
        reason: "Refresh token JWT jti matched, but hashed token did not match stored hash.",
      },
      req,
    });

    if (oldToken.session_id) {
      await revokeSession(oldToken.session_id);
    }

    res.clearCookie(REFRESH_COOKIE, clearRefreshCookieOptions());
    res.clearCookie(ACCESS_COOKIE, clearAccessCookieOptions());
    return res.status(401).json({ message: "Invalid refresh token" });
  }

  if (
    !oldToken ||
    oldToken.revoked_at !== null ||
    new Date(oldToken.expires_at) < new Date()
  ) {
    await auditLog({
      action: "REFRESH_TOKEN_INVALID_OR_REVOKED",
      actorId: userId,
      object: "refresh_token",
      objectId: oldJti,
      requestData: {
        revoked: oldToken?.revoked_at !== null,
        replacedBy: oldToken?.replaced_by || null,
      },
      req,
    });

    if (oldToken?.revoked_at !== null && oldToken?.replaced_by) {
      await revokeSessionByRefreshTokenJti(oldJti);
      await alertRefreshTokenReuse(userId, oldJti, oldToken.replaced_by, req);
    }

    res.clearCookie(REFRESH_COOKIE, clearRefreshCookieOptions());
    res.clearCookie(ACCESS_COOKIE, clearAccessCookieOptions());
    return res.status(401).json({ message: "Refresh token is not active" });
  }

  if (!oldToken.session_id || !(await isSessionActive(oldToken.session_id))) {
    await auditLog({
      action: "SESSION_INVALID_OR_EXPIRED",
      actorId: userId,
      object: "session",
      objectId: oldToken.session_id || null,
      requestData: {
        refreshTokenJti: oldJti,
      },
      req,
    });

    if (oldToken.session_id) {
      await revokeSession(oldToken.session_id);
    }

    res.clearCookie(REFRESH_COOKIE, clearRefreshCookieOptions());
    res.clearCookie(ACCESS_COOKIE, clearAccessCookieOptions());
    return res.status(401).json({ message: "Session is not active" });
  }

  const user = await getUserById(userId);

  if (!user) {
    res.clearCookie(REFRESH_COOKIE, clearRefreshCookieOptions());
    return res.status(404).json({ message: "User not found" });
  }

  const refreshTtl = oldToken.trusted_device_id ? "10d" : config.session.refreshTtl;

  const {
    token: newRefreshToken,
    tokenHash: newRefreshTokenHash,
    jti: newJti,
    expiresAt,
  } = signRefreshToken(user.id, refreshTtl as any);

  const accessToken = signAccessToken({
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role || "user",
    sessionId: oldToken.session_id,
  });

  const connection = await db.getConnection();

  try {
    await connection.beginTransaction();

    await connection.query(
      `INSERT INTO refresh_tokens
         (jti, token_hash, user_id, session_id, expires_at, user_agent, ip)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        newJti,
        newRefreshTokenHash,
        user.id,
        oldToken.session_id,
        expiresAt,
        req.headers["user-agent"] || null,
        req.ip || null,
      ]
    );

    await connection.query(
      `UPDATE sessions
       SET expires_at = ?
       WHERE id = ? AND revoked_at IS NULL`,
      [expiresAt, oldToken.session_id]
    );

    await connection.query(
      `UPDATE refresh_tokens
       SET revoked_at = NOW(), replaced_by = ?
       WHERE jti = ? AND revoked_at IS NULL`,
      [newJti, oldJti]
    );

    await connection.commit();
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }

  res.cookie(ACCESS_COOKIE, accessToken, accessCookieOptions());
  res.cookie(REFRESH_COOKIE, newRefreshToken, refreshCookieOptions(expiresAt));

  await auditLog({
    action: "REFRESH_TOKEN_ROTATED",
    actorId: user.id,
    actorRole: user.role || "user",
    object: "refresh_token",
    objectId: oldJti,
    requestData: { replacedBy: newJti },
    req,
  });

  return res.status(200).json({
    message: "Token refreshed successfully",
    accessToken,
  });
});

router.get("/me", requireAuth, (req, res) => {
  return res.json({
    message: "Authenticated user loaded successfully.",
    user: req.user,
  });
});

router.post(
  "/security/change-password",
  sensitiveLimiter,
  requireAuth,
  async (req, res) => {
    const userId = req.user!.sub;
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        message: "Current password and new password are required.",
      });
    }

    const [rows]: any = await db.query(
      `SELECT id, email, username, role, password_hash
       FROM users
       WHERE id = ?
       LIMIT 1`,
      [userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = rows[0];
    const matches = await comparePassword(currentPassword, user.password_hash);

    if (!matches) {
      await auditLog({
        action: "PASSWORD_CHANGE_FAILED",
        actorId: user.id,
        actorRole: user.role || "user",
        object: "user",
        objectId: user.id,
        requestData: { reason: "Current password is incorrect" },
        req,
      });

      return res.status(401).json({ message: "Current password is incorrect." });
    }

    const passwordErrors = validatePassword(newPassword);

    if (passwordErrors.length > 0) {
      await auditLog({
        action: "PASSWORD_CHANGE_FAILED",
        actorId: user.id,
        actorRole: user.role || "user",
        object: "user",
        objectId: user.id,
        requestData: { reason: passwordErrors.join(", ") },
        req,
      });

      return res.status(400).json({ message: passwordErrors.join(", ") });
    }

    const pwned = await isPasswordPwned(newPassword);

    if (pwned) {
      await auditLog({
        action: "PASSWORD_CHANGE_FAILED",
        actorId: user.id,
        actorRole: user.role || "user",
        object: "user",
        objectId: user.id,
        requestData: { reason: "Password is compromised" },
        req,
      });

      return res.status(400).json({
        message: "Password is compromised, choose another one.",
      });
    }

    const newHash = await hashPassword(newPassword);

    await db.query(
      `UPDATE users
       SET password_hash = ?
       WHERE id = ?`,
      [newHash, user.id]
    );

    await revokeAllUserSessions(user.id);

    await auditLog({
      action: "PASSWORD_CHANGED",
      actorId: user.id,
      actorRole: user.role || "user",
      object: "user",
      objectId: user.id,
      requestData: { sessionsRevoked: true },
      req,
    });

    res.clearCookie(REFRESH_COOKIE, clearRefreshCookieOptions());
    res.clearCookie(ACCESS_COOKIE, clearAccessCookieOptions());

    return res.status(200).json({
      message:
        "Password changed successfully. All sessions were revoked. Please log in again.",
    });
  }
);

router.get(
  "/security/sessions",
  sensitiveLimiter,
  requireAuth,
  async (req, res) => {
    const userId = req.user!.sub;
    const sessions = await getActiveSessions(userId);

    await auditLog({
      action: "SESSIONS_VIEWED",
      actorId: userId,
      actorRole: req.user?.role || "user",
      object: "session",
      requestData: {
        count: sessions.length,
      },
      req,
    });

    return res.status(200).json({
      message: "Active sessions loaded successfully.",
      sessions,
    });
  }
);

router.delete(
  "/security/sessions/:id",
  sensitiveLimiter,
  requireAuth,
  async (req, res) => {
    const userId = req.user!.sub;
    const sessionId = Number(req.params.id);

    if (!sessionId) {
      return res.status(400).json({ message: "Invalid session ID" });
    }

    const revoked = await revokeUserSession(userId, sessionId);

    if (!revoked) {
      return res.status(404).json({
        message: "Session not found or already revoked.",
      });
    }

    await auditLog({
      action: "SESSION_REVOKED_BY_USER",
      actorId: userId,
      actorRole: req.user?.role || "user",
      object: "session",
      objectId: sessionId,
      req,
    });

    return res.status(200).json({
      message: "Session revoked successfully.",
    });
  }
);

router.get(
  "/security/trusted-devices",
  sensitiveLimiter,
  requireAuth,
  async (req, res) => {
    const userId = req.user!.sub;
    const devices = await getTrustedDevices(userId);

    await auditLog({
      action: "TRUSTED_DEVICES_VIEWED",
      actorId: userId,
      actorRole: req.user?.role || "user",
      object: "trusted_device",
      requestData: { count: devices.length },
      req,
    });

    return res.status(200).json({
      message: "Trusted devices loaded successfully.",
      devices,
    });
  }
);

router.delete(
  "/security/trusted-devices/:id",
  sensitiveLimiter,
  requireAuth,
  async (req, res) => {
    const userId = req.user!.sub;
    const deviceId = Number(req.params.id);

    if (!deviceId) {
      return res.status(400).json({ message: "Invalid device ID" });
    }

    const revoked = await revokeTrustedDevice(userId, deviceId);

    if (!revoked) {
      return res.status(404).json({
        message: "Trusted device not found or already revoked.",
      });
    }

    await revokeSessionsForTrustedDevice(userId, deviceId);

    await auditLog({
      action: "TRUSTED_DEVICE_REVOKED",
      actorId: userId,
      actorRole: req.user?.role || "user",
      object: "trusted_device",
      objectId: deviceId,
      req,
    });

    return res.status(200).json({
      message: "Trusted device revoked successfully.",
    });
  }
);
router.get(
  "/admin/users",
  sensitiveLimiter,
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    const page = Math.max(Number(req.query.page || 1), 1);
    const limit = Math.min(Math.max(Number(req.query.limit || 20), 1), 100);
    const offset = (page - 1) * limit;
    const search = String(req.query.search || "").trim();

    const where: string[] = [];
    const params: any[] = [];

    if (search) {
      where.push("(email LIKE ? OR username LIKE ? OR full_name LIKE ?)");
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    const whereSql = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";

    const [countRows]: any = await db.query(
      `SELECT COUNT(*) AS total
       FROM users
       ${whereSql}`,
      params
    );

    const [rows]: any = await db.query(
      `SELECT id, full_name, email, username, phone, role, email_verified,
              is_blocked, two_factor_enabled, two_factor_method, created_at
       FROM users
       ${whereSql}
       ORDER BY id ASC
       LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    await auditLog({
      action: "ADMIN_USERS_VIEWED",
      actorId: req.user?.sub,
      actorRole: req.user?.role || "admin",
      object: "user",
      requestData: { page, limit, search: search || null },
      req,
    });

    return res.status(200).json({
      message: "Users loaded successfully.",
      page,
      limit,
      total: Number(countRows[0].total),
      users: rows,
    });
  }
);

router.patch(
  "/admin/users/:id/block",
  sensitiveLimiter,
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    const userId = Number(req.params.id);

    if (!userId) {
      return res.status(400).json({ message: "Invalid user ID" });
    }

    const [rows]: any = await db.query(
      `SELECT id, full_name, email, username, role, is_blocked
       FROM users
       WHERE id = ?
       LIMIT 1`,
      [userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const originalUser = rows[0];

    await db.query(
      `UPDATE users
       SET is_blocked = 1
       WHERE id = ?`,
      [userId]
    );

    await auditLog({
      action: "ADMIN_USER_BLOCKED",
      actorId: req.user?.sub,
      actorRole: req.user?.role || "admin",
      object: "user",
      objectId: userId,
      originalObject: originalUser,
      requestData: {
        newState: {
          is_blocked: 1,
        },
      },
      req,
    });

    return res.status(200).json({
      message: "User blocked successfully.",
    });
  }
);

router.patch(
  "/admin/users/:id/unblock",
  sensitiveLimiter,
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    const userId = Number(req.params.id);

    if (!userId) {
      return res.status(400).json({ message: "Invalid user ID" });
    }

    const [rows]: any = await db.query(
      `SELECT id, full_name, email, username, role, is_blocked
       FROM users
       WHERE id = ?
       LIMIT 1`,
      [userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const originalUser = rows[0];

    await db.query(
      `UPDATE users
       SET is_blocked = 0
       WHERE id = ?`,
      [userId]
    );

    await auditLog({
      action: "ADMIN_USER_UNBLOCKED",
      actorId: req.user?.sub,
      actorRole: req.user?.role || "admin",
      object: "user",
      objectId: userId,
      originalObject: originalUser,
      requestData: {
        newState: {
          is_blocked: 0,
        },
      },
      req,
    });

    return res.status(200).json({
      message: "User unblocked successfully.",
    });
  }
);
router.post(
  "/admin/reserved-usernames",
  sensitiveLimiter,
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    const username = String(req.body.username || "").toLowerCase().trim();

    if (!username) {
      return res.status(400).json({ message: "Username is required" });
    }

    const [result]: any = await db.query(
      `INSERT INTO reserved_usernames (username)
       VALUES (?)`,
      [username]
    );

    await auditLog({
      action: "ADMIN_RESERVED_USERNAME_CREATED",
      actorId: req.user?.sub,
      actorRole: req.user?.role || "admin",
      object: "reserved_username",
      objectId: result.insertId,
      requestData: {
        username,
      },
      req,
    });

    return res.status(201).json({
      message: "Reserved username created successfully.",
      id: result.insertId,
      username,
    });
  }
);
router.get(
  "/admin/reserved-usernames",
  sensitiveLimiter,
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    const page = Math.max(Number(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), 100);
    const offset = (page - 1) * limit;

    const [rows]: any = await db.query(
      `SELECT id, username
       FROM reserved_usernames
       ORDER BY username ASC
       LIMIT ? OFFSET ?`,
      [limit, offset]
    );

    await auditLog({
      action: "ADMIN_RESERVED_USERNAMES_VIEWED",
      actorId: req.user?.sub,
      actorRole: req.user?.role || "admin",
      object: "reserved_username",
      requestData: {
        page,
        limit,
      },
      req,
    });

    return res.status(200).json({
      message: "Reserved usernames loaded successfully.",
      page,
      limit,
      reservedUsernames: rows,
    });
  }
);
router.put(
  "/admin/reserved-usernames/:id",
  sensitiveLimiter,
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    const id = Number(req.params.id);
    const username = String(req.body.username || "").toLowerCase().trim();

    if (!id || !username) {
      return res.status(400).json({ message: "ID and username are required" });
    }

    const [rows]: any = await db.query(
      `SELECT id, username
       FROM reserved_usernames
       WHERE id = ?
       LIMIT 1`,
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "Reserved username not found" });
    }

    const originalObject = rows[0];

    await db.query(
      `UPDATE reserved_usernames
       SET username = ?
       WHERE id = ?`,
      [username, id]
    );

    await auditLog({
      action: "ADMIN_RESERVED_USERNAME_UPDATED",
      actorId: req.user?.sub,
      actorRole: req.user?.role || "admin",
      object: "reserved_username",
      objectId: id,
      originalObject,
      requestData: {
        newUsername: username,
      },
      req,
    });

    return res.status(200).json({
      message: "Reserved username updated successfully.",
    });
  }
);
router.delete(
  "/admin/reserved-usernames/:id",
  sensitiveLimiter,
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    const id = Number(req.params.id);

    if (!id) {
      return res.status(400).json({ message: "Invalid reserved username ID" });
    }

    const [rows]: any = await db.query(
      `SELECT id, username
       FROM reserved_usernames
       WHERE id = ?
       LIMIT 1`,
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "Reserved username not found" });
    }

    const originalObject = rows[0];

    await db.query(
      `DELETE FROM reserved_usernames
       WHERE id = ?`,
      [id]
    );

    await auditLog({
      action: "ADMIN_RESERVED_USERNAME_DELETED",
      actorId: req.user?.sub,
      actorRole: req.user?.role || "admin",
      object: "reserved_username",
      objectId: id,
      originalObject,
      req,
    });

    return res.status(200).json({
      message: "Reserved username deleted successfully.",
    });
  }
);
router.get(
  "/admin/audit-logs",
  sensitiveLimiter,
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    const page = Math.max(Number(req.query.page || 1), 1);
    const limit = Math.min(Math.max(Number(req.query.limit || 20), 1), 100);
    const offset = (page - 1) * limit;

    const action = String(req.query.action || "").trim();
    const actorId = req.query.actorId ? Number(req.query.actorId) : null;
    const ipAddress = String(req.query.ipAddress || "").trim();

    const where: string[] = [];
    const params: any[] = [];

    if (action) {
      where.push("action = ?");
      params.push(action);
    }

    if (actorId) {
      where.push("actor_id = ?");
      params.push(actorId);
    }

    if (ipAddress) {
      where.push("ip_address = ?");
      params.push(ipAddress);
    }

    const whereSql = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";

    const [countRows]: any = await db.query(
      `SELECT COUNT(*) AS total FROM audit_logs ${whereSql}`,
      params
    );

    const [rows]: any = await db.query(
      `SELECT id, actor_id, actor_role, action, object, object_id,
              original_object, request_data, ip_address, user_agent, created_at
       FROM audit_logs
       ${whereSql}
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    await auditLog({
      action: "ADMIN_AUDIT_LOGS_VIEWED",
      actorId: req.user?.sub,
      actorRole: req.user?.role || "admin",
      object: "audit_logs",
      requestData: {
        page,
        limit,
        action: action || null,
        actorId,
        ipAddress: ipAddress || null,
      },
      req,
    });

    return res.status(200).json({
      message: "Audit logs loaded successfully.",
      page,
      limit,
      total: Number(countRows[0].total),
      logs: rows,
    });
  }
);
