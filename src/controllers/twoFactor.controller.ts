import { Request, Response } from "express";
import { db } from "../config/database";
import { generateTotpSetup, verifyTotpToken } from "../services/totp.service";

export const setupTwoFactor = async (req: Request, res: Response) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ message: "userId is required" });
    }

    const [users]: any = await db.query(
      "SELECT id, email FROM users WHERE id = ? LIMIT 1",
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = users[0];

    const setup = await generateTotpSetup(user.email);

    await db.query(
      "UPDATE users SET two_factor_secret = ?, two_factor_enabled = FALSE WHERE id = ?",
      [setup.secret, userId]
    );
    return res.status(200).json({
      message: "2FA setup generated",
      qrCode: setup.qrCode,
      otpauth: setup.otpauth,
    });
  } catch (error) {
    console.error("2FA setup error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

export const verifyTwoFactor = async (req: Request, res: Response) => {
  try {
    const { userId, token } = req.body;

    if (!userId || !token) {
      return res.status(400).json({ message: "userId and token are required" });
    }

    const [users]: any = await db.query(
      "SELECT id, two_factor_secret FROM users WHERE id = ? LIMIT 1",
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const secret = users[0].two_factor_secret;

    if (!secret) {
      return res.status(400).json({ message: "2FA is not set up" });
    }

    const valid = await verifyTotpToken(token, secret);

    if (!valid) {
      return res.status(401).json({ message: "Invalid 2FA token" });
    }

    await db.query(
      "UPDATE users SET two_factor_enabled = TRUE WHERE id = ?",
      [userId]
    );

    return res.status(200).json({ message: "2FA verified successfully" });
  } catch (error) {
    console.error("2FA verify error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};