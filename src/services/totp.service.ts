import { generateSecret, generateURI, verify } from "otplib";
import qrcode from "qrcode";

export const generateTotpSetup = async (email: string) => {
  const secret = generateSecret();

  const otpauth = generateURI({
    secret,
    label: email,
    issuer: "SSSD Project",
  });

  const qrCode = await qrcode.toDataURL(otpauth);

  return { secret, otpauth, qrCode };
};

export const verifyTotpToken = async (
  token: string,
  secret: string
): Promise<boolean> => {
  const result = await verify({
    token: token.trim(),
    secret,
  });

  return result.valid;
};