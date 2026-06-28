import { config } from "../config";

export const verifyHCaptcha = async (captchaToken: string | undefined) => {
  if (!config.hCaptcha.serverSecret) {
    return {
      success: false,
      error: "HCAPTCHA_SERVER_SECRET is not configured",
    };
  }

  if (!captchaToken) {
    return {
      success: false,
      error: "Captcha token is required",
    };
  }

  const data = new URLSearchParams({
    secret: config.hCaptcha.serverSecret,
    response: captchaToken,
  });

  const verifyResponse = await fetch("https://hcaptcha.com/siteverify", {
    method: "POST",
    body: data,
  });

  const result = (await verifyResponse.json()) as {
  success: boolean;
  "error-codes"?: string[];
};

  if (!result.success) {
    return {
      success: false,
      error: "Captcha verification failed",
    };
  }

  return {
    success: true,
  };
};