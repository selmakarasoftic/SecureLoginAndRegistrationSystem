import { httpClient } from "../utils/httpClient";

export const sendSms = async (phone: string, message: string) => {
  console.log(" SMS SERVICE CALLED ");
  console.log("PHONE:", phone);
  //console.log("MESSAGE:", message);

  const baseUrl = process.env.INFOBIP_BASE_URL;
  const apiKey = process.env.INFOBIP_API_KEY;
  const sender = process.env.INFOBIP_SENDER || "ServiceSMS";

  if (!phone) {
    throw new Error("Phone number is missing for SMS.");
  }

  if (!baseUrl || !apiKey) {
    console.log(`[DEV SMS FALLBACK] SMS to ${phone}: ${message}`);
    return {
      simulated: true,
      message: "INFOBIP_BASE_URL or INFOBIP_API_KEY is missing. SMS printed in terminal.",
    };
  }

  const url = `${baseUrl}/sms/2/text/advanced`;

  const payload = {
    messages: [
      {
        destinations: [{ to: phone.replace("+", "") }],
        from: sender,
        text: message,
      },
    ],
  };

  const response = await httpClient(url, {
    method: "POST",
    headers: {
      Authorization: `App ${apiKey}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(payload),
  });

  console.log("INFOBIP RESPONSE:", response);
  return response;
};

export const sendSmsCode = async (phone: string, code: string) => {
  return sendSms(phone, `Your verification code is: ${code}`);
};