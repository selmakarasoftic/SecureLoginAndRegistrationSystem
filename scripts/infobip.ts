import dotenv from "dotenv";
import path from "path";
import { sendSmsCode } from "../src/services/smsService";

// load .env from root
dotenv.config({ path: path.resolve(__dirname, "../.env") });

const run = async () => {
  try {
    const phone = process.env.TEST_PHONE;
    const code = "123456";

    if (!phone) {
      console.error("TEST_PHONE is not defined in .env");
      return;
    }

    console.log("Sending SMS...");

    const result = await sendSmsCode(phone, code);

    console.log("SMS result:", result);
  } catch (error) {
    console.error("Failed to send SMS:", error);
  }
};

run();