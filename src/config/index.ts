import dotenv from "dotenv";
import path from "path";

dotenv.config({ path: path.resolve(__dirname, "../../.env") });

export const config = {
    port: Number(process.env.PORT) || 3000,
    nodeEnv: process.env.NODE_ENV || "development",

    db: {
        host: process.env.DBHost || "",
        port: Number(process.env.DBPort) || 3306,
        database: process.env.DBDatabase || "",
        username: process.env.DBUsername || "",
        password: process.env.DBPassword || "",
    },

    hCaptcha: {
        serverSecret: process.env.HCAPTCHA_SERVER_SECRET || "",
        siteKey: process.env.HCAPTCHA_SITE_KEY || "",
    },

    infobip: {
        apiKey: process.env.INFOBIP_API_KEY || "",
        baseUrl: process.env.INFOBIP_BASE_URL || "",
        sender: process.env.INFOBIP_SENDER || "",
        testPhone: process.env.TEST_PHONE || "",
    },

    smtp: {
        host: process.env.SMTP_HOST || "",
        port: Number(process.env.SMTP_PORT) || 465,
        user: process.env.SMTP_USER || "",
        pass: process.env.SMTP_PASS || "",
        from: process.env.SMTP_FROM || "",
    },

    google: {
        clientId: process.env.GOOGLE_CLIENT_ID || "",
        clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
        redirectUri:
            process.env.GOOGLE_REDIRECT_URI ||
            "http://localhost:3000/api/google-callback",
    },
    github: {
        clientId: process.env.GITHUB_CLIENT_ID || "",
        clientSecret: process.env.GITHUB_CLIENT_SECRET || "",
        redirectUri:
            process.env.GITHUB_REDIRECT_URI ||
            "http://localhost:3000/api/github-callback",
    },
    session: {
        accessSecret: process.env.JWT_ACCESS_SECRET || "",
        refreshSecret: process.env.JWT_REFRESH_SECRET || "",
        accessTtl: process.env.JWT_ACCESS_TTL || "15m",
        refreshTtl: process.env.JWT_REFRESH_TTL || "7d",
    },
    adminAlertEmail: process.env.ADMIN_ALERT_EMAIL || "",

    appUrl: process.env.APP_URL || "http://localhost:3000",
    testEmail: process.env.TEST_EMAIL || "",
};