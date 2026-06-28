import "dotenv/config";
import { db } from "./database";

async function testConnection() {
  try {
    const [rows] = await db.query("SELECT 1 AS connected");
    console.log("Database connected:", rows);
    process.exit(0);
  } catch (error) {
    console.error("Database connection failed:", error);
    process.exit(1);
  }
}

testConnection();