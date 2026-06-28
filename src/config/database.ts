import mysql from "mysql2/promise";
import { config } from "./index";

export const db = mysql.createPool({
  host: config.db.host,
  port: config.db.port,
  database: config.db.database,
  user: config.db.username,
  password: config.db.password,
});