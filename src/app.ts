import express from "express";
import path from "path";
import { router } from "./routes";

import SwaggerUi from "swagger-ui-express";
import { openApiSpec } from "./docs/openapi";

import "dotenv/config";

import { loadTlds } from "./utils/tld.util";
import cookieParser from "cookie-parser";
(async () => {
  await loadTlds();
})();
import { globalLimiter } from "./middlewares/rateLimit.middleware";

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "../public")));

app.use(
  "/front",
  express.static(path.join(__dirname, "../public"), {
    index: "login.html",
  })
);
app.use("/api", globalLimiter);
// Routes
app.use("/api", router);

// Swagger JSON
app.get("/api/docs.json", (_req, res) => {
  res.json(openApiSpec);
});
// Swagger UI
app.use("/api/docs", SwaggerUi.serve, SwaggerUi.setup(openApiSpec));

export default app;