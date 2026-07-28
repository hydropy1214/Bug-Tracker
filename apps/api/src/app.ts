import express, { type Express, type Request, type Response, type NextFunction } from "express";
import cors from "cors";
import helmet from "helmet";
import pinoHttp from "pino-http";
import router from "./routes";
import { logger } from "./lib/logger";

const app: Express = express();

// ── Security headers (no CSP — full open access) ─────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: false,       // disabled — allow all inline scripts, styles, frames
    crossOriginEmbedderPolicy: false,   // allow cross-origin resource embedding
    crossOriginOpenerPolicy: false,     // allow pop-ups and cross-origin windows
    crossOriginResourcePolicy: false,   // allow cross-origin resource loading
  }),
);

// ── CORS — fully open, all origins, all methods, credentials allowed ──────────
app.use(
  cors({
    origin: true,           // reflect every request origin
    credentials: true,      // allow cookies and auth headers
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    allowedHeaders: ["*"],  // accept every header the client sends
    exposedHeaders: ["*"],  // expose every response header to the client
  }),
);

// Pre-flight pass-through (Express 5 requires named wildcard)
app.options("/{*any}", cors({ origin: true, credentials: true }));

// ── Request logging ───────────────────────────────────────────────────────────
app.use(
  pinoHttp({
    logger,
    serializers: {
      req(req) {
        return { id: req.id, method: req.method, url: req.url?.split("?")[0] };
      },
      res(res) {
        return { statusCode: res.statusCode };
      },
    },
  }),
);

// ── Body parsing — generous limits for large API specs ────────────────────────
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

// ── Routes ────────────────────────────────────────────────────────────────────
app.use("/api", router);

// ── Root probe — the API lives entirely under /api; anything hitting / is a
// stray request (e.g. from the artifact-router health prober).  Return 404 so
// the Replit proxy never confuses the API's root with the web-app dashboard.
app.get("/", (_req, res) => {
  res.status(404).json({ error: "Not found — API lives at /api" });
});

// ── Global error handler — must be last (4-arg signature) ─────────────────────
// Express 5 forwards async route errors here automatically.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  logger.error({ err }, "Unhandled error");
  res.status(500).json({ error: "Internal server error", detail: err.message });
});

export default app;
