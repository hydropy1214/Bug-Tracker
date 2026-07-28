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

// ── Root health probe — Replit's health checker hits GET / on every service.
// Serve an HTML redirect so the browser is always sent to the web app;
// returning raw JSON here caused the Replit preview to show API output
// instead of the dashboard whenever the proxy landed on this port.
app.get("/", (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.status(200).send(
    '<!DOCTYPE html><html><head>' +
    '<meta http-equiv="refresh" content="0; url=/">' +
    '<title>SentinelX API</title></head><body>' +
    '<p>SentinelX API is running. ' +
    '<a href="/api/healthz">Health check</a></p>' +
    '</body></html>'
  );
});

// ── Global error handler — must be last (4-arg signature) ─────────────────────
// Express 5 forwards async route errors here automatically.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  logger.error({ err }, "Unhandled error");
  res.status(500).json({ error: "Internal server error", detail: err.message });
});

export default app;
