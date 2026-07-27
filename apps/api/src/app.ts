import express, { type Express, type Request, type Response, type NextFunction } from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import pinoHttp from "pino-http";
import router from "./routes";
import { logger } from "./lib/logger";

const app: Express = express();

// ── Security headers ─────────────────────────────────────────────────────────
app.use(
  helmet({
    crossOriginEmbedderPolicy: false, // allow iframe embeds in Replit preview
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'", "https:"],
      },
    },
  }),
);

// ── CORS ─────────────────────────────────────────────────────────────────────
// In development the Vite dev server proxies /api requests, so CORS headers are
// only exercised by direct API calls or in production. Allow the Replit preview
// origin family plus any explicitly configured ALLOWED_ORIGINS.
const allowedOriginsEnv = process.env.ALLOWED_ORIGINS;
const allowedOrigins = allowedOriginsEnv
  ? allowedOriginsEnv.split(",").map((o) => o.trim())
  : [];

app.use(
  cors({
    origin(origin, callback) {
      // Allow server-to-server (no origin), local dev, Replit preview domains,
      // and any explicitly configured origins.
      if (!origin) return callback(null, true);
      if (process.env.NODE_ENV !== "production") return callback(null, true);
      const replitDomain = process.env.REPLIT_DEV_DOMAIN ?? "";
      const isReplit =
        origin.endsWith(".replit.dev") ||
        origin.endsWith(".repl.co") ||
        (replitDomain && origin.includes(replitDomain));
      if (isReplit || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      callback(new Error(`CORS: origin not allowed — ${origin}`));
    },
    credentials: true,
  }),
);

// ── Rate limiting ─────────────────────────────────────────────────────────────
// Global: 300 requests per minute per IP (burst-tolerant for normal use)
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests — please slow down" },
});

// Scan initiation: 10 scans per minute per IP (scanning is expensive)
const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many scan requests — maximum 10 scans per minute" },
  skip: (req) => req.method !== "POST",
});

app.use(globalLimiter);

// ── Request logging ───────────────────────────────────────────────────────────
app.use(
  pinoHttp({
    logger,
    serializers: {
      req(req) {
        return {
          id: req.id,
          method: req.method,
          url: req.url?.split("?")[0],
        };
      },
      res(res) {
        return {
          statusCode: res.statusCode,
        };
      },
    },
  }),
);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

// ── Routes ────────────────────────────────────────────────────────────────────
// Apply scan-specific rate limiting to the two scan creation endpoints
app.use("/api/quick-scan", scanLimiter);
app.use("/api/projects", scanLimiter); // POST .../scans
app.use("/api", router);

// ── Global error handler — must be last (4-arg signature) ─────────────────────
// Express 5 forwards async route errors here automatically.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  logger.error({ err }, "Unhandled error");

  // Surface validation errors as 400 instead of 500
  if (err.name === "ZodError" || err.message.startsWith("Validation")) {
    res.status(400).json({ error: err.message });
    return;
  }

  res.status(500).json({ error: "Internal server error" });
});

export default app;
