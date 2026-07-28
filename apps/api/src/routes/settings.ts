/**
 * Settings routes — runtime-configurable options.
 * Currently supports setting the NVD API key (process.env only; not persisted
 * across restarts; users should add it as a Replit secret for persistence).
 */
import { Router, type IRouter } from "express";

const router: IRouter = Router();

// POST /settings/nvd-api-key
// Applies the NVD API key to process.env for the current process lifetime.
// For persistence, add NVD_API_KEY as a Replit secret.
router.post("/settings/nvd-api-key", (req, res): void => {
  const apiKey = req.body?.apiKey;
  if (typeof apiKey !== "string" || apiKey.trim().length < 30) {
    res.status(400).json({ error: "Invalid API key format (minimum 30 characters)" });
    return;
  }
  process.env["NVD_API_KEY"] = apiKey.trim();
  res.json({
    ok: true,
    message:
      "NVD API key set for current process. Add NVD_API_KEY as a Replit secret to persist across restarts.",
  });
});

// GET /settings/nvd-api-key/status
// Returns whether a key is currently configured (never returns the key itself).
router.get("/settings/nvd-api-key/status", (_req, res): void => {
  const key = process.env["NVD_API_KEY"];
  res.json({
    configured: !!key,
    hint: key
      ? `Key configured (${key.length} chars)`
      : "Not configured — CVE lookups will use unauthenticated NVD API (5 req/30s limit)",
  });
});

export default router;
