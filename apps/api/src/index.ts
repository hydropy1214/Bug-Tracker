import app from "./app";
import { logger } from "./lib/logger";
import { startScanWorker } from "./lib/scan-worker";

// API_PORT is preferred so the shared PORT env var stays owned by the web app
// (the Replit proxy uses PORT to identify the primary preview service).
// Fall back to PORT for production builds where the artifact system injects it.
const rawPort = process.env["API_PORT"] ?? process.env["PORT"];

if (!rawPort) {
  throw new Error(
    "API_PORT (or PORT) environment variable is required but was not provided.",
  );
}

const port = Number(rawPort);

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

app.listen(port, (err) => {
  if (err) {
    logger.error({ err }, "Error listening on port");
    process.exit(1);
  }

  logger.info({ port }, "Server listening");
  startScanWorker();
});
