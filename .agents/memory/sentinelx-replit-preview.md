---
name: SentinelX Replit preview
description: Direct service checks and artifact lookup used when the shared preview proxy is unavailable.
---

The SentinelX web and API processes can be healthy even when the shared preview proxy at `localhost:80` refuses connections; verify the web service on its configured local port and the API health route directly before changing application code.

**Why:** Imported artifact workflows expose the service ports independently, and a proxy failure can otherwise be mistaken for an application startup failure.

**How to apply:** Check workflow open ports and direct HTTP responses first; use the registered artifact directory names (`web` and `api`) when presenting or previewing artifacts.