/**
 * Scan Worker
 *
 * Simulates background scan execution. Picks up pending scans, runs them
 * through realistic phases with progress updates, and records activity on
 * completion. In a production system this would hand off to a real scanning
 * engine; here the simulation makes the UI fully functional.
 */

import { eq, sql, and } from "drizzle-orm";
import {
  db,
  scansTable,
  activityTable,
  findingsTable,
  assetsTable,
  projectsTable,
} from "@workspace/db";
import { logger } from "./logger";

// Scan phase definitions per scan type
const SCAN_PHASES: Record<string, string[]> = {
  recon: [
    "Initializing reconnaissance module...",
    "Performing DNS enumeration...",
    "Checking WHOIS records...",
    "Scanning for subdomain takeover vulnerabilities...",
    "Fingerprinting web technologies...",
    "Collecting SSL/TLS certificate info...",
    "Gathering open-source intelligence (OSINT)...",
    "Finalizing recon report...",
  ],
  enumeration: [
    "Initializing enumeration engine...",
    "Running port scan (TCP SYN)...",
    "Probing service banners...",
    "Enumerating HTTP endpoints...",
    "Checking for directory listings...",
    "Scanning for API endpoints...",
    "Identifying authentication surfaces...",
    "Compiling enumeration results...",
  ],
  vulnerability: [
    "Initializing vulnerability scanner...",
    "Loading CVE database...",
    "Testing for injection vulnerabilities (SQLi, XSS, SSTI)...",
    "Checking for outdated software versions...",
    "Testing authentication mechanisms...",
    "Probing for misconfigurations...",
    "Checking for exposed secrets and sensitive data...",
    "Running SSRF and XXE checks...",
    "Generating vulnerability report...",
  ],
  full: [
    "Initializing full-scope scan...",
    "Running reconnaissance phase...",
    "Performing asset enumeration...",
    "Loading CVE database...",
    "Testing for injection vulnerabilities (SQLi, XSS, SSTI)...",
    "Checking for outdated software versions...",
    "Testing authentication mechanisms...",
    "Probing for misconfigurations...",
    "Checking for exposed secrets...",
    "Running privilege escalation checks...",
    "Analyzing attack surface...",
    "Compiling final report...",
  ],
};

// Simulated finding templates surfaced during vulnerability/full scans
const SIMULATED_FINDINGS = [
  {
    title: "Cross-Site Scripting (Reflected XSS)",
    severity: "high" as const,
    description:
      "A reflected XSS vulnerability was detected in a query parameter. Attacker-controlled input is reflected into the page without sufficient encoding.",
    cve: null,
    cvss: 7.4,
    remediation:
      "Encode all user-supplied output using context-appropriate escaping (HTML, JS, URL). Apply a strict Content-Security-Policy.",
  },
  {
    title: "Missing HTTP Security Headers",
    severity: "medium" as const,
    description:
      "The application is missing several recommended HTTP security headers: Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options.",
    cve: null,
    cvss: 5.3,
    remediation:
      "Configure HSTS, X-Content-Type-Options: nosniff, X-Frame-Options: DENY, and a restrictive Content-Security-Policy on all responses.",
  },
  {
    title: "Outdated OpenSSL Version (CVE-2023-0286)",
    severity: "high" as const,
    description:
      "Server is running an OpenSSL version affected by CVE-2023-0286 (X.400 address type confusion). A remote attacker may trigger a denial of service or information disclosure.",
    cve: "CVE-2023-0286",
    cvss: 7.4,
    remediation: "Upgrade OpenSSL to 3.0.8 or later.",
  },
  {
    title: "Server-Side Request Forgery (SSRF)",
    severity: "critical" as const,
    description:
      "An SSRF vulnerability was found in the URL fetch endpoint. Unauthenticated requests can reach internal services including the cloud metadata endpoint.",
    cve: null,
    cvss: 9.1,
    remediation:
      "Validate and allowlist outbound URLs. Block requests to RFC-1918 and link-local address ranges. Disable unnecessary URL-fetch features.",
  },
  {
    title: "SQL Injection via Search Parameter",
    severity: "critical" as const,
    description:
      "Unsanitized user input in the search parameter is passed directly into a SQL query, allowing authentication bypass and data exfiltration.",
    cve: null,
    cvss: 9.8,
    remediation:
      "Use parameterized queries or prepared statements. Never concatenate user input into SQL strings.",
  },
  {
    title: "Sensitive Data Exposure in API Response",
    severity: "medium" as const,
    description:
      "The API returns internal stack traces and database error messages in production responses, leaking implementation details.",
    cve: null,
    cvss: 5.3,
    remediation:
      "Suppress detailed error messages in production. Return generic error responses and log details server-side only.",
  },
  {
    title: "Insecure Direct Object Reference (IDOR)",
    severity: "high" as const,
    description:
      "User-controlled object identifiers in the API allow accessing resources belonging to other users without authorization checks.",
    cve: null,
    cvss: 8.1,
    remediation:
      "Enforce ownership checks on every resource access. Never rely solely on obscurity of identifiers for access control.",
  },
  {
    title: "Open Redirect",
    severity: "low" as const,
    description:
      "A redirect endpoint accepts an arbitrary destination URL without validation, enabling phishing via trusted domain links.",
    cve: null,
    cvss: 4.3,
    remediation:
      "Restrict redirects to an allowlist of trusted domains. Avoid user-controlled redirect destinations.",
  },
];

const TICK_MS = 4000; // how often worker ticks
const STEPS_PER_SCAN = 8; // progress increments to reach 100

async function pickUpPendingScans(): Promise<void> {
  const pending = await db
    .select()
    .from(scansTable)
    .where(eq(scansTable.status, "pending"))
    .limit(5);

  for (const scan of pending) {
    const phases = SCAN_PHASES[scan.type] ?? SCAN_PHASES.recon;
    const initialLog = `[${new Date().toISOString()}] ${phases[0]}\n`;

    await db
      .update(scansTable)
      .set({
        status: "running",
        progress: 0,
        startedAt: new Date(),
        logs: initialLog,
      })
      .where(eq(scansTable.id, scan.id));

    logger.info({ scanId: scan.id, type: scan.type }, "Scan started");
  }
}

async function tickRunningScans(): Promise<void> {
  const running = await db
    .select()
    .from(scansTable)
    .where(eq(scansTable.status, "running"));

  for (const scan of running) {
    const phases = SCAN_PHASES[scan.type] ?? SCAN_PHASES.recon;
    const progressIncrement = Math.ceil(100 / STEPS_PER_SCAN);
    const newProgress = Math.min((scan.progress ?? 0) + progressIncrement, 100);
    const phaseIndex = Math.floor((newProgress / 100) * (phases.length - 1));
    const phaseLine = phases[Math.min(phaseIndex, phases.length - 1)];
    const logLine = `[${new Date().toISOString()}] ${phaseLine}\n`;
    const updatedLogs = (scan.logs ?? "") + logLine;

    if (newProgress >= 100) {
      await completeScan(scan, updatedLogs);
    } else {
      await db
        .update(scansTable)
        .set({ progress: newProgress, logs: updatedLogs })
        .where(eq(scansTable.id, scan.id));
    }
  }
}

async function completeScan(
  scan: typeof scansTable.$inferSelect,
  logs: string,
): Promise<void> {
  const completionLine = `[${new Date().toISOString()}] Scan complete.\n`;
  const finalLogs = logs + completionLine;

  // For vulnerability/full scans, surface 1-3 simulated findings
  let findingsAdded = 0;
  if (scan.type === "vulnerability" || scan.type === "full") {
    const [assetRow] = await db
      .select({ id: assetsTable.id })
      .from(assetsTable)
      .where(eq(assetsTable.projectId, scan.projectId))
      .limit(1);

    const pool = [...SIMULATED_FINDINGS].sort(() => Math.random() - 0.5);
    const count = scan.type === "full" ? 3 : 2;
    const toInsert = pool.slice(0, count);

    for (const f of toInsert) {
      await db.insert(findingsTable).values({
        projectId: scan.projectId,
        assetId: assetRow?.id ?? null,
        title: f.title,
        description: f.description,
        severity: f.severity,
        status: "open",
        cvss: f.cvss,
        cve: f.cve ?? null,
        remediation: f.remediation,
        evidence: `Discovered during ${scan.name} (${scan.type} scan, ID ${scan.id}).`,
      });
      findingsAdded++;
    }
  }

  await db
    .update(scansTable)
    .set({
      status: "completed",
      progress: 100,
      completedAt: new Date(),
      logs: finalLogs,
      findingsCount: findingsAdded,
    })
    .where(eq(scansTable.id, scan.id));

  // Fetch project name for activity log
  const [project] = await db
    .select({ name: projectsTable.name })
    .from(projectsTable)
    .where(eq(projectsTable.id, scan.projectId));

  await db.insert(activityTable).values({
    type: "scan_completed",
    title: `Scan completed: ${scan.name}`,
    description: `${scan.type} scan finished for ${project?.name ?? "project"}${findingsAdded > 0 ? ` — ${findingsAdded} finding(s) discovered` : ""}`,
    severity: findingsAdded > 0 ? "medium" : null,
    projectId: scan.projectId,
    projectName: project?.name ?? null,
  });

  logger.info(
    { scanId: scan.id, findingsAdded },
    "Scan completed",
  );
}

export function startScanWorker(): void {
  logger.info("Scan worker started");
  setInterval(async () => {
    try {
      await pickUpPendingScans();
      await tickRunningScans();
    } catch (err) {
      logger.error({ err }, "Scan worker error");
    }
  }, TICK_MS);
}
