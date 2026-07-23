/**
 * Real HTTP Security Scanner
 *
 * Makes actual network requests to target assets and detects genuine security
 * misconfigurations. This is passive/informational scanning — it does NOT
 * exploit vulnerabilities or modify anything on the target.
 *
 * Checks performed:
 *  - Security header analysis (CSP, HSTS, X-Frame-Options, etc.)
 *  - SSL/TLS certificate validity and expiry
 *  - Sensitive path exposure (.git, .env, admin panels, backups, etc.)
 *  - CORS misconfiguration (wildcard or reflection)
 *  - Cookie security flags (HttpOnly, Secure, SameSite)
 *  - HTTP TRACE method enabled
 *  - HTTP → HTTPS redirect enforcement
 *  - Server/technology information disclosure
 */

import * as tls from "node:tls";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface RealFinding {
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  cvss: number;
  cve: string | null;
  evidence: string;
  remediation: string;
}

interface ProbeResult {
  status: number;
  headers: Record<string, string>;
  body: string;
  finalUrl: string;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Normalise an asset value to a fully-qualified URL string, or null if unscannable. */
export function normalizeTarget(value: string, type: string): { url: string; hostname: string; port: number; isHttps: boolean } | null {
  // Strip wildcard prefix
  let v = value.trim().replace(/^\*\./, "");

  // Already has a scheme
  if (/^https?:\/\//i.test(v)) {
    try {
      const u = new URL(v);
      return {
        url: u.origin + "/",
        hostname: u.hostname,
        port: parseInt(u.port) || (u.protocol === "https:" ? 443 : 80),
        isHttps: u.protocol === "https:",
      };
    } catch {
      return null;
    }
  }

  // Raw domain or IP — prefer HTTPS
  if (type === "ip") {
    return { url: `http://${v}/`, hostname: v, port: 80, isHttps: false };
  }
  return { url: `https://${v}/`, hostname: v, port: 443, isHttps: true };
}

/** Fire an HTTP request with a hard timeout. Returns null on network error. */
async function probe(
  url: string,
  options: { method?: string; headers?: Record<string, string>; timeoutMs?: number; followRedirects?: boolean } = {},
): Promise<ProbeResult | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 10_000);
  try {
    const res = await fetch(url, {
      method: options.method ?? "GET",
      headers: options.headers ?? {},
      signal: controller.signal,
      redirect: options.followRedirects === false ? "manual" : "follow",
    });

    const headers: Record<string, string> = {};
    res.headers.forEach((val, key) => { headers[key.toLowerCase()] = val; });

    let body = "";
    try { body = await res.text(); } catch { /* ignore */ }

    return { status: res.status, headers, body, finalUrl: res.url || url };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** Check one sensitive path. Returns a finding if the path is reachable (2xx/3xx but not auth-gated). */
async function probeSensitivePath(
  baseUrl: string,
  path: string,
  finding: Omit<RealFinding, "evidence">,
): Promise<RealFinding | null> {
  const target = baseUrl.replace(/\/$/, "") + path;
  const result = await probe(target, { timeoutMs: 8_000 });
  if (!result) return null;

  // 200 = exposed. 403/401 means protected (not a finding). 404/other = not present.
  if (result.status === 200) {
    const snippet = result.body.slice(0, 200).replace(/\s+/g, " ").trim();
    return {
      ...finding,
      evidence: `GET ${target} → HTTP ${result.status}\nBody preview: ${snippet || "(empty)"}`,
    };
  }
  return null;
}

/** Inspect an SSL certificate for expiry and other issues. */
async function checkSslCert(hostname: string, port: number): Promise<RealFinding[]> {
  return new Promise((resolve) => {
    const findings: RealFinding[] = [];
    const socket = tls.connect(
      { host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout: 8_000 },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          socket.destroy();

          if (!cert || !cert.valid_to) {
            resolve([]);
            return;
          }

          // Self-signed: issuer === subject
          const selfSigned =
            cert.issuer?.CN === cert.subject?.CN &&
            cert.issuer?.O === cert.subject?.O;
          if (selfSigned) {
            findings.push({
              title: "Self-Signed SSL Certificate",
              severity: "medium",
              description: `The server presents a self-signed SSL certificate for ${hostname}. Browsers will show a security warning and users cannot verify the server's identity.`,
              cvss: 5.9,
              cve: null,
              evidence: `Certificate subject: ${cert.subject?.CN ?? hostname}\nIssuer: ${cert.issuer?.CN ?? "unknown"}\nValid to: ${cert.valid_to}`,
              remediation: "Obtain a certificate from a trusted Certificate Authority (e.g. Let's Encrypt). Self-signed certs are not suitable for production.",
            });
          }

          // Expiry
          const expiresAt = new Date(cert.valid_to);
          const daysLeft = Math.floor((expiresAt.getTime() - Date.now()) / 86_400_000);
          if (daysLeft < 0) {
            findings.push({
              title: "Expired SSL Certificate",
              severity: "critical",
              description: `The SSL certificate for ${hostname} expired ${Math.abs(daysLeft)} day(s) ago. All connections will be flagged as insecure.`,
              cvss: 9.1,
              cve: null,
              evidence: `Certificate expired: ${cert.valid_to}`,
              remediation: "Renew the SSL certificate immediately. Configure auto-renewal (e.g. Certbot with cron or systemd timer).",
            });
          } else if (daysLeft < 30) {
            findings.push({
              title: "SSL Certificate Expiring Soon",
              severity: "high",
              description: `The SSL certificate for ${hostname} expires in ${daysLeft} day(s). Service disruption is imminent if not renewed.`,
              cvss: 7.5,
              cve: null,
              evidence: `Certificate expires: ${cert.valid_to} (${daysLeft} days remaining)`,
              remediation: "Renew the certificate now. Enable auto-renewal to prevent future lapses.",
            });
          }
        } catch {
          socket.destroy();
          resolve([]);
        }
        resolve(findings);
      },
    );
    socket.on("error", () => resolve([]));
    socket.setTimeout(8_000, () => { socket.destroy(); resolve([]); });
  });
}

// ─── Individual Check Functions ───────────────────────────────────────────────

async function checkSecurityHeaders(baseUrl: string): Promise<RealFinding[]> {
  const result = await probe(baseUrl);
  if (!result) return [];

  const h = result.headers;
  const findings: RealFinding[] = [];
  const missing: string[] = [];

  // HSTS (HTTPS only)
  if (baseUrl.startsWith("https") && !h["strict-transport-security"]) {
    missing.push("Strict-Transport-Security");
    findings.push({
      title: "Missing HTTP Strict Transport Security (HSTS)",
      severity: "medium",
      description: "The server does not set the Strict-Transport-Security header. Without HSTS, browsers may allow downgrade attacks where an attacker strips the HTTPS connection and intercepts traffic in plaintext.",
      cvss: 6.5,
      cve: null,
      evidence: `GET ${baseUrl} → HTTP ${result.status}\nStrict-Transport-Security header: absent`,
      remediation: "Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    });
  }

  // X-Content-Type-Options
  if (!h["x-content-type-options"]) {
    missing.push("X-Content-Type-Options");
    findings.push({
      title: "Missing X-Content-Type-Options Header",
      severity: "low",
      description: "Without X-Content-Type-Options: nosniff, browsers may MIME-sniff responses and execute uploaded files (e.g. images) as scripts, enabling content-injection attacks.",
      cvss: 4.3,
      cve: null,
      evidence: `GET ${baseUrl} → HTTP ${result.status}\nX-Content-Type-Options header: absent`,
      remediation: "Add the header: X-Content-Type-Options: nosniff",
    });
  }

  // X-Frame-Options / CSP frame-ancestors (clickjacking)
  const hasFrameGuard = h["x-frame-options"] || (h["content-security-policy"] ?? "").includes("frame-ancestors");
  if (!hasFrameGuard) {
    missing.push("X-Frame-Options");
    findings.push({
      title: "Clickjacking Protection Missing (No X-Frame-Options)",
      severity: "medium",
      description: "The application can be embedded in an iframe on any external domain. An attacker can use this to create invisible overlay attacks (clickjacking), tricking users into performing unintended actions.",
      cvss: 6.1,
      cve: null,
      evidence: `GET ${baseUrl} → HTTP ${result.status}\nX-Frame-Options header: absent\nCSP frame-ancestors directive: absent`,
      remediation: "Add: X-Frame-Options: DENY  (or SAMEORIGIN if iframe embedding within your own domain is needed). Alternatively use: Content-Security-Policy: frame-ancestors 'none'",
    });
  }

  // Content-Security-Policy
  if (!h["content-security-policy"]) {
    missing.push("Content-Security-Policy");
    findings.push({
      title: "No Content Security Policy (CSP)",
      severity: "medium",
      description: "The application does not set a Content-Security-Policy header. CSP is a critical defence against Cross-Site Scripting (XSS) — without it, injected scripts run freely in the user's browser.",
      cvss: 6.1,
      cve: null,
      evidence: `GET ${baseUrl} → HTTP ${result.status}\nContent-Security-Policy header: absent`,
      remediation: "Define a restrictive CSP. Start with: Content-Security-Policy: default-src 'self'. Tighten script-src, style-src, and img-src as appropriate.",
    });
  }

  // Referrer-Policy
  if (!h["referrer-policy"]) {
    findings.push({
      title: "Missing Referrer-Policy Header",
      severity: "low",
      description: "Without a Referrer-Policy header, the full URL (including query parameters that may contain sensitive data) is sent in the Referer header to third-party sites when users follow external links.",
      cvss: 3.1,
      cve: null,
      evidence: `GET ${baseUrl} → HTTP ${result.status}\nReferrer-Policy header: absent`,
      remediation: "Add: Referrer-Policy: strict-origin-when-cross-origin",
    });
  }

  // Server header (info disclosure)
  const server = h["server"] ?? "";
  const poweredBy = h["x-powered-by"] ?? "";
  if (server && /[\d.]+/.test(server)) {
    findings.push({
      title: "Server Version Disclosed in HTTP Header",
      severity: "low",
      description: `The Server header reveals the software name and version (${server}). Attackers use this to look up known vulnerabilities for that specific version without needing to probe further.`,
      cvss: 4.3,
      cve: null,
      evidence: `GET ${baseUrl} → HTTP ${result.status}\nServer: ${server}`,
      remediation: "Configure the web server to suppress or genericise the Server header (e.g. Apache: ServerTokens Prod, Nginx: server_tokens off).",
    });
  }
  if (poweredBy) {
    findings.push({
      title: "Technology Stack Disclosed via X-Powered-By",
      severity: "low",
      description: `The X-Powered-By header discloses the underlying technology stack (${poweredBy}). This helps attackers target known vulnerabilities for that framework or runtime.`,
      cvss: 3.1,
      cve: null,
      evidence: `GET ${baseUrl} → HTTP ${result.status}\nX-Powered-By: ${poweredBy}`,
      remediation: "Disable the X-Powered-By header. In Express: app.disable('x-powered-by'). In PHP: expose_php = Off.",
    });
  }

  return findings;
}

async function checkCors(baseUrl: string): Promise<RealFinding[]> {
  const result = await probe(baseUrl, {
    headers: {
      "Origin": "https://evil.attacker.example",
      "Access-Control-Request-Method": "GET",
    },
  });
  if (!result) return [];

  const acao = result.headers["access-control-allow-origin"] ?? "";
  const acac = result.headers["access-control-allow-credentials"] ?? "";

  if (acao === "*") {
    return [{
      title: "CORS Wildcard Origin Allowed",
      severity: "medium",
      description: "The API allows cross-origin requests from any domain (Access-Control-Allow-Origin: *). Any website can make requests to this API on behalf of a visitor, potentially leaking data.",
      cvss: 6.5,
      cve: null,
      evidence: `GET ${baseUrl} with Origin: https://evil.attacker.example\nAccess-Control-Allow-Origin: ${acao}`,
      remediation: "Restrict CORS to an explicit allowlist of trusted origins. Never use wildcard (*) on APIs that return sensitive data.",
    }];
  }

  // Reflected origin with credentials — critical
  if (acao === "https://evil.attacker.example" && acac.toLowerCase() === "true") {
    return [{
      title: "CORS: Arbitrary Origin Reflected with Credentials",
      severity: "critical",
      description: "The server reflects any Origin header value and allows credentials (Access-Control-Allow-Credentials: true). A malicious website can make authenticated cross-origin requests and steal user data.",
      cvss: 9.0,
      cve: null,
      evidence: `GET ${baseUrl} with Origin: https://evil.attacker.example\nAccess-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac}`,
      remediation: "Validate the Origin header against a strict allowlist before reflecting it. Never combine a reflected/wildcard origin with Allow-Credentials: true.",
    }];
  }

  return [];
}

async function checkCookieSecurity(baseUrl: string): Promise<RealFinding[]> {
  const result = await probe(baseUrl);
  if (!result) return [];

  const setCookie = result.headers["set-cookie"] ?? "";
  if (!setCookie) return [];

  const findings: RealFinding[] = [];
  const cookies = setCookie.split(/,(?=[^;]+?=)/); // rough split for multiple Set-Cookie

  for (const cookie of cookies) {
    const lower = cookie.toLowerCase();
    const nameMatch = cookie.match(/^([^=;]+)=/);
    const cookieName = nameMatch?.[1]?.trim() ?? "session";

    if (!lower.includes("httponly")) {
      findings.push({
        title: `Cookie Missing HttpOnly Flag (${cookieName})`,
        severity: "medium",
        description: `The cookie "${cookieName}" is accessible via JavaScript because the HttpOnly flag is absent. If an XSS vulnerability exists anywhere on the site, an attacker can steal this cookie.`,
        cvss: 6.1,
        cve: null,
        evidence: `Set-Cookie: ${cookie.slice(0, 200)}`,
        remediation: "Set the HttpOnly flag on all session and authentication cookies: Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict",
      });
    }

    if (baseUrl.startsWith("https") && !lower.includes("secure")) {
      findings.push({
        title: `Cookie Missing Secure Flag (${cookieName})`,
        severity: "medium",
        description: `The cookie "${cookieName}" can be transmitted over unencrypted HTTP connections because the Secure flag is absent. An attacker on the same network can intercept it.`,
        cvss: 5.9,
        cve: null,
        evidence: `Set-Cookie: ${cookie.slice(0, 200)}`,
        remediation: "Add the Secure flag to all cookies: Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict",
      });
    }

    if (!lower.includes("samesite")) {
      findings.push({
        title: `Cookie Missing SameSite Attribute (${cookieName})`,
        severity: "low",
        description: `The cookie "${cookieName}" has no SameSite attribute, making it vulnerable to Cross-Site Request Forgery (CSRF) attacks where a malicious site tricks the user's browser into sending authenticated requests.`,
        cvss: 4.3,
        cve: null,
        evidence: `Set-Cookie: ${cookie.slice(0, 200)}`,
        remediation: "Add SameSite=Strict (or Lax for flows that need cross-site GET navigation): Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict",
      });
    }
  }

  return findings;
}

async function checkTraceMethod(baseUrl: string): Promise<RealFinding[]> {
  const result = await probe(baseUrl, { method: "TRACE", timeoutMs: 6_000 });
  if (!result) return [];

  if (result.status === 200 || result.status === 405 === false) {
    if (result.status === 200) {
      return [{
        title: "HTTP TRACE Method Enabled",
        severity: "medium",
        description: "The server responds to HTTP TRACE requests. This can be used in Cross-Site Tracing (XST) attacks to steal cookies and HTTP authentication credentials even when HttpOnly is set.",
        cvss: 5.8,
        cve: null,
        evidence: `TRACE ${baseUrl} → HTTP ${result.status}\nBody: ${result.body.slice(0, 300)}`,
        remediation: "Disable the TRACE method. In Apache: TraceEnable off. In Nginx: add 'if ($request_method = TRACE) { return 405; }' to the server block.",
      }];
    }
  }
  return [];
}

async function checkHttpsRedirect(baseUrl: string, hostname: string): Promise<RealFinding[]> {
  if (!baseUrl.startsWith("https")) return [];

  const httpUrl = `http://${hostname}/`;
  const result = await probe(httpUrl, { followRedirects: false, timeoutMs: 8_000 });
  if (!result) return [];

  const redirectsToHttps = (result.status >= 300 && result.status < 400) &&
    (result.headers["location"] ?? "").startsWith("https://");

  if (!redirectsToHttps && result.status < 300) {
    return [{
      title: "HTTP Site Accessible Without Redirect to HTTPS",
      severity: "medium",
      description: "The server accepts plain HTTP connections without redirecting to HTTPS. Traffic between the user and server can be intercepted and read by anyone on the same network.",
      cvss: 6.5,
      cve: null,
      evidence: `GET ${httpUrl} → HTTP ${result.status} (no redirect to HTTPS)\nLocation: ${result.headers["location"] ?? "(absent)"}`,
      remediation: "Configure a permanent redirect (HTTP 301) from all HTTP URLs to the HTTPS equivalent. In Nginx: return 301 https://$host$request_uri;",
    }];
  }
  return [];
}

async function checkSensitivePaths(baseUrl: string, deep: boolean): Promise<RealFinding[]> {
  const checks: Array<{ path: string; finding: Omit<RealFinding, "evidence"> }> = [
    {
      path: "/.git/HEAD",
      finding: {
        title: "Exposed .git Directory",
        severity: "critical",
        description: "The .git directory is publicly accessible. An attacker can reconstruct the full source code, including configuration files, hardcoded secrets, API keys, and historical credentials.",
        cvss: 9.1, cve: null,
        remediation: "Block access to /.git at the web server level. In Nginx: location ~ /\\.git { deny all; }. Never deploy git repositories to web roots.",
      },
    },
    {
      path: "/.env",
      finding: {
        title: "Exposed .env Configuration File",
        severity: "critical",
        description: "The .env file is publicly accessible. It typically contains database credentials, API keys, secret tokens, and other sensitive configuration that would give an attacker full access to the application backend.",
        cvss: 9.8, cve: null,
        remediation: "Block access to .env and similar config files at the web server level. Store secrets in environment variables or a secrets manager, never in files within the web root.",
      },
    },
    {
      path: "/phpinfo.php",
      finding: {
        title: "PHP Info Page Exposed",
        severity: "high",
        description: "A phpinfo() page is publicly accessible. It reveals the PHP version, server configuration, enabled modules, environment variables, and file paths — critical recon data for an attacker.",
        cvss: 7.5, cve: null,
        remediation: "Remove phpinfo() files from production. If needed for debugging, protect them with authentication and IP restrictions.",
      },
    },
    {
      path: "/.DS_Store",
      finding: {
        title: "Exposed .DS_Store File",
        severity: "medium",
        description: "A macOS .DS_Store file is publicly accessible. These files reveal the directory structure and filenames of the web root, helping attackers locate hidden files and directories.",
        cvss: 5.3, cve: null,
        remediation: "Delete .DS_Store files from the server and add them to .gitignore. Block access at the web server: location ~ /\\.DS_Store { deny all; }",
      },
    },
  ];

  // Deeper checks for enumeration/vulnerability/full scans
  if (deep) {
    checks.push(
      {
        path: "/backup.sql",
        finding: {
          title: "Database Backup File Exposed",
          severity: "critical",
          description: "A database backup file is publicly accessible. This typically contains all application data including user credentials, personal information, and business-sensitive records.",
          cvss: 9.8, cve: null,
          remediation: "Move backup files outside the web root immediately. Restrict access to backup files with server-level rules and store them in a secure, access-controlled location.",
        },
      },
      {
        path: "/dump.sql",
        finding: {
          title: "Database Dump File Exposed",
          severity: "critical",
          description: "A database dump file is publicly accessible, exposing all application data including credentials and sensitive user information.",
          cvss: 9.8, cve: null,
          remediation: "Remove database dump files from the web root immediately. Store backups in secure, access-controlled storage.",
        },
      },
      {
        path: "/wp-login.php",
        finding: {
          title: "WordPress Admin Login Panel Exposed",
          severity: "medium",
          description: "A WordPress login page is publicly accessible. This is a common target for brute-force and credential stuffing attacks.",
          cvss: 5.3, cve: null,
          remediation: "Restrict access to /wp-login.php by IP. Enable two-factor authentication. Use a Web Application Firewall (WAF) to rate-limit login attempts.",
        },
      },
      {
        path: "/admin",
        finding: {
          title: "Admin Panel Accessible Without Authentication Gate",
          severity: "high",
          description: "An administration panel is reachable without immediately enforcing authentication. Admin interfaces should never be exposed to the public internet.",
          cvss: 7.5, cve: null,
          remediation: "Restrict admin panels by IP allowlist or VPN. Ensure authentication is enforced before any admin functionality is rendered.",
        },
      },
      {
        path: "/.htpasswd",
        finding: {
          title: "Exposed .htpasswd File",
          severity: "critical",
          description: "The .htpasswd file is publicly accessible. It contains hashed user credentials that can be cracked offline to gain access to protected areas.",
          cvss: 9.1, cve: null,
          remediation: "Store .htpasswd files outside the web root. Add a web server rule to deny access to all dotfiles.",
        },
      },
    );
  }

  const results = await Promise.all(
    checks.map(({ path, finding }) => probeSensitivePath(baseUrl, path, finding)),
  );
  return results.filter((f): f is RealFinding => f !== null);
}

// ─── Public API ───────────────────────────────────────────────────────────────

export type ScanType = "recon" | "enumeration" | "vulnerability" | "full";
export type LogFn = (msg: string) => void;

/**
 * Scan a single asset target and return all detected findings.
 *
 * @param value   Asset value (domain, IP, URL, wildcard)
 * @param type    Asset type from the DB ("domain", "ip", "api", "wildcard", etc.)
 * @param scanType Scan depth: recon | enumeration | vulnerability | full
 * @param onLog   Callback to stream log lines back to the caller
 */
export async function scanTarget(
  value: string,
  type: string,
  scanType: ScanType,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const target = normalizeTarget(value, type);
  if (!target) {
    onLog(`[SKIP] Cannot normalise target: ${value}`);
    return [];
  }

  const { url: baseUrl, hostname, port, isHttps } = target;
  const findings: RealFinding[] = [];
  const ts = () => new Date().toISOString();

  onLog(`[${ts()}] Target: ${baseUrl}`);

  // ── Phase 1: Reachability probe (all scan types) ──────────────────────────
  onLog(`[${ts()}] Probing target reachability...`);
  const reachability = await probe(baseUrl, { timeoutMs: 10_000 });
  if (!reachability) {
    onLog(`[${ts()}] Target unreachable or timed out: ${baseUrl}`);
    return [];
  }
  onLog(`[${ts()}] Target responded: HTTP ${reachability.status}`);

  // ── Phase 2: Security headers (all scan types) ────────────────────────────
  onLog(`[${ts()}] Checking HTTP security headers...`);
  const headerFindings = await checkSecurityHeaders(baseUrl);
  findings.push(...headerFindings);
  onLog(`[${ts()}] Security headers: ${headerFindings.length} issue(s) found`);

  // ── Phase 3: SSL certificate (recon, vulnerability, full) ─────────────────
  if (isHttps && ["recon", "vulnerability", "full"].includes(scanType)) {
    onLog(`[${ts()}] Inspecting SSL/TLS certificate...`);
    const sslFindings = await checkSslCert(hostname, port);
    findings.push(...sslFindings);
    onLog(`[${ts()}] SSL/TLS: ${sslFindings.length} issue(s) found`);
  }

  // ── Phase 4: Sensitive path discovery (enumeration, vulnerability, full) ──
  if (["enumeration", "vulnerability", "full"].includes(scanType)) {
    const deep = ["vulnerability", "full"].includes(scanType);
    onLog(`[${ts()}] Scanning for exposed sensitive paths${deep ? " (deep)" : ""}...`);
    const pathFindings = await checkSensitivePaths(baseUrl, deep);
    findings.push(...pathFindings);
    onLog(`[${ts()}] Sensitive paths: ${pathFindings.length} exposure(s) found`);
  }

  // ── Phase 5: CORS misconfiguration (vulnerability, full) ─────────────────
  if (["vulnerability", "full"].includes(scanType)) {
    onLog(`[${ts()}] Testing CORS policy...`);
    const corsFindings = await checkCors(baseUrl);
    findings.push(...corsFindings);
    onLog(`[${ts()}] CORS: ${corsFindings.length} issue(s) found`);
  }

  // ── Phase 6: Cookie security (vulnerability, full) ────────────────────────
  if (["vulnerability", "full"].includes(scanType)) {
    onLog(`[${ts()}] Checking cookie security attributes...`);
    const cookieFindings = await checkCookieSecurity(baseUrl);
    findings.push(...cookieFindings);
    onLog(`[${ts()}] Cookies: ${cookieFindings.length} issue(s) found`);
  }

  // ── Phase 7: HTTP TRACE (vulnerability, full) ─────────────────────────────
  if (["vulnerability", "full"].includes(scanType)) {
    onLog(`[${ts()}] Testing HTTP TRACE method...`);
    const traceFindings = await checkTraceMethod(baseUrl);
    findings.push(...traceFindings);
    onLog(`[${ts()}] TRACE: ${traceFindings.length} issue(s) found`);
  }

  // ── Phase 8: HTTPS enforcement (vulnerability, full) ─────────────────────
  if (isHttps && ["vulnerability", "full"].includes(scanType)) {
    onLog(`[${ts()}] Checking HTTP-to-HTTPS redirect enforcement...`);
    const redirectFindings = await checkHttpsRedirect(baseUrl, hostname);
    findings.push(...redirectFindings);
    onLog(`[${ts()}] HTTPS enforcement: ${redirectFindings.length} issue(s) found`);
  }

  onLog(`[${ts()}] Scan of ${hostname} complete — ${findings.length} total finding(s).`);
  return findings;
}
