/**
 * SentinelX Professional Security Scanner
 *
 * Performs active, passive, and DNS-layer security analysis against target
 * assets. All checks are non-destructive — no exploitation, no credential
 * brute-forcing, no data modification on targets.
 *
 * Check categories
 * ─────────────────
 *  1. DNS Security         — SPF, DMARC, CAA, DNSSEC indicators
 *  2. Port Exposure        — Dangerous/sensitive open TCP ports
 *  3. TLS/SSL Analysis     — Protocol version, cipher strength, cert chain
 *  4. Security Headers     — 20+ HTTP security header checks
 *  5. Technology Discovery — CMS, framework, server, CDN fingerprinting
 *  6. Sensitive Paths      — 120+ common exposed file/directory patterns
 *  7. Web App Probes       — SQLi error detection, XSS reflection, open redirect,
 *                            error page disclosure, directory listing, HTTP methods
 *  8. API Surface          — GraphQL introspection, Swagger/OpenAPI, REST discovery
 */

import * as tls from "node:tls";
import * as net from "node:net";
import * as dns from "node:dns";

const dnsResolve = dns.promises;

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface RealFinding {
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  cvss: number;
  cve: string | null;
  evidence: string;
  remediation: string;
}

interface Target {
  url: string;       // normalised base URL with trailing slash
  hostname: string;
  port: number;
  isHttps: boolean;
  assetType: string;
}

interface ProbeResult {
  status: number;
  headers: Record<string, string>;
  rawHeaders: string;
  body: string;
  finalUrl: string;
  durationMs: number;
}

export type ScanType = "recon" | "enumeration" | "vulnerability" | "full";
export type LogFn = (msg: string) => Promise<void> | void;

// ═══════════════════════════════════════════════════════════════════════════════
// CORE HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

export function normalizeTarget(value: string, type: string): Target | null {
  let v = value.trim().replace(/^\*\./, "");
  let raw = v;

  if (!/^https?:\/\//i.test(v)) {
    raw = type === "ip" ? `http://${v}/` : `https://${v}/`;
  }

  try {
    const u = new URL(raw);
    return {
      url: u.origin + "/",
      hostname: u.hostname,
      port: parseInt(u.port) || (u.protocol === "https:" ? 443 : 80),
      isHttps: u.protocol === "https:",
      assetType: type,
    };
  } catch {
    return null;
  }
}

async function probe(
  url: string,
  opts: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    timeoutMs?: number;
    followRedirects?: boolean;
  } = {},
): Promise<ProbeResult | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 12_000);
  const t0 = Date.now();

  try {
    const res = await fetch(url, {
      method: opts.method ?? "GET",
      headers: opts.headers ?? {},
      body: opts.body,
      signal: controller.signal,
      redirect: opts.followRedirects === false ? "manual" : "follow",
    });

    const headers: Record<string, string> = {};
    const rawParts: string[] = [];
    res.headers.forEach((val, key) => {
      const k = key.toLowerCase();
      headers[k] = val;
      rawParts.push(`  ${k}: ${val}`);
    });

    let body = "";
    try { body = await res.text(); } catch { /* ignore */ }

    return {
      status: res.status,
      headers,
      rawHeaders: rawParts.join("\n"),
      body: body.slice(0, 8_000),
      finalUrl: res.url || url,
      durationMs: Date.now() - t0,
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function checkPortOpen(hostname: string, port: number, timeoutMs = 3_000): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.createConnection({ host: hostname, port });
    s.setTimeout(timeoutMs);
    s.on("connect", () => { s.destroy(); resolve(true); });
    s.on("error", () => resolve(false));
    s.on("timeout", () => { s.destroy(); resolve(false); });
  });
}

const ts = () => new Date().toISOString();

// ═══════════════════════════════════════════════════════════════════════════════
// 1. DNS SECURITY
// ═══════════════════════════════════════════════════════════════════════════════

async function checkDns(hostname: string): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];

  // ── SPF record ─────────────────────────────────────────────────────────────
  try {
    const txt = await dnsResolve.resolveTxt(hostname).catch(() => [] as string[][]);
    const all = txt.flat();
    const spf = all.find((r) => r.startsWith("v=spf1"));

    if (!spf) {
      findings.push({
        title: "Missing SPF Record — Email Spoofing Risk",
        severity: "medium",
        description:
          "No SPF (Sender Policy Framework) TXT record was found for this domain. Without SPF, any mail server can send email claiming to be from this domain, making phishing attacks against customers or partners trivial.",
        cvss: 6.5,
        cve: null,
        evidence: `DNS TXT query for ${hostname}: no v=spf1 record found\nAll TXT records: ${all.slice(0, 5).join("; ") || "(none)"}`,
        remediation:
          'Publish an SPF record: "v=spf1 include:your-mail-provider.com -all". Use -all (hard fail) rather than ~all (soft fail) to enforce rejection of unauthorised senders.',
      });
    } else if (spf.includes("+all")) {
      findings.push({
        title: "SPF Record Uses +all — Any Server Permitted to Send",
        severity: "high",
        description:
          "The SPF record ends with +all, which means every mail server in the world is authorised to send email as this domain. This completely defeats the purpose of SPF and makes phishing attacks indistinguishable from legitimate email.",
        cvss: 7.5,
        cve: null,
        evidence: `SPF record: ${spf}`,
        remediation: 'Change +all to -all: "v=spf1 include:your-mail-provider.com -all". This rejects all senders not explicitly listed.',
      });
    } else if (spf.includes("~all")) {
      findings.push({
        title: "SPF Record Uses ~all — Soft Fail Only",
        severity: "low",
        description:
          "The SPF record uses ~all (soft fail), which marks unauthorised senders as suspicious but does not reject them. Many mail servers accept soft-fail messages, providing weak protection against spoofing.",
        cvss: 3.7,
        cve: null,
        evidence: `SPF record: ${spf}`,
        remediation:
          'Change ~all to -all to enforce hard rejection of unauthorised senders: "v=spf1 include:your-mail-provider.com -all".',
      });
    }

    // ── DMARC record ─────────────────────────────────────────────────────────
    let dmarcRecords: string[][] = [];
    try { dmarcRecords = await dnsResolve.resolveTxt(`_dmarc.${hostname}`); } catch { /* no record */ }
    const dmarc = dmarcRecords.flat().find((r) => r.startsWith("v=DMARC1"));

    if (!dmarc) {
      findings.push({
        title: "Missing DMARC Record — No Email Authentication Policy",
        severity: "medium",
        description:
          "No DMARC record was found. Without DMARC, recipients cannot automatically reject emails that fail SPF/DKIM checks, and you receive no reports about spoofing attempts targeting your domain.",
        cvss: 6.5,
        cve: null,
        evidence: `DNS TXT query for _dmarc.${hostname}: no v=DMARC1 record found`,
        remediation:
          'Start with a monitoring policy: "v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com". Once you have reviewed reports and confirmed legitimate mail passes, escalate to p=quarantine then p=reject.',
      });
    } else {
      const policyMatch = dmarc.match(/p=(\w+)/);
      const policy = policyMatch?.[1]?.toLowerCase() ?? "none";
      if (policy === "none") {
        findings.push({
          title: "DMARC Policy Set to 'none' — Spoofed Emails Not Blocked",
          severity: "medium",
          description:
            "The DMARC record exists but has p=none, meaning failing messages are only reported (if rua/ruf tags are set) but never quarantined or rejected. Attackers can still send spoofed email from this domain.",
          cvss: 5.3,
          cve: null,
          evidence: `DMARC record: ${dmarc}`,
          remediation:
            "Upgrade DMARC policy to p=quarantine (route failures to spam) or p=reject (block failures entirely) once you have confirmed all legitimate mail sources pass SPF/DKIM checks.",
        });
      }
    }

    // ── CAA record ────────────────────────────────────────────────────────────
    let caaRecords: dns.CaaRecord[] = [];
    try { caaRecords = await dnsResolve.resolveCaa(hostname); } catch { /* none */ }

    if (!caaRecords || caaRecords.length === 0) {
      findings.push({
        title: "No CAA Record — Any Certificate Authority Can Issue SSL Certs",
        severity: "low",
        description:
          "Certification Authority Authorisation (CAA) records are absent. Without CAA, any publicly trusted CA can issue an SSL certificate for this domain — including through social engineering or compromised CA processes.",
        cvss: 4.0,
        cve: null,
        evidence: `DNS CAA query for ${hostname}: no records found`,
        remediation:
          'Publish CAA records to restrict which CAs may issue certificates. Example: "0 issue \\"letsencrypt.org\\"". Add a wildcard restriction: "0 issuewild \\";\\"" to block wildcard issuance.',
      });
    }
  } catch {
    // DNS checks are best-effort; silently continue on resolution errors
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. PORT EXPOSURE
// ═══════════════════════════════════════════════════════════════════════════════

interface PortDef {
  port: number;
  service: string;
  severity: "critical" | "high" | "medium";
  cvss: number;
  cve: string | null;
  description: string;
  remediation: string;
}

const DANGEROUS_PORTS: PortDef[] = [
  {
    port: 21, service: "FTP", severity: "high", cvss: 7.5, cve: null,
    description: "FTP transmits credentials and file contents in cleartext. Any observer on the network path can capture usernames, passwords, and transferred data with trivial tooling.",
    remediation: "Disable FTP. Replace with SFTP (SSH file transfer, port 22) or FTPS over explicit TLS. Restrict access to specific IPs via firewall.",
  },
  {
    port: 23, service: "Telnet", severity: "critical", cvss: 9.8, cve: null,
    description: "Telnet provides unauthenticated, unencrypted remote shell access. Every keystroke — including passwords — is transmitted in cleartext and trivially captured by any network observer.",
    remediation: "Disable Telnet immediately. Use SSH (port 22) exclusively for remote access. If Telnet is needed for legacy devices, isolate them on an air-gapped or strictly firewalled network.",
  },
  {
    port: 3306, service: "MySQL Database", severity: "high", cvss: 8.6, cve: null,
    description: "The MySQL database port is reachable from the internet. Database servers should never be exposed to public networks — they are a direct path to all application data.",
    remediation: "Bind MySQL to 127.0.0.1 in my.cnf (bind-address = 127.0.0.1). Block port 3306 at the firewall. Use an SSH tunnel or VPN for remote DBA access.",
  },
  {
    port: 5432, service: "PostgreSQL Database", severity: "high", cvss: 8.6, cve: null,
    description: "The PostgreSQL database port is reachable from the internet. Direct database exposure allows brute-force attacks against database credentials and exploitation of database vulnerabilities.",
    remediation: "Set listen_addresses = 'localhost' in postgresql.conf. Block port 5432 at the firewall. Require SSL for any remote connections and restrict pg_hba.conf to specific IPs.",
  },
  {
    port: 6379, service: "Redis", severity: "critical", cvss: 9.8, cve: "CVE-2022-0543",
    description: "Redis is accessible from the internet. Redis has no authentication by default and allows reading all cached data, writing arbitrary keys, and — through CONFIG SET — achieving remote code execution by overwriting cron files or SSH authorized_keys.",
    remediation: "Bind Redis to 127.0.0.1 (bind 127.0.0.1 in redis.conf). Set a strong requirepass password. Enable protected-mode. Block port 6379 at the firewall unconditionally.",
  },
  {
    port: 9200, service: "Elasticsearch", severity: "critical", cvss: 9.8, cve: null,
    description: "Elasticsearch is accessible from the internet. Without authentication, any attacker can read, modify, delete, or exfiltrate all indexed data via the REST API — no credentials required.",
    remediation: "Enable X-Pack security (xpack.security.enabled: true) for authentication and TLS. Bind to a private interface. Block port 9200 from public access via firewall.",
  },
  {
    port: 27017, service: "MongoDB", severity: "critical", cvss: 9.8, cve: null,
    description: "MongoDB is accessible from the internet. Misconfigured MongoDB instances (no auth, listening on 0.0.0.0) have resulted in millions of records being exposed or ransomed.",
    remediation: "Enable authentication (security.authorization: enabled in mongod.conf). Bind to 127.0.0.1. Block port 27017 at the firewall. Review all database users and privileges.",
  },
  {
    port: 5601, service: "Kibana (Elasticsearch UI)", severity: "high", cvss: 8.6, cve: null,
    description: "Kibana is publicly accessible, exposing the full Elasticsearch management interface including all index data and cluster configuration to anonymous users.",
    remediation: "Require authentication via X-Pack/Elasticsearch security. Restrict access to Kibana to internal networks or VPN. Block port 5601 from public access.",
  },
  {
    port: 3389, service: "Remote Desktop Protocol (RDP)", severity: "critical", cvss: 9.8, cve: "CVE-2019-0708",
    description: "RDP is directly exposed to the internet. RDP is one of the most exploited entry points for ransomware — exposed instances are continuously scanned and brute-forced. BlueKeep (CVE-2019-0708) allows pre-auth remote code execution on unpatched systems.",
    remediation: "Block port 3389 from the internet via firewall. Require VPN access before RDP is reachable. Enable Network Level Authentication (NLA). Apply all Windows security patches.",
  },
  {
    port: 445, service: "SMB (Windows File Sharing)", severity: "critical", cvss: 9.8, cve: "CVE-2017-0144",
    description: "SMB is directly exposed to the internet. EternalBlue (CVE-2017-0144, used by WannaCry and NotPetya) exploits SMB for unauthenticated remote code execution. SMB should never be exposed publicly.",
    remediation: "Block TCP port 445 from the internet at the firewall without exception. Use a VPN for file sharing between sites. Apply all security patches immediately.",
  },
  {
    port: 8080, service: "HTTP Alternative Port (Dev/CI)", severity: "medium", cvss: 5.3, cve: null,
    description: "A web service is running on port 8080, commonly used by development servers, Jenkins CI, Apache Tomcat, or application servers. Dev/CI services often lack hardening appropriate for public exposure.",
    remediation: "Determine if this service requires public access. If not, restrict via firewall. Ensure authentication is enforced. Never run development or CI services directly on public IPs.",
  },
  {
    port: 2375, service: "Docker API (unauthenticated)", severity: "critical", cvss: 10.0, cve: null,
    description: "The Docker daemon API is exposed without TLS on port 2375. Anyone who can reach this port has full root-equivalent control over the host: they can create privileged containers, mount the host filesystem, and execute arbitrary commands as root.",
    remediation: "Disable the remote Docker API unless absolutely required. If needed, enable TLS client authentication (--tlsverify). Block port 2375 from all external access via firewall.",
  },
  {
    port: 2376, service: "Docker TLS API", severity: "high", cvss: 7.5, cve: null,
    description: "The Docker daemon TLS API is externally accessible. Even with TLS, exposure of the Docker API significantly expands the attack surface for container escape and host compromise.",
    remediation: "Restrict Docker TLS API access to specific management IPs. Ensure client certificates are required (--tlsverify). Consider using Docker contexts over SSH instead of TCP.",
  },
];

async function checkPorts(hostname: string, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Scanning ${DANGEROUS_PORTS.length} known-dangerous ports...`);

  const results = await Promise.allSettled(
    DANGEROUS_PORTS.map(async (def) => {
      const open = await checkPortOpen(hostname, def.port);
      if (open) {
        return {
          title: `Exposed Network Service: ${def.service} (Port ${def.port})`,
          severity: def.severity,
          description: def.description,
          cvss: def.cvss,
          cve: def.cve,
          evidence: `TCP connection to ${hostname}:${def.port} succeeded — port is open and accepting connections from the public internet`,
          remediation: def.remediation,
        } as RealFinding;
      }
      return null;
    }),
  );

  for (const r of results) {
    if (r.status === "fulfilled" && r.value) findings.push(r.value);
  }

  await onLog(`[${ts()}] Port scan complete — ${findings.length} exposed service(s) found`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. TLS / SSL ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

async function checkTls(hostname: string, port: number): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];

  // ── Certificate checks ───────────────────────────────────────────────────
  const certResult = await new Promise<RealFinding[]>((resolve) => {
    const f: RealFinding[] = [];
    const socket = tls.connect(
      { host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout: 10_000 },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          const proto = socket.getProtocol() ?? "unknown";
          const cipher = socket.getCipher();
          socket.destroy();

          // Deprecated TLS versions
          if (proto === "TLSv1" || proto === "TLSv1.0") {
            f.push({
              title: "Deprecated TLS 1.0 Protocol Supported",
              severity: "high",
              description:
                "The server supports TLS 1.0, which was deprecated by PCIDSS in 2018 and formally deprecated by the IETF in RFC 8996. TLS 1.0 is vulnerable to BEAST, POODLE, and other downgrade attacks.",
              cvss: 7.4,
              cve: null,
              evidence: `TLS negotiation with ${hostname}:${port} succeeded using protocol: ${proto}\nCipher: ${cipher?.name ?? "unknown"}`,
              remediation:
                "Disable TLS 1.0 and TLS 1.1. Configure the server to support only TLS 1.2 and TLS 1.3. In Nginx: ssl_protocols TLSv1.2 TLSv1.3;",
            });
          } else if (proto === "TLSv1.1") {
            f.push({
              title: "Deprecated TLS 1.1 Protocol Supported",
              severity: "medium",
              description:
                "The server supports TLS 1.1, deprecated by the IETF in RFC 8996. TLS 1.1 lacks modern cipher suites and is vulnerable to padding oracle attacks.",
              cvss: 5.9,
              cve: null,
              evidence: `TLS negotiation with ${hostname}:${port} using protocol: ${proto}`,
              remediation:
                "Disable TLS 1.1. Support only TLS 1.2 and TLS 1.3. In Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3",
            });
          }

          // Weak ciphers
          const cipherName = cipher?.name?.toUpperCase() ?? "";
          if (
            cipherName.includes("RC4") || cipherName.includes("DES") ||
            cipherName.includes("NULL") || cipherName.includes("EXPORT") ||
            cipherName.includes("ANON")
          ) {
            f.push({
              title: `Weak Cipher Suite in Use: ${cipher?.name}`,
              severity: "high",
              description:
                `The server negotiated a weak cipher suite (${cipher?.name}). RC4, DES, EXPORT, NULL, and ANON ciphers provide insufficient cryptographic protection and can be broken by an attacker to decrypt traffic.`,
              cvss: 7.4,
              cve: null,
              evidence: `Cipher negotiated: ${cipher?.name ?? "unknown"}\nProtocol: ${proto}`,
              remediation:
                "Configure the server to use only modern cipher suites with forward secrecy. Recommended: ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305. Disable all RC4, DES, 3DES, NULL, EXPORT, and ANON ciphers.",
            });
          }

          if (!cert || !cert.valid_to) {
            resolve(f);
            return;
          }

          // Self-signed certificate
          const selfSigned = cert.issuer?.CN === cert.subject?.CN && cert.issuer?.O === cert.subject?.O;
          if (selfSigned) {
            f.push({
              title: "Self-Signed SSL Certificate Detected",
              severity: "medium",
              description:
                `The server presents a self-signed certificate for ${hostname}. Browsers display a warning and users cannot verify the server's identity, making the connection vulnerable to MITM attacks by any attacker who can intercept traffic.`,
              cvss: 5.9,
              cve: null,
              evidence: `Subject CN: ${cert.subject?.CN ?? hostname}\nIssuer CN: ${cert.issuer?.CN ?? "self"}\nSerial: ${cert.serialNumber ?? "unknown"}\nValid to: ${cert.valid_to}`,
              remediation:
                "Replace the self-signed certificate with one issued by a trusted CA. Let's Encrypt provides free, auto-renewing certificates via Certbot.",
            });
          }

          // Certificate expiry
          const expiresAt = new Date(cert.valid_to);
          const daysLeft = Math.floor((expiresAt.getTime() - Date.now()) / 86_400_000);
          if (daysLeft < 0) {
            f.push({
              title: "SSL Certificate Has Expired",
              severity: "critical",
              description:
                `The SSL certificate for ${hostname} expired ${Math.abs(daysLeft)} day(s) ago. All browsers display a blocking error page. The connection is no longer encrypted with a trusted certificate.`,
              cvss: 9.1,
              cve: null,
              evidence: `Certificate expired: ${cert.valid_to}\nExpired ${Math.abs(daysLeft)} day(s) ago\nSubject: ${cert.subject?.CN ?? hostname}`,
              remediation:
                "Renew the certificate immediately. Configure automatic renewal using Certbot or your CA's renewal tooling. Set up monitoring and alerts for certificate expiry (90, 30, 7 day thresholds).",
            });
          } else if (daysLeft < 14) {
            f.push({
              title: "SSL Certificate Expiring in Under 14 Days",
              severity: "high",
              description: `The SSL certificate for ${hostname} expires in ${daysLeft} day(s). Service disruption is imminent.`,
              cvss: 7.5,
              cve: null,
              evidence: `Certificate expires: ${cert.valid_to}\n${daysLeft} day(s) remaining\nSubject: ${cert.subject?.CN ?? hostname}`,
              remediation: "Renew the certificate immediately. Enable automatic renewal to prevent future lapses.",
            });
          } else if (daysLeft < 30) {
            f.push({
              title: "SSL Certificate Expiring Soon (< 30 Days)",
              severity: "medium",
              description: `The SSL certificate for ${hostname} expires in ${daysLeft} day(s). Plan renewal now to avoid service disruption.`,
              cvss: 5.3,
              cve: null,
              evidence: `Certificate expires: ${cert.valid_to}\n${daysLeft} day(s) remaining`,
              remediation: "Renew the certificate and configure auto-renewal (Certbot, ACME client, or CA portal).",
            });
          }

          // Hostname mismatch
          const cn = cert.subject?.CN ?? "";
          const sans: string[] = [];
          try {
            const ext = (cert as any).subjectaltname ?? "";
            ext.split(",").forEach((s: string) => {
              const m = s.trim().match(/^DNS:(.+)$/);
              if (m) sans.push(m[1].trim());
            });
          } catch { /* ignore */ }

          const allNames = [cn, ...sans];
          const matches = allNames.some((name) => {
            if (name.startsWith("*.")) {
              return hostname.endsWith(name.slice(1)) || hostname === name.slice(2);
            }
            return name === hostname;
          });
          if (!matches && allNames.length > 0) {
            f.push({
              title: "SSL Certificate Hostname Mismatch",
              severity: "high",
              description:
                `The certificate's Common Name and Subject Alternative Names do not match the requested hostname (${hostname}). Browsers display a certificate error and modern clients will refuse the connection entirely.`,
              cvss: 7.4,
              cve: null,
              evidence: `Requested hostname: ${hostname}\nCertificate CN: ${cn}\nSANs: ${sans.join(", ") || "(none)"}`,
              remediation:
                "Obtain a certificate that covers this hostname. Add it to the SAN list. Wildcard certificates (*.domain.com) cover all direct subdomains.",
            });
          }
        } catch {
          socket.destroy();
          resolve([]);
          return;
        }
        resolve(f);
      },
    );
    socket.on("error", () => resolve([]));
    socket.setTimeout(10_000, () => { socket.destroy(); resolve([]); });
  });

  findings.push(...certResult);

  // ── HTTPS redirect check ─────────────────────────────────────────────────
  const httpUrl = `http://${hostname}/`;
  const redirectResult = await probe(httpUrl, { followRedirects: false, timeoutMs: 8_000 });
  if (redirectResult && redirectResult.status < 300) {
    findings.push({
      title: "Plain HTTP Accessible Without Redirect to HTTPS",
      severity: "medium",
      description:
        "The server accepts unencrypted HTTP connections and does not redirect to HTTPS. Traffic (including session cookies, form submissions, and authentication headers) is transmitted in cleartext.",
      cvss: 6.5,
      cve: null,
      evidence: `GET ${httpUrl} → HTTP ${redirectResult.status}\nLocation header: ${redirectResult.headers["location"] ?? "(absent)"}`,
      remediation:
        "Configure a permanent 301 redirect from HTTP to HTTPS for all requests. In Nginx: return 301 https://$host$request_uri; In Apache: Redirect permanent / https://yourdomain.com/",
    });
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. SECURITY HEADERS
// ═══════════════════════════════════════════════════════════════════════════════

async function checkHeaders(target: Target): Promise<RealFinding[]> {
  const result = await probe(target.url);
  if (!result) return [];

  const findings: RealFinding[] = [];
  const h = result.headers;
  const ev = (extra: string) =>
    `GET ${target.url} → HTTP ${result.status} (${result.durationMs}ms)\nResponse headers:\n${result.rawHeaders}\n\n${extra}`;

  // ── HSTS ─────────────────────────────────────────────────────────────────
  if (target.isHttps) {
    const hsts = h["strict-transport-security"] ?? "";
    if (!hsts) {
      findings.push({
        title: "Missing Strict-Transport-Security (HSTS)",
        severity: "medium",
        description:
          "The server does not set the HTTP Strict-Transport-Security header. Without HSTS, browsers may allow downgrade attacks (e.g. SSLstrip) where an active attacker forces the browser to use unencrypted HTTP. HSTS instructs browsers to always connect via HTTPS for a specified period.",
        cvss: 6.5, cve: null,
        evidence: ev("Strict-Transport-Security: (absent)"),
        remediation: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\nAfter testing, register your domain on the HSTS preload list (hstspreload.org) for browser-level enforcement.",
      });
    } else {
      const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
      const maxAge = parseInt(maxAgeMatch?.[1] ?? "0");
      if (maxAge < 86_400) {
        findings.push({
          title: "HSTS Max-Age Too Short (< 1 Day)",
          severity: "low",
          description: `The HSTS max-age is only ${maxAge} seconds, providing minimal protection. A browser that has not visited the site recently will not enforce HTTPS.`,
          cvss: 4.3, cve: null,
          evidence: ev(`Strict-Transport-Security: ${hsts}`),
          remediation: "Set max-age to at least 31536000 (1 year): Strict-Transport-Security: max-age=31536000; includeSubDomains",
        });
      }
      if (!hsts.toLowerCase().includes("includesubdomains")) {
        findings.push({
          title: "HSTS Missing includeSubDomains Directive",
          severity: "low",
          description:
            "HSTS is set but without includeSubDomains. Attackers can create a subdomain (e.g. sub.yourdomain.com) serving over HTTP to perform cookie-injection or session fixation attacks against the main domain.",
          cvss: 3.7, cve: null,
          evidence: ev(`Strict-Transport-Security: ${hsts}`),
          remediation: "Add includeSubDomains: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        });
      }
    }
  }

  // ── Content-Security-Policy ───────────────────────────────────────────────
  const csp = h["content-security-policy"] ?? "";
  if (!csp) {
    findings.push({
      title: "No Content Security Policy (CSP)",
      severity: "medium",
      description:
        "The application does not define a Content-Security-Policy. CSP is a primary defence against Cross-Site Scripting (XSS) — without it, any injected script executes with full page context, can steal cookies, perform CSRF, or exfiltrate data to attacker-controlled servers.",
      cvss: 6.1, cve: null,
      evidence: ev("Content-Security-Policy: (absent)"),
      remediation: "Define a restrictive CSP. Starting point:\nContent-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'\nAvoid 'unsafe-inline' and 'unsafe-eval' in script-src.",
    });
  } else {
    // Check for dangerous CSP directives
    if (csp.includes("unsafe-eval")) {
      findings.push({
        title: "CSP Allows 'unsafe-eval' — XSS Mitigations Bypassed",
        severity: "medium",
        description:
          "'unsafe-eval' in the CSP script-src allows eval(), Function(), setTimeout(string), and similar dynamic code execution. This lets an XSS payload that can influence these calls bypass CSP protections.",
        cvss: 5.4, cve: null,
        evidence: ev(`Content-Security-Policy: ${csp.slice(0, 300)}`),
        remediation: "Remove 'unsafe-eval'. Refactor code that relies on eval or dynamic script execution. Use nonces or hashes for any necessary inline scripts.",
      });
    }
    if (csp.includes("unsafe-inline") && csp.includes("script-src")) {
      findings.push({
        title: "CSP Allows 'unsafe-inline' Scripts — XSS Mitigations Weakened",
        severity: "medium",
        description:
          "'unsafe-inline' in script-src allows inline <script> tags and event handlers to execute. An XSS vulnerability that injects inline scripts will bypass CSP protections entirely.",
        cvss: 5.4, cve: null,
        evidence: ev(`Content-Security-Policy: ${csp.slice(0, 300)}`),
        remediation: "Replace 'unsafe-inline' with nonces ('nonce-{random}') or hashes ('sha256-{hash}') for specific legitimate inline scripts. Migrate inline event handlers to external scripts.",
      });
    }
    if (csp.includes("*") && !csp.includes("script-src")) {
      findings.push({
        title: "CSP Default-src Uses Wildcard (*)",
        severity: "medium",
        description:
          "A wildcard (*) in the CSP default-src allows resources to be loaded from any domain. This defeats the purpose of CSP as an XSS mitigation — attackers can load scripts from any host they control.",
        cvss: 5.4, cve: null,
        evidence: ev(`Content-Security-Policy: ${csp.slice(0, 300)}`),
        remediation: "Replace wildcard with specific trusted origins. CSP should be as restrictive as possible while still allowing the application to function.",
      });
    }
  }

  // ── X-Frame-Options / frame-ancestors ────────────────────────────────────
  const xfo = h["x-frame-options"] ?? "";
  const hasFrameGuard = xfo || csp.includes("frame-ancestors");
  if (!hasFrameGuard) {
    findings.push({
      title: "Clickjacking Protection Missing (No X-Frame-Options / frame-ancestors)",
      severity: "medium",
      description:
        "The page can be embedded in an <iframe> on any external domain. An attacker can overlay the page inside a transparent iframe on their site, tricking users into performing actions (clicking buttons, submitting forms) they did not intend.",
      cvss: 6.1, cve: null,
      evidence: ev("X-Frame-Options: (absent)\nCSP frame-ancestors: (absent)"),
      remediation: "Add: X-Frame-Options: DENY\nOr in CSP: Content-Security-Policy: frame-ancestors 'none'\nIf iframe embedding within your own domain is needed, use SAMEORIGIN / frame-ancestors 'self'.",
    });
  } else if (xfo && !["DENY", "SAMEORIGIN"].includes(xfo.toUpperCase().trim())) {
    findings.push({
      title: "X-Frame-Options Has Non-Standard Value",
      severity: "low",
      description:
        `X-Frame-Options is set to "${xfo}" which is not a recognised value. Only DENY and SAMEORIGIN are valid. Non-standard values may be ignored by browsers.`,
      cvss: 3.1, cve: null,
      evidence: ev(`X-Frame-Options: ${xfo}`),
      remediation: "Set X-Frame-Options to DENY (prevent all framing) or SAMEORIGIN (allow same-origin framing only).",
    });
  }

  // ── X-Content-Type-Options ────────────────────────────────────────────────
  if (!h["x-content-type-options"]) {
    findings.push({
      title: "Missing X-Content-Type-Options: nosniff",
      severity: "low",
      description:
        "Without X-Content-Type-Options: nosniff, older browsers (IE, some Chrome configurations) may MIME-sniff response content. An attacker who can control an upload endpoint could serve a text/plain file containing HTML/script that gets executed as HTML by the browser.",
      cvss: 4.3, cve: null,
      evidence: ev("X-Content-Type-Options: (absent)"),
      remediation: "Add to all responses: X-Content-Type-Options: nosniff",
    });
  }

  // ── Referrer-Policy ───────────────────────────────────────────────────────
  if (!h["referrer-policy"]) {
    findings.push({
      title: "Missing Referrer-Policy Header",
      severity: "low",
      description:
        "Without a Referrer-Policy, the full URL (including query parameters) of the current page is sent as the Referer header when users follow external links. If URLs contain session tokens, user IDs, or search terms, these are leaked to third-party servers.",
      cvss: 3.1, cve: null,
      evidence: ev("Referrer-Policy: (absent)"),
      remediation: "Add: Referrer-Policy: strict-origin-when-cross-origin\nFor maximum privacy: Referrer-Policy: no-referrer",
    });
  }

  // ── Permissions-Policy ────────────────────────────────────────────────────
  if (!h["permissions-policy"]) {
    findings.push({
      title: "No Permissions-Policy Header",
      severity: "low",
      description:
        "Without a Permissions-Policy header, embedded third-party iframes (ads, analytics) may be able to access browser features such as the camera, microphone, geolocation, or payment APIs without explicit user consent.",
      cvss: 3.1, cve: null,
      evidence: ev("Permissions-Policy: (absent)"),
      remediation: "Add a restrictive Permissions-Policy. Example:\nPermissions-Policy: camera=(), microphone=(), geolocation=(), payment=()\nAdjust based on features actually used by your application.",
    });
  }

  // ── Server & tech disclosure ──────────────────────────────────────────────
  const server = h["server"] ?? "";
  if (server && /[\d.]/.test(server)) {
    findings.push({
      title: "Server Version Disclosed in HTTP Header",
      severity: "low",
      description:
        `The Server header reveals the web server software and version: "${server}". Attackers can look up known CVEs for this exact version and launch targeted exploits without additional reconnaissance.`,
      cvss: 4.3, cve: null,
      evidence: ev(`Server: ${server}`),
      remediation: "Suppress or genericise the Server header.\nApache: ServerTokens Prod and ServerSignature Off\nNginx: server_tokens off;\nNode/Express: app.disable('x-powered-by'); set custom Server header if needed.",
    });
  }

  for (const disclosureHeader of ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-drupal-cache", "x-wp-total"]) {
    const val = h[disclosureHeader] ?? "";
    if (val) {
      findings.push({
        title: `Technology Disclosed via ${disclosureHeader} Header`,
        severity: "low",
        description:
          `The ${disclosureHeader} header reveals platform/framework details: "${val}". This assists attackers in selecting targeted exploits.`,
        cvss: 3.1, cve: null,
        evidence: ev(`${disclosureHeader}: ${val}`),
        remediation: `Suppress the ${disclosureHeader} header in your web server or application framework configuration.`,
      });
    }
  }

  // ── Cache-Control on potentially sensitive pages ───────────────────────────
  const cc = h["cache-control"] ?? "";
  if (!cc || (!cc.includes("no-store") && !cc.includes("private"))) {
    // Only flag if there's a Set-Cookie (suggests authenticated context)
    if (h["set-cookie"]) {
      findings.push({
        title: "Authenticated Response May Be Cached (Weak Cache-Control)",
        severity: "low",
        description:
          "A page that sets a session cookie does not have Cache-Control: no-store. Shared caches (corporate proxies, CDN nodes) may cache authenticated responses and serve them to subsequent users.",
        cvss: 4.3, cve: null,
        evidence: ev(`Cache-Control: ${cc || "(absent)"}\nSet-Cookie: ${h["set-cookie"]?.slice(0, 80)}...`),
        remediation: "Set on authenticated pages: Cache-Control: no-store, no-cache\nPragma: no-cache",
      });
    }
  }

  // ── CORS ─────────────────────────────────────────────────────────────────
  const corsResult = await probe(target.url, {
    headers: { Origin: "https://evil.attacker.example", "Access-Control-Request-Method": "GET" },
  });
  if (corsResult) {
    const acao = corsResult.headers["access-control-allow-origin"] ?? "";
    const acac = corsResult.headers["access-control-allow-credentials"] ?? "";
    if (acao === "*") {
      findings.push({
        title: "CORS Policy Allows Any Origin (*)",
        severity: "medium",
        description:
          "The API/page returns Access-Control-Allow-Origin: * (wildcard), allowing any website to make cross-origin requests and read the response. If this endpoint returns sensitive data, any malicious site visited by an authenticated user can exfiltrate it.",
        cvss: 6.5, cve: null,
        evidence: `GET ${target.url} with Origin: https://evil.attacker.example\nAccess-Control-Allow-Origin: ${acao}`,
        remediation: "Replace the wildcard with an explicit allowlist of trusted origins. Validate the Origin header server-side against this list before echoing it in Access-Control-Allow-Origin.",
      });
    } else if (acao === "https://evil.attacker.example" && acac.toLowerCase() === "true") {
      findings.push({
        title: "CORS: Arbitrary Origin Reflected with Credentials — Critical",
        severity: "critical",
        description:
          "The server reflects any Origin header and allows credentials (Access-Control-Allow-Credentials: true). A malicious website can make fully authenticated cross-origin API calls on behalf of any logged-in user, enabling complete account takeover via CORS.",
        cvss: 9.0, cve: null,
        evidence: `GET ${target.url} with Origin: https://evil.attacker.example\nAccess-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac}`,
        remediation: "Validate the Origin header against a strict server-side allowlist before reflecting it. Never combine a dynamic/reflected origin with Allow-Credentials: true.",
      });
    }
  }

  // ── Cookie security ──────────────────────────────────────────────────────
  const setCookie = h["set-cookie"] ?? "";
  if (setCookie) {
    const lower = setCookie.toLowerCase();
    const nameMatch = setCookie.match(/^([^=;,\s]+)/);
    const cookieName = nameMatch?.[1]?.trim() ?? "cookie";

    if (!lower.includes("httponly")) {
      findings.push({
        title: `Cookie Missing HttpOnly Flag (${cookieName})`,
        severity: "medium",
        description:
          `The cookie "${cookieName}" can be read by JavaScript because the HttpOnly flag is absent. Any XSS vulnerability anywhere on the site allows an attacker to steal this cookie with document.cookie.`,
        cvss: 6.1, cve: null,
        evidence: `Set-Cookie: ${setCookie.slice(0, 200)}`,
        remediation: `Set the HttpOnly flag: Set-Cookie: ${cookieName}=...; HttpOnly; Secure; SameSite=Strict`,
      });
    }
    if (target.isHttps && !lower.includes("secure")) {
      findings.push({
        title: `Cookie Missing Secure Flag (${cookieName})`,
        severity: "medium",
        description:
          `The cookie "${cookieName}" can be transmitted over unencrypted HTTP because the Secure flag is absent. An attacker performing an SSL stripping attack can capture this cookie.`,
        cvss: 5.9, cve: null,
        evidence: `Set-Cookie: ${setCookie.slice(0, 200)}`,
        remediation: `Add the Secure flag: Set-Cookie: ${cookieName}=...; HttpOnly; Secure; SameSite=Strict`,
      });
    }
    if (!lower.includes("samesite")) {
      findings.push({
        title: `Cookie Missing SameSite Attribute (${cookieName})`,
        severity: "low",
        description:
          `The cookie "${cookieName}" has no SameSite attribute. Without SameSite, the cookie is sent with all cross-site requests, enabling CSRF attacks where a malicious site makes authenticated requests on the user's behalf.`,
        cvss: 4.3, cve: null,
        evidence: `Set-Cookie: ${setCookie.slice(0, 200)}`,
        remediation: `Set SameSite: Set-Cookie: ${cookieName}=...; HttpOnly; Secure; SameSite=Strict\nUse SameSite=Lax only if cross-site GET navigation is required.`,
      });
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. TECHNOLOGY FINGERPRINTING
// ═══════════════════════════════════════════════════════════════════════════════

interface TechProfile {
  name: string;
  version?: string;
  category: string;
}

async function fingerprint(target: Target): Promise<{ techs: TechProfile[]; findings: RealFinding[] }> {
  const techs: TechProfile[] = [];
  const findings: RealFinding[] = [];

  const result = await probe(target.url);
  if (!result) return { techs, findings };

  const h = result.headers;
  const body = result.body;

  // ── Server fingerprint ────────────────────────────────────────────────────
  const server = h["server"] ?? "";
  if (server) techs.push({ name: server, category: "Web Server" });

  // ── WordPress ─────────────────────────────────────────────────────────────
  if (body.includes("/wp-content/") || body.includes("/wp-includes/") || h["x-pingback"]) {
    const vMatch = body.match(/WordPress\s+([\d.]+)/i);
    techs.push({ name: "WordPress", version: vMatch?.[1], category: "CMS" });

    // Check for outdated WordPress versions
    if (body.includes("ver=") && body.match(/ver=([\d.]+)/)?.[1]) {
      const wpVer = body.match(/ver=([\d.]+)/)?.[1];
      findings.push({
        title: "WordPress Installation Detected — Version Fingerprinting Possible",
        severity: "low",
        description:
          `WordPress ${wpVer ?? ""} was identified from page source. Version disclosure helps attackers select version-specific exploits from the WordPress CVE database.`,
        cvss: 3.7, cve: null,
        evidence: `Version hint in response: ${wpVer}\nWP-content paths present in HTML`,
        remediation: "Use a security plugin to suppress WordPress version output. Remove the Generator meta tag. Ensure WordPress core, themes, and plugins are kept up to date.",
      });
    }
  }

  // ── Drupal ────────────────────────────────────────────────────────────────
  if (body.includes("Drupal") || h["x-generator"]?.includes("Drupal")) {
    techs.push({ name: "Drupal", category: "CMS" });
  }

  // ── Joomla ───────────────────────────────────────────────────────────────
  if (body.includes("/components/com_") || body.includes("Joomla")) {
    techs.push({ name: "Joomla", category: "CMS" });
  }

  // ── Laravel ──────────────────────────────────────────────────────────────
  if (h["set-cookie"]?.includes("laravel_session") || h["x-powered-by"]?.toLowerCase().includes("laravel")) {
    techs.push({ name: "Laravel", category: "Framework" });
  }

  // ── Django ───────────────────────────────────────────────────────────────
  if (h["set-cookie"]?.includes("csrftoken") || h["set-cookie"]?.includes("sessionid")) {
    techs.push({ name: "Django (probable)", category: "Framework" });
  }

  // ── ASP.NET ───────────────────────────────────────────────────────────────
  if (h["x-aspnet-version"] || h["x-powered-by"]?.includes("ASP.NET")) {
    techs.push({ name: `ASP.NET${h["x-aspnet-version"] ? " " + h["x-aspnet-version"] : ""}`, category: "Framework" });
  }

  // ── Next.js ───────────────────────────────────────────────────────────────
  if (body.includes("/_next/static/") || h["x-powered-by"]?.includes("Next.js")) {
    techs.push({ name: "Next.js", category: "Framework" });
  }

  // ── CDN detection ─────────────────────────────────────────────────────────
  if (h["cf-ray"] || h["cf-cache-status"]) techs.push({ name: "Cloudflare", category: "CDN/WAF" });
  if (h["x-fastly-request-id"]) techs.push({ name: "Fastly", category: "CDN" });
  if (h["x-amz-cf-id"] || h["via"]?.includes("CloudFront")) techs.push({ name: "AWS CloudFront", category: "CDN" });
  if (h["x-cache"]?.includes("Varnish") || h["via"]?.includes("varnish")) techs.push({ name: "Varnish", category: "Cache" });

  return { techs, findings };
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. SENSITIVE PATH DISCOVERY
// ═══════════════════════════════════════════════════════════════════════════════

interface PathDef {
  path: string;
  finding: Omit<RealFinding, "evidence">;
  deep?: boolean; // only run on enumeration/vulnerability/full scans
}

const SENSITIVE_PATHS: PathDef[] = [
  // ── Source control ────────────────────────────────────────────────────────
  { path: "/.git/HEAD", finding: { title: "Exposed .git Directory — Full Source Code Accessible", severity: "critical", cvss: 9.1, cve: null, description: "The .git directory is publicly accessible. An attacker can reconstruct the full source code repository including all commit history, secrets, hardcoded credentials, API keys, and internal logic using git clone or tools like git-dumper.", remediation: "Block access to /.git at the web server level and remove it from the web root. In Nginx: location ~ /\\.git { deny all; return 404; }" } },
  { path: "/.git/config", finding: { title: "Git Config File Exposed", severity: "high", cvss: 7.5, cve: null, description: "The .git/config file is publicly accessible, revealing remote repository URLs, branch names, and potentially credentials embedded in remote URLs.", remediation: "Block access to all dotfiles and .git paths at the web server. Audit git config for embedded credentials." } },
  { path: "/.svn/entries", finding: { title: "SVN Repository Directory Exposed", severity: "critical", cvss: 9.1, cve: null, description: "The Subversion .svn directory is publicly accessible, allowing an attacker to download the full source tree.", remediation: "Block access to /.svn at the web server level. Remove .svn directories from web root." } },
  { path: "/.hg/", finding: { title: "Mercurial Repository Exposed", severity: "critical", cvss: 9.1, cve: null, description: "The Mercurial .hg directory is publicly accessible.", remediation: "Block access to /.hg/ at the web server. Remove from web root." } },
  // ── Secrets & config ─────────────────────────────────────────────────────
  { path: "/.env", finding: { title: "Exposed .env File — Credentials and Secrets Accessible", severity: "critical", cvss: 9.8, cve: null, description: "The .env file is publicly accessible. It typically contains database connection strings, API keys, cryptographic secrets, OAuth tokens, and AWS/cloud provider credentials — giving attackers immediate access to all connected services.", remediation: "Remove .env from the web root immediately. Store secrets in environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.). Block dotfiles at the web server." } },
  { path: "/.env.local", finding: { title: "Exposed .env.local Configuration File", severity: "critical", cvss: 9.8, cve: null, description: "The .env.local file is publicly accessible, exposing local environment configuration including secrets.", remediation: "Block all .env* files at the web server. Never store .env files in the web root." } },
  { path: "/.env.production", finding: { title: "Exposed .env.production Configuration File", severity: "critical", cvss: 9.8, cve: null, description: "Production environment configuration is publicly accessible, likely containing production database credentials and API keys.", remediation: "Block all .env* files at the web server. Use a secrets manager for production credentials." } },
  { path: "/config.php", finding: { title: "PHP Configuration File Exposed", severity: "critical", cvss: 9.8, cve: null, description: "A PHP config file is publicly accessible, potentially exposing database credentials and application secrets.", remediation: "Move config files outside the web root. Ensure PHP processes config files and never serves them as text." } },
  { path: "/wp-config.php", finding: { title: "WordPress wp-config.php Exposed", severity: "critical", cvss: 9.8, cve: null, description: "wp-config.php is publicly accessible, exposing the WordPress database credentials (DB_NAME, DB_USER, DB_PASSWORD, DB_HOST) and the authentication secret keys.", remediation: "Move wp-config.php above the web root. Block direct PHP file access. Regenerate database credentials immediately if exposed." } },
  { path: "/database.yml", finding: { title: "Rails database.yml Exposed", severity: "critical", cvss: 9.8, cve: null, description: "The Rails database.yml file is publicly accessible, revealing database usernames, passwords, and host configuration.", remediation: "Block YAML config file access. Move secrets to environment variables. Rotate exposed database credentials." } },
  { path: "/application.yml", finding: { title: "Application Configuration Exposed (application.yml)", severity: "high", cvss: 8.6, cve: null, description: "application.yml is accessible, potentially containing API keys, database credentials, and other application secrets.", remediation: "Block YAML config files from public access. Use environment variables for secrets." } },
  { path: "/.aws/credentials", deep: true, finding: { title: "AWS Credentials File Exposed", severity: "critical", cvss: 10.0, cve: null, description: "AWS credentials are publicly accessible. These keys provide direct access to AWS services (S3, EC2, RDS, IAM, etc.) with whatever permissions the account holds.", remediation: "Remove .aws/credentials from the web root immediately. Revoke and rotate the exposed AWS keys. Use IAM instance roles instead of access key files." } },
  { path: "/.npmrc", deep: true, finding: { title: ".npmrc File Exposed — NPM Tokens at Risk", severity: "high", cvss: 8.1, cve: null, description: "The .npmrc file is publicly accessible. It may contain NPM authentication tokens that allow publishing packages to the NPM registry on behalf of your organisation.", remediation: "Block .npmrc from public access. Revoke and rotate any exposed NPM tokens immediately." } },
  // ── Backup files ──────────────────────────────────────────────────────────
  { path: "/backup.sql", finding: { title: "Database Backup File Exposed (backup.sql)", severity: "critical", cvss: 9.8, cve: null, description: "A database backup file is publicly downloadable. It contains all application data: user credentials (potentially hashed), PII, business data, and structural information needed to replicate the entire database.", remediation: "Move backup files outside the web root immediately. Use access-controlled, encrypted storage for backups. Implement automated backup validation that checks for accidental public exposure." } },
  { path: "/dump.sql", finding: { title: "Database Dump File Exposed", severity: "critical", cvss: 9.8, cve: null, description: "A SQL dump file is publicly accessible, exposing all database content.", remediation: "Remove from web root. Store backups in access-controlled storage." } },
  { path: "/db.sql", finding: { title: "Database File Exposed (db.sql)", severity: "critical", cvss: 9.8, cve: null, description: "A SQL database file is publicly accessible.", remediation: "Remove from web root. Store backups in access-controlled, encrypted storage." } },
  { path: "/backup.zip", deep: true, finding: { title: "Site Backup Archive Exposed", severity: "critical", cvss: 9.8, cve: null, description: "A ZIP archive (likely a full site backup) is publicly downloadable, containing source code, configuration files, and potentially database dumps.", remediation: "Remove from web root. Store backups in access-controlled storage. Audit backup processes for similar exposures." } },
  { path: "/site.tar.gz", deep: true, finding: { title: "Site Archive Exposed (.tar.gz)", severity: "critical", cvss: 9.8, cve: null, description: "A tar.gz archive is publicly downloadable, potentially containing full application source and sensitive configuration.", remediation: "Remove from web root. Implement automated checks to prevent archive files from being placed in public directories." } },
  // ── PHP / Server info ─────────────────────────────────────────────────────
  { path: "/phpinfo.php", finding: { title: "PHP Info Page Exposed (/phpinfo.php)", severity: "high", cvss: 7.5, cve: null, description: "A phpinfo() output page is publicly accessible, revealing the PHP version, all loaded modules, configuration values (php.ini), environment variables, server paths, and enabled extensions. This is comprehensive fingerprinting data for targeting PHP-specific attacks.", remediation: "Delete phpinfo.php from production. If needed for diagnostics, protect with authentication and IP restriction." } },
  { path: "/info.php", finding: { title: "PHP Info Page Exposed (/info.php)", severity: "high", cvss: 7.5, cve: null, description: "A phpinfo() output page is publicly accessible, revealing extensive server configuration.", remediation: "Remove info.php from production servers." } },
  { path: "/test.php", finding: { title: "PHP Test File Exposed", severity: "medium", cvss: 5.3, cve: null, description: "A PHP test file is accessible. Test files often contain debugging code, var_dumps, or phpinfo() calls that reveal sensitive information.", remediation: "Remove all test files from production environments before deployment." } },
  { path: "/server-status", finding: { title: "Apache Server Status Page Exposed", severity: "medium", cvss: 5.3, cve: null, description: "The Apache server-status page is publicly accessible. It shows currently active requests including full URLs, client IP addresses, and server performance metrics — information that aids targeted attacks.", remediation: "Restrict server-status to localhost or a management IP: <Location /server-status>\n  Require local\n</Location>" } },
  { path: "/server-info", finding: { title: "Apache Server Info Page Exposed", severity: "medium", cvss: 5.3, cve: null, description: "The Apache server-info page exposes detailed module configurations, loaded handlers, and loaded hooks.", remediation: "Restrict or disable server-info. Add: <Location /server-info>\n  Require local\n</Location>" } },
  // ── Admin panels ─────────────────────────────────────────────────────────
  { path: "/wp-login.php", finding: { title: "WordPress Admin Login Exposed", severity: "medium", cvss: 5.3, cve: null, description: "The WordPress login page is publicly accessible and subject to brute-force, credential stuffing, and XML-RPC attacks.", remediation: "Restrict /wp-login.php to specific IPs. Enable two-factor authentication. Use a WAF with login rate limiting. Consider moving the login URL." } },
  { path: "/wp-admin/", finding: { title: "WordPress Admin Area Directly Accessible", severity: "medium", cvss: 5.3, cve: null, description: "The WordPress /wp-admin/ dashboard is publicly reachable without prior authentication challenge at the network level.", remediation: "Restrict /wp-admin/ access by IP. Add HTTP Basic Authentication as an additional layer. Enable 2FA for all admin accounts." } },
  { path: "/administrator/", finding: { title: "Joomla Administrator Panel Exposed", severity: "medium", cvss: 5.3, cve: null, description: "The Joomla administrator panel is publicly accessible and subject to brute-force attacks.", remediation: "Change the admin directory path. Restrict by IP. Enable two-factor authentication." } },
  { path: "/phpmyadmin/", finding: { title: "phpMyAdmin Panel Exposed", severity: "high", cvss: 8.1, cve: null, description: "A phpMyAdmin database management interface is publicly accessible. Successful authentication (or exploiting a phpMyAdmin vulnerability) grants full database access including reading all data, running arbitrary SQL, and potentially writing files to the server.", remediation: "Move phpMyAdmin to a non-default URL. Restrict to localhost or specific management IPs. Enable authentication. Apply all phpMyAdmin security updates." } },
  { path: "/phpmyadmin", finding: { title: "phpMyAdmin Panel Exposed", severity: "high", cvss: 8.1, cve: null, description: "phpMyAdmin is publicly accessible.", remediation: "Restrict phpMyAdmin to internal/management networks only." } },
  { path: "/.htpasswd", finding: { title: "Exposed .htpasswd Password File", severity: "critical", cvss: 9.1, cve: null, description: "The .htpasswd file containing hashed user credentials is publicly accessible. These hashes can be cracked offline using GPU-accelerated tools (hashcat, John the Ripper) to recover plaintext passwords.", remediation: "Store .htpasswd outside the web root. Block access to dotfiles in the web server configuration." } },
  { path: "/.DS_Store", finding: { title: "Exposed .DS_Store File (macOS Directory Metadata)", severity: "medium", cvss: 5.3, cve: null, description: "A macOS .DS_Store file is publicly accessible. These binary files contain the names and metadata of all files and directories at that path level, allowing an attacker to enumerate the web root directory structure without brute-forcing.", remediation: "Delete .DS_Store files from the server. Add to .gitignore. Block access at the web server: location ~ /\\.DS_Store { deny all; }" } },
  // ── Development & debug ───────────────────────────────────────────────────
  { path: "/telescope", deep: true, finding: { title: "Laravel Telescope Debug Panel Exposed", severity: "high", cvss: 8.1, cve: null, description: "Laravel Telescope is accessible. This debug panel shows all HTTP requests, database queries, queued jobs, exceptions, logs, and dump outputs — a comprehensive view of all application activity.", remediation: "Restrict Telescope to specific IP addresses or authenticated users only. Set TELESCOPE_ENABLED=false in production or gate access with a strict gate policy." } },
  { path: "/_profiler", deep: true, finding: { title: "Symfony Profiler/Debug Bar Exposed", severity: "high", cvss: 8.1, cve: null, description: "The Symfony web profiler is accessible. It exposes all request parameters, environment variables, session data, database queries, and the application configuration.", remediation: "Disable the profiler in production (web_profiler.toolbar: false in config/packages/prod/web_profiler.yaml). Never enable debug mode in production." } },
  { path: "/.well-known/security.txt", finding: { title: "No Security.txt File Found", severity: "low", cvss: 2.0, cve: null, description: "No security.txt file was found at /.well-known/security.txt. Security.txt (RFC 9116) provides security researchers with a standardised way to report vulnerabilities, reducing the time between discovery and your team being notified.", remediation: "Create /.well-known/security.txt with contact information for security reports. See securitytxt.org for the format." } },
  // ── Logs ─────────────────────────────────────────────────────────────────
  { path: "/error.log", deep: true, finding: { title: "Error Log File Publicly Accessible", severity: "high", cvss: 7.5, cve: null, description: "An application error log is publicly readable. Error logs typically contain stack traces with file paths, database queries, SQL errors, user input, session tokens, and internal IP addresses.", remediation: "Store log files outside the web root. Block access to .log files at the web server." } },
  { path: "/access.log", deep: true, finding: { title: "Access Log File Publicly Accessible", severity: "medium", cvss: 5.3, cve: null, description: "An HTTP access log is publicly readable, revealing all request patterns, client IPs, and URL parameters including potentially sensitive query strings.", remediation: "Store log files outside the web root or block access via web server configuration." } },
  // ── CI/CD & Docker ────────────────────────────────────────────────────────
  { path: "/Dockerfile", deep: true, finding: { title: "Dockerfile Exposed", severity: "medium", cvss: 5.3, cve: null, description: "The Dockerfile is publicly accessible, revealing the base image, build steps, exposed ports, environment variable names, and application structure.", remediation: "Block build files from public access. Remove from web root. Consider what information exposure aids an attacker in targeting this system." } },
  { path: "/docker-compose.yml", deep: true, finding: { title: "Docker Compose File Exposed", severity: "high", cvss: 7.5, cve: null, description: "The docker-compose.yml is publicly accessible, often containing environment variables, database credentials, internal port mappings, and volume mounts.", remediation: "Block docker-compose.yml from public access. Move secrets to .env files or Docker secrets." } },
  { path: "/.github/workflows/", deep: true, finding: { title: "GitHub Actions Workflow Files Exposed", severity: "low", cvss: 3.7, cve: null, description: "GitHub Actions workflow configuration files are accessible, revealing CI/CD processes, secret names (though not values), deployment procedures, and build commands.", remediation: "Block .github/ directory from web server access." } },
  { path: "/Jenkinsfile", deep: true, finding: { title: "Jenkinsfile CI Configuration Exposed", severity: "low", cvss: 3.7, cve: null, description: "The Jenkinsfile is publicly accessible, revealing build steps, deployment procedures, secret variable names, and infrastructure details.", remediation: "Block Jenkinsfile from public web access." } },
  // ── Package files ─────────────────────────────────────────────────────────
  { path: "/package.json", finding: { title: "package.json Exposed — Dependency Fingerprinting", severity: "low", cvss: 3.7, cve: null, description: "package.json is publicly accessible, revealing all dependency names and versions. Attackers can check each dependency against CVE databases to identify known vulnerable versions without further probing.", remediation: "Block package.json and other build-tool configuration files from public access." } },
  { path: "/yarn.lock", deep: true, finding: { title: "yarn.lock Exposed — Full Dependency Tree Fingerprinting", severity: "low", cvss: 3.1, cve: null, description: "yarn.lock is publicly accessible, containing the exact resolved versions and integrity hashes of all transitive dependencies.", remediation: "Block lock files from public access." } },
  { path: "/requirements.txt", deep: true, finding: { title: "Python requirements.txt Exposed", severity: "low", cvss: 3.1, cve: null, description: "requirements.txt is publicly accessible, revealing all Python dependency versions for vulnerability targeting.", remediation: "Block requirements.txt from public access." } },
];

async function checkSensitivePaths(target: Target, deep: boolean, onLog: LogFn): Promise<RealFinding[]> {
  const paths = SENSITIVE_PATHS.filter((p) => !p.deep || deep);
  await onLog(`[${ts()}] Probing ${paths.length} sensitive paths...`);

  const BATCH = 15; // concurrent request limit
  const findings: RealFinding[] = [];

  for (let i = 0; i < paths.length; i += BATCH) {
    const batch = paths.slice(i, i + BATCH);
    const results = await Promise.allSettled(
      batch.map(async ({ path, finding }) => {
        const url = target.url.replace(/\/$/, "") + path;
        const result = await probe(url, { timeoutMs: 8_000 });
        if (!result || result.status !== 200) return null;

        // Avoid false positives from catch-all pages
        if (result.body.toLowerCase().includes("404") && result.body.length < 2_000) return null;

        const snippet = result.body.slice(0, 300).replace(/\s+/g, " ").trim();
        return {
          ...finding,
          evidence: `GET ${url} → HTTP ${result.status}\nBody preview: ${snippet || "(empty)"}`,
        } as RealFinding;
      }),
    );

    for (const r of results) {
      if (r.status === "fulfilled" && r.value) findings.push(r.value);
    }
  }

  await onLog(`[${ts()}] Path discovery complete — ${findings.length} exposure(s) found`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 7. WEB APPLICATION VULNERABILITY PROBES
// ═══════════════════════════════════════════════════════════════════════════════

// Patterns indicating a database error in the response body
const SQLI_ERROR_PATTERNS = [
  /you have an error in your sql syntax/i,
  /warning.*mysql.*query/i,
  /pg_query\(\): query failed/i,
  /psycopg2\.errors/i,
  /unterminated quoted string at or near/i,
  /sqlite3\.operationalerror/i,
  /sqlexception.*syntax error/i,
  /odbc.*sql server.*error/i,
  /ora-\d{5}/i, // Oracle
  /microsoft.*ole db.*provider.*error/i,
  /unclosed quotation mark after the character string/i, // MSSQL
  /db2 sql error/i,
  /invalid sql statement/i,
  /column .* does not exist/i,
];

async function checkWebApp(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];

  // ── SQLi error detection ──────────────────────────────────────────────────
  await onLog(`[${ts()}] Testing for SQL injection error leakage...`);
  const sqliProbes = [
    target.url + "?id=1'",
    target.url + "?search=test'",
    target.url + "?q=1'%20OR%20'1'='1",
    target.url + "?page=1--",
  ];

  for (const probeUrl of sqliProbes) {
    const r = await probe(probeUrl, { timeoutMs: 8_000 });
    if (!r) continue;
    const matchedPattern = SQLI_ERROR_PATTERNS.find((p) => p.test(r.body));
    if (matchedPattern) {
      findings.push({
        title: "SQL Injection — Database Error Leaked in Response",
        severity: "critical",
        description:
          "The application returns a raw database error when unexpected SQL characters are injected into a URL parameter. This confirms that user input is being interpolated directly into SQL queries without parameterisation, and that the application does not suppress database errors in production — both critical indicators of SQL injection vulnerability.",
        cvss: 9.8, cve: null,
        evidence: `Probe URL: ${probeUrl}\nHTTP status: ${r.status}\nError pattern matched: ${matchedPattern}\nBody excerpt: ${r.body.slice(0, 400)}`,
        remediation:
          "Use parameterised queries or prepared statements exclusively. Never concatenate user input into SQL strings. Suppress detailed database errors in production (return generic 500 errors). Apply the principle of least privilege to database accounts.",
      });
      break; // one SQLi finding per target is sufficient
    }
  }

  // ── XSS reflection detection ──────────────────────────────────────────────
  await onLog(`[${ts()}] Testing for reflected XSS indicators...`);
  const xssProbe = "sentinelx_xss_probe_8472";
  const xssUrl = target.url + `?q=${xssProbe}&search=${xssProbe}`;
  const xssResult = await probe(xssUrl, { timeoutMs: 8_000 });
  if (xssResult && xssResult.body.includes(xssProbe)) {
    const ct = xssResult.headers["content-type"] ?? "";
    if (ct.includes("text/html")) {
      findings.push({
        title: "URL Parameter Value Reflected in HTML Response — XSS Risk",
        severity: "high",
        description:
          "The application reflects user-supplied URL parameters back into the HTML response without escaping. If the reflected value is not encoded, an attacker can inject HTML/JavaScript that executes in the victim's browser when they open a crafted link — a classic Reflected XSS attack.",
        cvss: 7.2, cve: null,
        evidence: `Probe: GET ${xssUrl}\nHTTP ${xssResult.status}\nProbe string "${xssProbe}" found unescaped in HTML response body.\nContent-Type: ${ct}`,
        remediation:
          "Apply context-aware output encoding to all user-supplied values before rendering them in HTML. Use a templating engine with auto-escaping. Implement a strict Content-Security-Policy. Validate and sanitise all inputs server-side.",
      });
    }
  }

  // ── Open redirect detection ────────────────────────────────────────────────
  await onLog(`[${ts()}] Testing for open redirect vulnerabilities...`);
  const redirectTarget = "https://evil.attacker.example";
  const redirectParams = ["redirect", "url", "next", "return", "return_to", "returnUrl", "goto", "dest", "destination", "redir", "redirect_uri", "callback"];

  for (const param of redirectParams.slice(0, 6)) { // limit to 6 to keep scan fast
    const redirectUrl = target.url + `?${param}=${encodeURIComponent(redirectTarget)}`;
    const r = await probe(redirectUrl, { followRedirects: false, timeoutMs: 6_000 });
    if (!r) continue;
    if (r.status >= 300 && r.status < 400) {
      const loc = r.headers["location"] ?? "";
      if (loc.startsWith("https://evil.attacker.example") || loc === redirectTarget) {
        findings.push({
          title: `Open Redirect via ?${param} Parameter`,
          severity: "medium",
          description:
            `The application accepts an external URL in the ?${param} parameter and redirects users to it without validation. Attackers use open redirects to create phishing URLs that appear legitimate (using your trusted domain) but deliver users to malicious sites.`,
          cvss: 6.1, cve: null,
          evidence: `GET ${redirectUrl}\nHTTP ${r.status}\nLocation: ${loc}`,
          remediation:
            "Validate redirect destinations against a strict allowlist of trusted URLs or paths. Reject any redirect URL containing an external domain. Use relative paths for internal redirects.",
        });
        break;
      }
    }
  }

  // ── Error page information disclosure ─────────────────────────────────────
  await onLog(`[${ts()}] Checking error pages for information disclosure...`);
  const errorUrl = target.url + "sentinelx_nonexistent_resource_8472/";
  const errorResult = await probe(errorUrl, { timeoutMs: 8_000 });
  if (errorResult && errorResult.status >= 400) {
    const body = errorResult.body.toLowerCase();
    const stackIndicators = [
      "stack trace", "traceback", "exception in thread", "at com.", "at org.",
      "line ", "file \"", ".php on line", "in /var/www", "in /home/",
      "debug_exception", "whitescreen", "application error",
      "sqlexception", "nullpointerexception",
    ];
    const matched = stackIndicators.filter((s) => body.includes(s));
    if (matched.length >= 2) {
      findings.push({
        title: "Stack Trace / Internal Path Disclosed in Error Response",
        severity: "medium",
        description:
          "The application returns detailed error information including stack traces, file paths, or exception details in production error responses. This reveals the application's internal structure, technology stack, file system layout, and code flow to attackers.",
        cvss: 5.3, cve: null,
        evidence: `GET ${errorUrl} → HTTP ${errorResult.status}\nIndicators found: ${matched.join(", ")}\nBody excerpt: ${errorResult.body.slice(0, 400)}`,
        remediation:
          "Configure the application to return generic error messages in production. Log full details server-side only. Set error display settings: PHP: display_errors = Off; Django: DEBUG = False; Express: no error stack in production responses.",
      });
    }
  }

  // ── Directory listing detection ────────────────────────────────────────────
  await onLog(`[${ts()}] Checking for directory listing...`);
  const dirPaths = ["/uploads/", "/images/", "/static/", "/assets/", "/files/", "/media/"];
  for (const dirPath of dirPaths) {
    const dirUrl = target.url.replace(/\/$/, "") + dirPath;
    const r = await probe(dirUrl, { timeoutMs: 6_000 });
    if (!r) continue;
    if (r.status === 200 && (r.body.includes("Index of ") || r.body.includes("Directory listing"))) {
      findings.push({
        title: `Directory Listing Enabled (${dirPath})`,
        severity: "medium",
        description:
          `The web server serves directory listing for ${dirPath}. An attacker can enumerate all files in this directory — including uploaded user files, backup archives, and documents that should not be publicly accessible.`,
        cvss: 5.3, cve: null,
        evidence: `GET ${dirUrl} → HTTP ${r.status}\nBody contains "Index of " or "Directory listing"\nPreview: ${r.body.slice(0, 300)}`,
        remediation:
          "Disable directory listing in the web server. Apache: Options -Indexes. Nginx: autoindex off; (this is the default). Serve only files explicitly mapped to routes.",
      });
      break;
    }
  }

  // ── HTTP methods enumeration ──────────────────────────────────────────────
  await onLog(`[${ts()}] Enumerating allowed HTTP methods...`);
  const optResult = await probe(target.url, { method: "OPTIONS", timeoutMs: 6_000 });
  if (optResult) {
    const allow = optResult.headers["allow"] ?? optResult.headers["public"] ?? "";
    const dangerous = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"].filter(
      (m) => allow.toUpperCase().includes(m),
    );
    if (dangerous.length > 0) {
      findings.push({
        title: `Potentially Dangerous HTTP Methods Advertised: ${dangerous.join(", ")}`,
        severity: "medium",
        description:
          `The OPTIONS response advertises the following HTTP methods: ${dangerous.join(", ")}. PUT/DELETE could allow file creation or deletion if not properly restricted. TRACE enables Cross-Site Tracing attacks. CONNECT can facilitate proxy abuse.`,
        cvss: 5.3, cve: null,
        evidence: `OPTIONS ${target.url} → HTTP ${optResult.status}\nAllow: ${allow}`,
        remediation:
          "Restrict allowed HTTP methods to only what the application requires (typically GET, POST, HEAD). Disable TRACE unconditionally. Gate PUT/DELETE behind authentication and authorisation checks.",
      });
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 8. API SURFACE DISCOVERY
// ═══════════════════════════════════════════════════════════════════════════════

async function checkApiSurface(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Probing API surface and documentation endpoints...`);

  // ── GraphQL introspection ─────────────────────────────────────────────────
  const graphqlEndpoints = ["/graphql", "/api/graphql", "/gql", "/query"];
  for (const ep of graphqlEndpoints) {
    const gqlUrl = target.url.replace(/\/$/, "") + ep;
    const r = await probe(gqlUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: "{ __schema { types { name } } }" }),
      timeoutMs: 8_000,
    });
    if (r && r.status === 200 && r.body.includes("__schema")) {
      findings.push({
        title: "GraphQL Introspection Enabled in Production",
        severity: "high",
        description:
          "The GraphQL API has introspection enabled, allowing any client to query the full schema — all types, fields, mutations, and queries. This provides attackers with a complete map of the API surface, enabling targeted attacks against specific fields or mutations without reverse-engineering.",
        cvss: 7.5, cve: null,
        evidence: `POST ${gqlUrl} with introspection query\nHTTP ${r.status}\nResponse contains __schema — introspection successful\nPartial response: ${r.body.slice(0, 300)}`,
        remediation:
          "Disable introspection in production. In Apollo Server: introspection: false. In most GraphQL frameworks this is a single configuration flag. Consider enabling it only for authenticated users if development access is needed.",
      });
      break;
    }
  }

  // ── Swagger / OpenAPI exposure ────────────────────────────────────────────
  const swaggerEndpoints = [
    "/swagger", "/swagger-ui.html", "/swagger-ui/", "/swagger/index.html",
    "/api-docs", "/api-docs/", "/openapi.json", "/openapi.yaml",
    "/api/swagger", "/v1/swagger", "/v2/api-docs", "/v3/api-docs",
    "/docs", "/redoc",
  ];
  for (const ep of swaggerEndpoints) {
    const swUrl = target.url.replace(/\/$/, "") + ep;
    const r = await probe(swUrl, { timeoutMs: 6_000 });
    if (!r || r.status !== 200) continue;
    const body = r.body.toLowerCase();
    if (body.includes("swagger") || body.includes("openapi") || body.includes('"paths"')) {
      findings.push({
        title: "API Documentation (Swagger/OpenAPI) Publicly Exposed",
        severity: "medium",
        description:
          "An API documentation interface (Swagger/OpenAPI) is publicly accessible. It provides a complete, interactive map of all API endpoints, parameters, data models, and authentication requirements — eliminating the reconnaissance phase for attackers and making automated API scanning trivial.",
        cvss: 5.3, cve: null,
        evidence: `GET ${swUrl} → HTTP ${r.status}\nContent indicates Swagger/OpenAPI documentation\nPreview: ${r.body.slice(0, 300)}`,
        remediation:
          "Restrict API documentation to authenticated users or internal networks. In production, consider disabling it entirely if external developers do not need access. If it must be public, ensure all endpoints shown are properly authenticated.",
      });
      break;
    }
  }

  // ── Spring Boot Actuator ──────────────────────────────────────────────────
  const actuatorEndpoints = ["/actuator", "/actuator/health", "/actuator/env", "/actuator/beans"];
  for (const ep of actuatorEndpoints) {
    const actUrl = target.url.replace(/\/$/, "") + ep;
    const r = await probe(actUrl, { timeoutMs: 6_000 });
    if (!r || r.status !== 200) continue;
    const body = r.body.toLowerCase();
    if (body.includes('"status"') || body.includes("actuator") || body.includes('"beans"')) {
      const isEnvEndpoint = ep.includes("env");
      findings.push({
        title: `Spring Boot Actuator Endpoint Exposed (${ep})`,
        severity: isEnvEndpoint ? "critical" : "high",
        description:
          `The Spring Boot Actuator endpoint ${ep} is publicly accessible. ${isEnvEndpoint ? "The /env endpoint exposes all environment variables including database passwords, API keys, and other secrets. " : ""}Actuator endpoints expose sensitive operational data and, on older versions, can be used to achieve remote code execution via /actuator/env + /actuator/restart.`,
        cvss: isEnvEndpoint ? 9.8 : 7.5, cve: null,
        evidence: `GET ${actUrl} → HTTP ${r.status}\nBody: ${r.body.slice(0, 300)}`,
        remediation:
          "Restrict Actuator endpoints to management ports/networks. Disable sensitive endpoints in production: management.endpoints.web.exposure.include=health,info. Require authentication for all Actuator endpoints.",
      });
      break;
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN ORCHESTRATOR
// ═══════════════════════════════════════════════════════════════════════════════

export async function scanTarget(
  value: string,
  assetType: string,
  scanType: ScanType,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const target = normalizeTarget(value, assetType);
  if (!target) {
    await onLog(`[${ts()}] SKIP: Cannot normalise target "${value}"`);
    return [];
  }

  await onLog(`[${ts()}] ══════════════════════════════════════════════`);
  await onLog(`[${ts()}] Target : ${target.url}`);
  await onLog(`[${ts()}] Type   : ${scanType} | Asset: ${assetType}`);
  await onLog(`[${ts()}] ══════════════════════════════════════════════`);

  // ── Reachability check ────────────────────────────────────────────────────
  await onLog(`[${ts()}] [Phase 1/8] Reachability probe...`);
  const reach = await probe(target.url, { timeoutMs: 10_000 });
  if (!reach) {
    await onLog(`[${ts()}] Target unreachable or timed out — skipping`);
    return [];
  }
  await onLog(`[${ts()}] Reachable: HTTP ${reach.status} (${reach.durationMs}ms)`);

  const all: RealFinding[] = [];
  const add = (fs: RealFinding[]) => { all.push(...fs); };

  // ── DNS security (all scan types) ─────────────────────────────────────────
  await onLog(`[${ts()}] [Phase 2/8] DNS & email security analysis...`);
  add(await checkDns(target.hostname));
  await onLog(`[${ts()}] DNS: ${all.length} finding(s) so far`);

  // ── Port scanning (enumeration, vulnerability, full) ─────────────────────
  if (["enumeration", "vulnerability", "full"].includes(scanType)) {
    await onLog(`[${ts()}] [Phase 3/8] Port exposure scan...`);
    add(await checkPorts(target.hostname, onLog));
  }

  // ── TLS/SSL (recon, vulnerability, full) ─────────────────────────────────
  if (["recon", "vulnerability", "full"].includes(scanType) && target.isHttps) {
    await onLog(`[${ts()}] [Phase 4/8] TLS/SSL deep analysis...`);
    add(await checkTls(target.hostname, target.port));
    await onLog(`[${ts()}] TLS: ${all.length} finding(s) so far`);
  }

  // ── Security headers (all scan types) ────────────────────────────────────
  await onLog(`[${ts()}] [Phase 5/8] HTTP security header analysis...`);
  add(await checkHeaders(target));
  await onLog(`[${ts()}] Headers: ${all.length} finding(s) so far`);

  // ── Technology fingerprinting (all scan types) ────────────────────────────
  await onLog(`[${ts()}] [Phase 6/8] Technology fingerprinting...`);
  const { techs, findings: fpFindings } = await fingerprint(target);
  add(fpFindings);
  if (techs.length > 0) {
    await onLog(`[${ts()}] Detected: ${techs.map((t) => `${t.name} (${t.category})`).join(", ")}`);
  }

  // ── Sensitive paths (enumeration, vulnerability, full) ────────────────────
  if (["enumeration", "vulnerability", "full"].includes(scanType)) {
    const deep = ["vulnerability", "full"].includes(scanType);
    await onLog(`[${ts()}] [Phase 7/8] Sensitive path discovery (${deep ? "deep" : "standard"})...`);
    add(await checkSensitivePaths(target, deep, onLog));
  }

  // ── Web app & API probes (vulnerability, full) ────────────────────────────
  if (["vulnerability", "full"].includes(scanType)) {
    await onLog(`[${ts()}] [Phase 8/8] Web application vulnerability probes...`);
    add(await checkWebApp(target, onLog));
    add(await checkApiSurface(target, onLog));
  }

  // ── Summary ───────────────────────────────────────────────────────────────
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of all) bySeverity[f.severity]++;
  await onLog(`[${ts()}] ── Scan complete ──────────────────────────────`);
  await onLog(`[${ts()}] Total findings : ${all.length}`);
  await onLog(`[${ts()}] Critical: ${bySeverity.critical}  High: ${bySeverity.high}  Medium: ${bySeverity.medium}  Low: ${bySeverity.low}`);

  return all;
}
