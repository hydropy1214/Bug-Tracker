import { isContextualReflection, ts } from '../context';
import type { LogFn, RealFinding, ScanPolicy, Target } from '../context';
import { createFinding } from '../utils/findings';
import { probe } from '../utils/http';
import {
  getParameterCandidates,
  makeParameterRequest,
  type SurfaceInventory,
  type SurfaceParameter,
} from './surface-discovery';

const SQL_ERRORS = [
  /you have an error in your sql syntax/i,
  /warning.*mysql.*query/i,
  /mysql_fetch|mysqli?[_\s]/i,
  /pg_query\(\): query failed|postgresql.*error|pgsql.*error/i,
  /unterminated quoted string|unclosed quotation mark/i,
  /odbc.*sql server|microsoft.*ole db/i,
  /ora-\d{5}|quoted string not properly terminated/i,
  /sqlite(?:3)?[.\s].*(?:error|exception)/i,
  /sql(?:exception| syntax error| command not properly ended)/i,
];

const SQL_ERROR_PROBES = ["'", '"', '`', "')", "'--", '1))'];
const BOOLEAN_PAIRS = [
  ['1 AND 1=1', '1 AND 1=2'],
  ["' AND '1'='1", "' AND '1'='2"],
  ['1 OR 1=1--', '1 OR 1=2--'],
];

const URL_PARAMETER_HINT = /(?:url|uri|href|redirect|return|next|dest|destination|link|continue|callback|feed|image|src|path|file|template|include|load)/i;
const FILE_PARAMETER_HINT = /(?:file|path|page|template|view|doc|document|include|load|read|download|attachment)/i;

interface ResponseFingerprint {
  status: number;
  length: number;
  words: Set<string>;
}

function fingerprint(body: string, status: number): ResponseFingerprint {
  const words = new Set(
    body
      .toLowerCase()
      .replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/[^a-z0-9]+/g, ' ')
      .split(/\s+/)
      .filter((word) => word.length >= 5)
      .slice(0, 600),
  );
  return { status, length: body.length, words };
}

function similarity(left: ResponseFingerprint, right: ResponseFingerprint): number {
  const smaller = left.words.size < right.words.size ? left.words : right.words;
  const larger = left.words.size < right.words.size ? right.words : left.words;
  let overlap = 0;
  for (const word of smaller) if (larger.has(word)) overlap++;
  return overlap / Math.max(larger.size, 1);
}

function changedFromBaseline(
  baseline: ResponseFingerprint,
  response: ResponseFingerprint,
): boolean {
  return (
    baseline.status !== response.status ||
    Math.abs(baseline.length - response.length) > Math.max(80, baseline.length * 0.12) ||
    similarity(baseline, response) < 0.82
  );
}

function candidateKey(candidate: SurfaceParameter): string {
  return `${candidate.method} ${candidate.endpoint}#${candidate.parameter}`;
}

function buildRequest(candidate: SurfaceParameter, value: string) {
  return makeParameterRequest(candidate, value);
}

function isHtml(response: { headers: Record<string, string> }): boolean {
  return /text\/html|application\/xhtml/i.test(response.headers['content-type'] ?? '');
}

export async function runDeepInputTesting(
  target: Target,
  policy: ScanPolicy,
  inventory: SurfaceInventory,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const candidates = getParameterCandidates(inventory, target, policy.allowDeepChecks ? 48 : 20);
  await onLog(
    `[${ts()}] Deep input testing — ${candidates.length} discovered parameter targets with per-endpoint baselines.`,
  );

  const baselines = new Map<string, ResponseFingerprint>();
  for (const candidate of candidates) {
    const request = buildRequest(candidate, candidate.sampleValue || 'sentinelx-baseline');
    const response = await probe(request.url, request.options);
    if (response) baselines.set(candidateKey(candidate), fingerprint(response.body, response.status));
  }

  // Error-based and boolean SQL injection. A finding requires a baseline
  // difference and either a database error or a repeatable true/false split.
  const sqlCandidates = candidates.filter((candidate) =>
    /(?:id|user|account|order|product|item|search|query|filter|sort|page|name|value|input)/i.test(
      candidate.parameter,
    ),
  );
  for (const candidate of sqlCandidates.slice(0, policy.allowDeepChecks ? 24 : 10)) {
    const baseline = baselines.get(candidateKey(candidate));
    if (!baseline) continue;
    let errorFinding = false;
    for (const payload of SQL_ERROR_PROBES) {
      const request = buildRequest(candidate, payload);
      const response = await probe(request.url, request.options);
      if (!response) continue;
      const error = SQL_ERRORS.find((pattern) => pattern.test(response.body));
      if (!error || !changedFromBaseline(baseline, fingerprint(response.body, response.status))) continue;
      const confirmRequest = buildRequest(candidate, `${payload}sentinelx`);
      const confirm = await probe(confirmRequest.url, confirmRequest.options);
      const confirmed = Boolean(
        confirm &&
          SQL_ERRORS.some((pattern) => pattern.test(confirm.body)) &&
          changedFromBaseline(baseline, fingerprint(confirm.body, confirm.status)),
      );
      findings.push(
        createFinding({
          title: `SQL Injection — Database Error at ${candidate.endpoint}`,
          severity: confirmed ? 'high' : 'medium',
          verification: confirmed ? 'verified' : 'suspected',
          verified: confirmed,
          confidence: confirmed ? 91 : 72,
          evidenceQuality: confirmed ? 'strong' : 'standard',
          verificationMethod: 'Endpoint-specific baseline plus repeated database error response.',
          reproducibility: confirmed ? 'reproducible' : 'intermittent',
          affectedEndpoint: candidate.endpoint,
          affectedParameter: candidate.parameter,
          cvss: confirmed ? 8.1 : 6.5,
          cve: null,
          description: `The discovered ${candidate.method} input '${candidate.parameter}' produced a database error absent from its normal response.`,
          evidence: `BASELINE ${candidate.method} ${candidate.endpoint} → HTTP ${baseline.status}, ${baseline.length} bytes\nPROBE ${request.url} → HTTP ${response.status}, ${response.body.length} bytes\nDATABASE MARKER: ${error}`,
          negativeTests: `Baseline value: ${candidate.sampleValue || 'sentinelx-baseline'}; repeated probe: ${confirmed ? 'same database marker reproduced' : 'not reproduced'}`,
          remediation: 'Use parameterized queries, validate types at the boundary, and return generic errors.',
          compliance: { owasp: ['A03'], pci: ['6.2.4'], nist: ['SI-10'] },
        }),
      );
      await onLog(`[${ts()}] SQL injection ${confirmed ? 'confirmed' : 'signal'}: ${candidate.endpoint}#${candidate.parameter}`);
      errorFinding = true;
      break;
    }
    if (errorFinding) continue;

    for (const [truePayload, falsePayload] of BOOLEAN_PAIRS.slice(
      0,
      policy.allowDeepChecks ? BOOLEAN_PAIRS.length : 1,
    )) {
      const trueRequest = buildRequest(candidate, truePayload);
      const falseRequest = buildRequest(candidate, falsePayload);
      const [trueResponse, falseResponse] = await Promise.all([
        probe(trueRequest.url, trueRequest.options),
        probe(falseRequest.url, falseRequest.options),
      ]);
      if (!trueResponse || !falseResponse) continue;
      const trueFingerprint = fingerprint(trueResponse.body, trueResponse.status);
      const falseFingerprint = fingerprint(falseResponse.body, falseResponse.status);
      const trueMatchesBaseline = similarity(trueFingerprint, baseline) > 0.86;
      const falseDiffers = changedFromBaseline(baseline, falseFingerprint);
      const pairDiffers = changedFromBaseline(trueFingerprint, falseFingerprint);
      if (!trueMatchesBaseline || !falseDiffers || !pairDiffers) continue;

      const confirmRequest = buildRequest(candidate, truePayload);
      const confirm = await probe(confirmRequest.url, confirmRequest.options);
      const confirmed = Boolean(
        confirm &&
          similarity(fingerprint(confirm.body, confirm.status), trueFingerprint) > 0.86,
      );
      findings.push(
        createFinding({
          title: `Blind SQL Injection — Boolean Differential at ${candidate.endpoint}`,
          severity: confirmed ? 'high' : 'medium',
          verification: confirmed ? 'verified' : 'suspected',
          verified: confirmed,
          confidence: confirmed ? 86 : 68,
          evidenceQuality: confirmed ? 'strong' : 'standard',
          verificationMethod: 'Baseline, true-condition, false-condition, and repeat response comparison.',
          reproducibility: confirmed ? 'reproducible' : 'intermittent',
          affectedEndpoint: candidate.endpoint,
          affectedParameter: candidate.parameter,
          cvss: confirmed ? 8.1 : 6.5,
          cve: null,
          description: `The discovered input '${candidate.parameter}' returns the baseline result for a true condition and a materially different result for a false condition.`,
          evidence: `TRUE ${trueRequest.url} → HTTP ${trueResponse.status}, ${trueResponse.body.length} bytes\nFALSE ${falseRequest.url} → HTTP ${falseResponse.status}, ${falseResponse.body.length} bytes\nBASELINE → HTTP ${baseline.status}, ${baseline.length} bytes`,
          negativeTests: `Repeated true condition: ${confirmed ? 'matched original true response' : 'not reproduced'}`,
          remediation: 'Use parameterized queries and avoid concatenating request values into SQL.',
          compliance: { owasp: ['A03'], pci: ['6.2.4'], nist: ['SI-10'] },
        }),
      );
      await onLog(`[${ts()}] Boolean SQL injection ${confirmed ? 'confirmed' : 'signal'}: ${candidate.endpoint}#${candidate.parameter}`);
      break;
    }
  }

  // Reflected XSS requires executable HTML context, not just a text echo.
  const xssToken = `sx${Date.now().toString(36).slice(-8)}`;
  const xssPayload = `<svg/onload=sentinelx_${xssToken}>`;
  for (const candidate of candidates.slice(0, policy.allowDeepChecks ? 32 : 14)) {
    const request = buildRequest(candidate, xssPayload);
    const response = await probe(request.url, request.options);
    if (!response || !isHtml(response)) continue;
    const executable = new RegExp(
      `<svg\\b[^>]*onload\\s*=\\s*sentinelx_${xssToken}`,
      'i',
    ).test(response.body);
    if (!executable || !isContextualReflection(response.body, xssPayload)) continue;
    const baseline = baselines.get(candidateKey(candidate));
    findings.push(
      createFinding({
        title: `Reflected XSS — Executable Payload at ${candidate.endpoint}`,
        severity: 'high',
        verification: 'verified',
        verified: true,
        confidence: 96,
        evidenceQuality: 'strong',
        verificationMethod: 'Unique SVG event-handler canary survived in an HTML response without encoding.',
        reproducibility: 'reproducible',
        affectedEndpoint: candidate.endpoint,
        affectedParameter: candidate.parameter,
        cvss: 8.2,
        cve: null,
        description: `The discovered ${candidate.method} input '${candidate.parameter}' is reflected in an executable HTML context.`,
        evidence: `${candidate.method} ${request.url} → HTTP ${response.status}\nContent-Type: ${response.headers['content-type']}\nCanary: sentinelx_${xssToken}\nBaseline available: ${Boolean(baseline)}`,
        remediation: 'Apply contextual output encoding, use a strict Content-Security-Policy, and validate input server-side.',
        compliance: { owasp: ['A03'], pci: ['6.2.4'], nist: ['SI-10'] },
      }),
    );
    await onLog(`[${ts()}] Reflected XSS confirmed: ${candidate.endpoint}#${candidate.parameter}`);
  }

  // Open redirect checks are limited to URL-like parameters and do not follow
  // redirects, so they cannot mutate target state.
  const redirectToken = `sentinelx-redirect-${Date.now().toString(36)}`;
  for (const candidate of candidates.filter((item) => URL_PARAMETER_HINT.test(item.parameter)).slice(0, 20)) {
    const destination = `https://${redirectToken}.invalid/`;
    const request = buildRequest(candidate, destination);
    const response = await probe(request.url, { ...request.options, followRedirects: false });
    const location = response?.headers['location'] ?? '';
    if (!response || ![301, 302, 303, 307, 308].includes(response.status) || !location.includes(redirectToken)) continue;
    findings.push(
      createFinding({
        title: `Open Redirect — Unvalidated Destination at ${candidate.endpoint}`,
        severity: 'medium',
        verification: 'verified',
        verified: true,
        confidence: 95,
        evidenceQuality: 'strong',
        verificationMethod: 'Non-following request returned a redirect Location containing a unique external canary.',
        reproducibility: 'reproducible',
        affectedEndpoint: candidate.endpoint,
        affectedParameter: candidate.parameter,
        cvss: 6.1,
        cve: null,
        description: `The '${candidate.parameter}' input controls an external redirect destination.`,
        evidence: `${candidate.method} ${request.url} → HTTP ${response.status}\nLocation: ${location}`,
        remediation: 'Allow only relative destinations or validate external destinations against an explicit allowlist.',
        compliance: { owasp: ['A01'], pci: ['6.2.4'], nist: ['SI-10'] },
      }),
    );
    await onLog(`[${ts()}] Open redirect confirmed: ${candidate.endpoint}#${candidate.parameter}`);
  }

  // File-read probes require a strong OS marker and a baseline difference.
  const traversalPayloads = [
    '../../../../etc/passwd',
    '..%2f..%2f..%2f..%2fetc%2fpasswd',
    '..%252f..%252f..%252f..%252fetc%2fpasswd',
    '..\\..\\..\\..\\windows\\win.ini',
  ];
  for (const candidate of candidates.filter((item) => FILE_PARAMETER_HINT.test(item.parameter)).slice(0, 16)) {
    const baseline = baselines.get(candidateKey(candidate));
    for (const payload of traversalPayloads) {
      const request = buildRequest(candidate, payload);
      const response = await probe(request.url, request.options);
      if (!response) continue;
      const linux = /(?:^|\n)root:[^:\n]*:0:0:/m.test(response.body);
      const windows = /\[(?:fonts|extensions|mci extensions)\]/i.test(response.body);
      if (!linux && !windows) continue;
      if (baseline && !changedFromBaseline(baseline, fingerprint(response.body, response.status))) continue;
      findings.push(
        createFinding({
          title: `Path Traversal — ${linux ? '/etc/passwd' : 'win.ini'} Retrieved`,
          severity: 'critical',
          verification: 'verified',
          verified: true,
          confidence: 99,
          evidenceQuality: 'strong',
          verificationMethod: 'High-entropy OS file marker returned from a discovered file/path input.',
          reproducibility: 'reproducible',
          affectedEndpoint: candidate.endpoint,
          affectedParameter: candidate.parameter,
          cvss: 9.8,
          cve: null,
          description: `The discovered '${candidate.parameter}' input retrieved a protected operating-system file.`,
          evidence: `${candidate.method} ${request.url} → HTTP ${response.status}\nMarker: ${linux ? 'root:x:0:0:' : '[fonts/extensions]'}`,
          remediation: 'Use an allowlist of server-side files and never concatenate request values into filesystem paths.',
          compliance: { owasp: ['A01'], pci: ['6.2.4'], nist: ['AC-3', 'SI-10'] },
        }),
      );
      await onLog(`[${ts()}] Path traversal confirmed: ${candidate.endpoint}#${candidate.parameter}`);
      break;
    }
  }

  await onLog(`[${ts()}] Deep input testing complete — ${findings.length} evidence-backed finding(s).`);
  return findings;
}