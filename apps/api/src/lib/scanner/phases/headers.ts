import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

export async function checkHeaders(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const r = await probe(target.url, { timeoutMs: 12_000 });
  if (!r) {
    await onLog(`[${ts()}] WARNING: Could not reach ${target.url} for header check`);
    return findings;
  }
  const h = r.headers;
  const rawHeaders = Object.entries(h).map(([k, v]) => `  ${k}: ${v}`).join('\n');
  const ev = (info: string) =>
    `GET ${target.url} → HTTP ${r.status}\nResponse headers:\n${rawHeaders}\n\n${info}`;
  await onLog(`[${ts()}] HTTP ${r.status} — checking ${Object.keys(h).length} response headers...`);

  if (!target.isHttps) {
    const httpR = await probe(`http://${target.hostname}/`, { followRedirects: false, timeoutMs: 8_000 });
    if (httpR && httpR.status >= 200 && httpR.status < 300) {
      findings.push({ title: 'HTTP Not Redirected to HTTPS', severity: 'high', cvss: 7.4, cve: null, description: 'The server serves content over HTTP without redirecting.', evidence: `GET http://${target.hostname}/ → HTTP ${httpR.status}`, remediation: 'Configure 301 redirect to HTTPS.' });
    }
  }

  const hsts = h['strict-transport-security'];
  if (target.isHttps && !hsts) {
    findings.push({ title: 'Missing HTTP Strict Transport Security (HSTS)', severity: 'medium', cvss: 6.1, cve: null, description: 'HSTS header is absent.', evidence: ev('Strict-Transport-Security: (absent)'), remediation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' });
  } else if (hsts) {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]!) : 0;
    if (maxAge < 31536000) {
      findings.push({ title: 'HSTS max-age Too Short', severity: 'low', cvss: 3.1, cve: null, description: `HSTS max-age is ${maxAge} seconds (${Math.round(maxAge / 86400)} days).`, evidence: ev(`Strict-Transport-Security: ${hsts}`), remediation: 'Set max-age to at least 31536000 (1 year).' });
    }
  }

  if (!h['content-security-policy']) {
    findings.push({ title: 'Missing Content-Security-Policy Header', severity: 'low', cvss: 3.7, cve: null, description: 'No CSP header is set.', evidence: ev('Content-Security-Policy: (absent)'), remediation: 'Implement a strict CSP.' });
  } else {
    const csp = h['content-security-policy']!;
    if (/unsafe-eval/i.test(csp)) {
      findings.push({ title: "CSP Contains 'unsafe-eval'", severity: 'medium', cvss: 5.3, cve: null, description: "CSP includes 'unsafe-eval'.", evidence: ev(`Content-Security-Policy: ${csp.slice(0, 200)}`), remediation: "Remove 'unsafe-eval'." });
    }
    if (/unsafe-inline/i.test(csp) && !/nonce-|hash-|sha/i.test(csp)) {
      findings.push({ title: "CSP Contains 'unsafe-inline' Without Nonce/Hash", severity: 'medium', cvss: 5.3, cve: null, description: 'CSP allows all inline scripts.', evidence: ev(`Content-Security-Policy: ${csp.slice(0, 200)}`), remediation: 'Replace with nonce-based CSP.' });
    }
    if (/\*/.test(csp.split('script-src')[1]?.split(';')[0] ?? '')) {
      findings.push({ title: 'CSP script-src Allows Wildcard Origin', severity: 'high', cvss: 7.4, cve: null, description: 'CSP script-src includes a wildcard (*).', evidence: ev(`Content-Security-Policy: ${csp.slice(0, 300)}`), remediation: 'Replace wildcard with explicit trusted domains.' });
    }
  }

  const xfo = h['x-frame-options'] ?? '';
  const cspFa = h['content-security-policy'] ?? '';
  if (!xfo && !cspFa.toLowerCase().includes('frame-ancestors')) {
    findings.push({ title: 'Clickjacking Protection Missing', severity: 'low', cvss: 4.3, cve: null, description: 'No X-Frame-Options or CSP frame-ancestors directive found.', evidence: ev('X-Frame-Options: (absent)'), remediation: "Add: X-Frame-Options: DENY or CSP: frame-ancestors 'none'" });
  }
  if (!h['x-content-type-options']) {
    findings.push({ title: 'Missing X-Content-Type-Options Header', severity: 'low', cvss: 3.7, cve: null, description: 'Without nosniff, MIME-sniffing possible.', evidence: ev('X-Content-Type-Options: (absent)'), remediation: 'Add: X-Content-Type-Options: nosniff' });
  }
  if (!h['referrer-policy']) {
    findings.push({ title: 'Missing Referrer-Policy Header', severity: 'low', cvss: 3.1, cve: null, description: 'Referrer-Policy absent.', evidence: ev('Referrer-Policy: (absent)'), remediation: 'Add: Referrer-Policy: strict-origin-when-cross-origin' });
  }
  if (!h['permissions-policy']) {
    findings.push({ title: 'Missing Permissions-Policy Header', severity: 'low', cvss: 3.1, cve: null, description: 'Permissions-Policy absent.', evidence: ev('Permissions-Policy: (absent)'), remediation: 'Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()' });
  }
  const server = h['server'] ?? '';
  if (server && /[\d.]/.test(server)) {
    findings.push({ title: 'Server Version Disclosed', severity: 'low', cvss: 4.3, cve: null, description: `Server header: "${server}".`, evidence: ev(`Server: ${server}`), remediation: 'Suppress Server header.' });
  }
  for (const discHeader of ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator']) {
    const val = h[discHeader];
    if (val) {
      findings.push({ title: `Technology Disclosed via ${discHeader}`, severity: 'low', cvss: 3.1, cve: null, description: `${discHeader}: ${val}`, evidence: ev(`${discHeader}: ${val}`), remediation: `Suppress ${discHeader} header.` });
    }
  }

  // CORS active test
  const corsTestOrigins = ['https://attacker.com', 'https://evil.attacker.example'];
  let corsFound = false;
  for (const attackerOrigin of corsTestOrigins) {
    if (corsFound) break;
    const corsR = await probe(target.url, {
      headers: { Origin: attackerOrigin, 'Access-Control-Request-Method': 'GET' },
      timeoutMs: 8_000,
    });
    if (!corsR) continue;
    const acao = corsR.headers['access-control-allow-origin'] ?? '';
    const acac = corsR.headers['access-control-allow-credentials'] ?? '';
    if (acao === '*') {
      findings.push({ title: 'CORS Wildcard Origin (*)', severity: 'medium', cvss: 6.5, cve: null, description: 'Any origin can read responses.', evidence: `Origin: ${attackerOrigin}\nAccess-Control-Allow-Origin: *`, remediation: 'Replace * with explicit allowlist.' });
      corsFound = true;
    } else if (acao === attackerOrigin && acac.toLowerCase() === 'true') {
      findings.push({ title: 'CRITICAL: CORS Reflects Arbitrary Origin + Credentials', severity: 'critical', cvss: 9.0, cve: null, description: 'Server reflects origin and allows credentials.', evidence: `Origin: ${attackerOrigin}\nAccess-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac}`, remediation: 'Never combine reflected origin with credentials.' });
      corsFound = true;
    } else if (acao === attackerOrigin && acac.toLowerCase() !== 'true') {
      findings.push({ title: 'CORS Reflects Arbitrary Origin (No Credentials)', severity: 'medium', cvss: 5.3, cve: null, description: 'Server reflects origin without credentials.', evidence: `Origin: ${attackerOrigin}\nAccess-Control-Allow-Origin: ${acao}`, remediation: 'Validate Origin against strict allowlist.' });
      corsFound = true;
    }
  }

  // Cookie security
  const setCookie = h['set-cookie'] ?? '';
  if (setCookie) {
    const lower = setCookie.toLowerCase();
    const nameMatch = setCookie.match(/^([^=;,\s]+)/);
    const cookieName = nameMatch?.[1]?.trim() ?? 'cookie';
    if (!lower.includes('httponly')) {
      findings.push({ title: `Cookie Missing HttpOnly Flag (${cookieName})`, severity: 'medium', cvss: 6.1, cve: null, description: `Cookie "${cookieName}" readable by JavaScript.`, evidence: `Set-Cookie: ${setCookie.slice(0, 200)}`, remediation: `Add HttpOnly flag.` });
    }
    if (target.isHttps && !lower.includes('secure')) {
      findings.push({ title: `Cookie Missing Secure Flag (${cookieName})`, severity: 'medium', cvss: 5.9, cve: null, description: `Cookie "${cookieName}" can be sent over HTTP.`, evidence: `Set-Cookie: ${setCookie.slice(0, 200)}`, remediation: `Add Secure flag.` });
    }
    if (!lower.includes('samesite')) {
      findings.push({ title: `Cookie Missing SameSite Attribute (${cookieName})`, severity: 'low', cvss: 4.3, cve: null, description: `Cookie "${cookieName}" missing SameSite.`, evidence: `Set-Cookie: ${setCookie.slice(0, 200)}`, remediation: `Add SameSite=Strict.` });
    }
  }

  // TRACE method
  const traceR = await probe(target.url, { method: 'TRACE', timeoutMs: 6_000 });
  if (traceR && traceR.status === 200) {
    findings.push({ title: 'HTTP TRACE Method Enabled', severity: 'medium', cvss: 5.3, cve: null, description: 'TRACE method enabled.', evidence: `TRACE ${target.url} → HTTP ${traceR.status}`, remediation: 'Disable TRACE.' });
  }

  await onLog(`[${ts()}] HTTP header analysis complete — ${findings.length} finding(s)`);
  return findings;
}
