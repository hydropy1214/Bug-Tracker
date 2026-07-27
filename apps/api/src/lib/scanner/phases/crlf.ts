import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

export async function checkCrlfInjection(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing CRLF injection...`);
  const injectedHeader = 'X-Sentinel-Injected';
  const injectedValue = 'crlfpoc';
  const crlfPayloads = [
    `%0d%0a${injectedHeader}:${injectedValue}`,
    `%0a${injectedHeader}:${injectedValue}`,
    `%0d%0a%20${injectedHeader}:${injectedValue}`,
    `\r\n${injectedHeader}:${injectedValue}`,
  ];
  for (const payload of crlfPayloads) {
    for (const param of ['url', 'redirect', 'next', 'return', 'ref', 'goto', 'location', 'redir']) {
      const probeUrl = `${target.url.replace(/\/$/, '')}?${param}=${encodeURIComponent(payload)}`;
      const r = await probe(probeUrl, { followRedirects: false, timeoutMs: 8_000 });
      if (!r) continue;
      if (r.headers[injectedHeader.toLowerCase()] === injectedValue) {
        findings.push({
          title: 'CRLF Injection — Response Splitting Confirmed',
          severity: 'high',
          verification: 'verified',
          confidence: 95,
          cvss: 7.5,
          cve: null,
          description: `The application reflects CRLF sequences into HTTP response headers via '${param}'.`,
          evidence: `PROBE: ${probeUrl}\nHTTP ${r.status} — ${injectedHeader}: ${injectedValue} header present in response`,
          remediation: 'Sanitise all user input before inserting into HTTP headers.',
        });
        await onLog(`[${ts()}] ⚠ CRLF INJECTION CONFIRMED`);
        return findings;
      }
    }
  }
  return findings;
}
