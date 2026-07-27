import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, LogFn } from '../context';

export async function checkWayback(hostname: string, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Querying Wayback Machine CDX API...`);
  try {
    const url = `https://web.archive.org/cdx/search/cdx?url=${hostname}/*&output=json&fl=original&collapse=urlkey&limit=200&filter=statuscode:200`;
    const r = await probe(url, { timeoutMs: 20_000 });
    if (!r || r.status !== 200) return findings;
    const rows: string[][] = JSON.parse(r.body);
    if (rows.length < 2) return findings;
    const urls = rows.slice(1).map((r) => r[0]!).filter(Boolean);
    await onLog(`[${ts()}] Wayback Machine: ${urls.length} historical URL(s)`);
    const sensitive = urls.filter(
      (u) =>
        /\.(sql|bak|zip|tar|gz|env|config|conf|cfg|log|xml|json|key|pem|p12|pfx|yaml|yml|ini|htpasswd|git|svn)/i.test(u) ||
        /\/admin|\/backup|\/\.env|\/config|\/debug|\/test|\/dev|\/api\/internal|\/private/i.test(u),
    );
    if (sensitive.length > 0) {
      findings.push({
        title: `${sensitive.length} Sensitive Historical URL(s) in Wayback Machine`,
        severity: 'medium',
        verification: 'suspected',
        confidence: 55,
        cvss: 5.3,
        cve: null,
        description: `Wayback Machine has archived sensitive paths.`,
        evidence: `Sensitive URLs:\n${sensitive.slice(0, 15).join('\n')}`,
        remediation: 'Audit each URL.',
      });
    }
    const apiKeyUrls = urls.filter((u) =>
      /api[_-]?key=|apikey=|access_token=|secret=|password=|token=/i.test(u),
    );
    if (apiKeyUrls.length > 0) {
      findings.push({
        title: 'API Keys or Secrets Found in Historical URLs',
        severity: 'high',
        verification: 'suspected',
        confidence: 60,
        cvss: 8.1,
        cve: null,
        description: `${apiKeyUrls.length} URLs contain potential secrets.`,
        evidence: `API key URLs:\n${apiKeyUrls.slice(0, 5).join('\n')}`,
        remediation: 'Revoke exposed credentials immediately.',
      });
    }
  } catch (err: any) {
    await onLog(`[${ts()}] Wayback lookup error: ${err?.message ?? 'timeout'}`);
  }
  return findings;
}
