import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

const SENSITIVE_PATHS: { path: string; deep?: boolean; finding: Omit<RealFinding, 'evidence'> }[] = [
  { path: '/.env', finding: { title: '.env File Exposed', severity: 'critical', cvss: 9.8, cve: null, description: 'The .env file is publicly accessible.', remediation: 'Block access to .env files.' } },
  { path: '/.git/config', finding: { title: 'Git Repository Exposed (.git/config)', severity: 'critical', cvss: 9.8, cve: null, description: '.git directory is accessible.', remediation: 'Block /.git/ access.' } },
  { path: '/robots.txt', finding: { title: 'robots.txt Reveals Internal Paths', severity: 'low', cvss: 3.1, cve: null, description: 'robots.txt is accessible.', remediation: 'Review for sensitive paths.' } },
  { path: '/phpinfo.php', finding: { title: 'PHP Info Page Exposed', severity: 'high', cvss: 7.5, cve: null, description: 'phpinfo() output publicly accessible.', remediation: 'Delete phpinfo.php.' } },
  { path: '/wp-login.php', finding: { title: 'WordPress Admin Login Exposed', severity: 'medium', cvss: 5.3, cve: null, description: 'WordPress login publicly accessible.', remediation: 'Rename wp-login.php, add IP restrictions.' } },
  { path: '/.env.local', finding: { title: '.env.local File Exposed', severity: 'critical', cvss: 9.8, cve: null, description: '.env.local publicly accessible.', remediation: 'Block all .env* files.' } },
  { path: '/.env.production', finding: { title: '.env.production Exposed', severity: 'critical', cvss: 9.8, cve: null, description: 'Production environment file exposed.', remediation: 'Block .env* files.' } },
  { path: '/.git/HEAD', finding: { title: 'Git Repository HEAD Exposed', severity: 'critical', cvss: 9.8, cve: null, description: '.git directory accessible.', remediation: 'Block /.git/ access.' } },
  { path: '/backup.sql', finding: { title: 'Database Backup Exposed (backup.sql)', severity: 'critical', cvss: 9.8, cve: null, description: 'SQL backup publicly downloadable.', remediation: 'Remove backup files from web root.' } },
  { path: '/dump.sql', finding: { title: 'Database Dump Exposed (dump.sql)', severity: 'critical', cvss: 9.8, cve: null, description: 'SQL dump publicly accessible.', remediation: 'Remove dump files.' } },
  { path: '/adminer.php', finding: { title: 'Adminer Database UI Exposed', severity: 'critical', cvss: 9.8, cve: null, description: 'Adminer is publicly accessible.', remediation: 'Remove Adminer from production.' } },
  { path: '/phpmyadmin/', finding: { title: 'phpMyAdmin Exposed', severity: 'high', cvss: 8.1, cve: null, description: 'phpMyAdmin publicly accessible.', remediation: 'Restrict to internal IPs.' } },
  { path: '/.DS_Store', finding: { title: '.DS_Store File Exposed', severity: 'medium', cvss: 5.3, cve: null, description: 'macOS .DS_Store exposed.', remediation: 'Block .DS_Store files.' } },
  { path: '/.htpasswd', finding: { title: '.htpasswd File Exposed', severity: 'critical', cvss: 9.8, cve: null, description: '.htpasswd credential file publicly readable.', remediation: 'Block .htpasswd.' } },
  { path: '/config.php', finding: { title: 'config.php Exposed', severity: 'high', cvss: 7.5, cve: null, description: 'Configuration file may contain credentials.', remediation: 'Move config outside web root.' } },
  { path: '/.well-known/security.txt', finding: { title: 'security.txt Present (Informational)', severity: 'low', cvss: 0, cve: null, description: 'RFC 9116 security.txt found.', remediation: 'Keep up-to-date.', verification: 'informational', confidence: 99 } },
  { path: '/api/v1/', finding: { title: 'API v1 Endpoint Accessible', severity: 'low', cvss: 3.1, cve: null, description: 'API endpoint discovered.', remediation: 'Ensure proper authentication.' } },
  { path: '/graphql', finding: { title: 'GraphQL Endpoint Exposed', severity: 'medium', cvss: 5.3, cve: null, description: 'GraphQL endpoint publicly accessible.', remediation: 'Disable introspection, require auth.' } },
  { path: '/crossdomain.xml', finding: { title: 'crossdomain.xml Present', severity: 'low', cvss: 3.1, cve: null, description: 'Flash crossdomain.xml found.', remediation: 'Remove if Flash not used.' } },
  { path: '/.aws/credentials', finding: { title: 'AWS Credentials File Exposed', severity: 'critical', cvss: 10.0, cve: null, description: 'AWS credentials publicly accessible.', remediation: 'Remove and revoke keys.' } },
  { path: '/id_rsa', finding: { title: 'SSH Private Key Exposed (id_rsa)', severity: 'critical', cvss: 10.0, cve: null, description: 'SSH private key publicly accessible.', remediation: 'Remove and rotate key pair.' } },
];

const contentMarkers: Record<string, RegExp> = {
  '/.env': /(?:^|\n)\s*[A-Z][A-Z0-9_]{2,}\s*=/,
  '/.git/config': /^\s*(?:\[core\]|repositoryformatversion|ref:)/im,
  '/.git/HEAD': /^\s*ref:\s+refs\//im,
  '/backup.sql': /(create\s+table|insert\s+into|--\s*(?:mysql|postgres|sql))/i,
  '/phpinfo.php': /(php version|phpinfo\(\)|configuration file)/i,
  '/wp-login.php': /(wp-login|user_login|wordpress)/i,
  '/robots.txt': /(?:^|\n)\s*(?:user-agent|disallow|sitemap)\s*:/i,
};

export async function checkSensitivePaths(
  target: Target,
  deep: boolean,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const paths = SENSITIVE_PATHS.filter((p) => !p.deep || deep);
  await onLog(`[${ts()}] Probing ${paths.length} sensitive paths...`);
  const BATCH = 12;
  const findings: RealFinding[] = [];
  const notFoundUrl = `${target.url.replace(/\/$/, '')}/sentinelx-not-found-${Date.now()}`;
  const notFound = await probe(notFoundUrl, { timeoutMs: 8_000 });
  const compact = (value: string) => value.replace(/\s+/g, ' ').trim().slice(0, 4_000);

  for (let i = 0; i < paths.length; i += BATCH) {
    const batch = paths.slice(i, i + BATCH);
    const results = await Promise.allSettled(
      batch.map(async ({ path, finding }) => {
        const url = target.url.replace(/\/$/, '') + path;
        const result = await probe(url, { timeoutMs: 8_000 });
        if (!result || result.status !== 200) return null;
        const resultBody = compact(result.body);
        const baselineBody = notFound ? compact(notFound.body) : '';
        if (notFound && result.status === notFound.status && resultBody === baselineBody) return null;
        const marker = contentMarkers[path];
        if (marker && !marker.test(result.body)) return null;
        if (!marker && resultBody.toLowerCase().includes('404') && result.body.length < 2_000) return null;
        const snippet = result.body.slice(0, 300).replace(/\s+/g, ' ').trim();
        return {
          ...finding,
          evidence: `GET ${url} → HTTP ${result.status} (${result.durationMs}ms)\nContent-Type: ${result.headers['content-type'] ?? 'unknown'}\nBody preview: ${snippet || '(empty)'}`,
        } as RealFinding;
      }),
    );
    for (const r of results) {
      if (r.status === 'fulfilled' && r.value) {
        findings.push(r.value);
        await onLog(`[${ts()}] FOUND: ${r.value.title}`);
      }
    }
  }
  await onLog(`[${ts()}] Path discovery: ${findings.length} exposure(s) found`);
  return findings;
}
