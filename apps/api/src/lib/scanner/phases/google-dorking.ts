/**
 * Phase 11c — Google Dorking (reconFTW-style)
 *
 * Generates Google dork queries for manual use AND actively probes the
 * target for the sensitive files/paths those dorks would find. This gives
 * both an OSINT lead-gen artifact and direct HTTP confirmation.
 */

import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

interface Dork {
  query: string;
  description: string;
  severity: RealFinding['severity'];
  cvss: number;
  paths?: string[]; // Optional: directly probe these paths
  contentPattern?: RegExp;
}

function buildDorks(hostname: string): Dork[] {
  const h = hostname;
  return [
    // Sensitive file exposure
    {
      query: `site:${h} ext:env OR ext:env.local OR ext:env.production`,
      description: 'Environment files (.env) indexed by search engines',
      severity: 'critical', cvss: 9.8,
      paths: ['/.env', '/.env.local', '/.env.production', '/.env.staging', '/.env.backup'],
      contentPattern: /[A-Z_]{3,}=.{1,}/,
    },
    {
      query: `site:${h} ext:sql OR ext:sql.gz OR ext:bak`,
      description: 'Database backup/dump files publicly accessible',
      severity: 'critical', cvss: 9.8,
      paths: ['/backup.sql', '/dump.sql', '/database.sql', '/db.sql', '/backup.sql.gz',
               '/db_backup.sql', '/site.sql', '/wordpress.sql', '/data.sql'],
    },
    {
      query: `site:${h} ext:log filetype:log`,
      description: 'Log files indexed that may contain credentials or stack traces',
      severity: 'high', cvss: 7.5,
      paths: ['/error.log', '/access.log', '/debug.log', '/application.log',
               '/storage/logs/laravel.log', '/logs/error.log', '/app.log'],
      contentPattern: /(error|exception|password|token|secret|key)/i,
    },
    {
      query: `site:${h} inurl:wp-content/uploads filetype:pdf OR filetype:xlsx OR filetype:docx`,
      description: 'Sensitive documents in WordPress uploads',
      severity: 'medium', cvss: 5.3,
      paths: ['/wp-content/uploads/'],
    },
    {
      query: `site:${h} inurl:"/phpinfo.php"`,
      description: 'PHP info page exposes server configuration',
      severity: 'high', cvss: 7.5,
      paths: ['/phpinfo.php', '/info.php', '/php_info.php', '/test.php'],
      contentPattern: /(phpinfo\(\)|PHP Version|Configuration File)/i,
    },
    {
      query: `site:${h} intitle:"index of" inurl:backup`,
      description: 'Open directory listing for backup folders',
      severity: 'high', cvss: 7.5,
      paths: ['/backup/', '/backups/', '/bak/', '/old/', '/archive/'],
      contentPattern: /index of \//i,
    },
    {
      query: `site:${h} inurl:admin OR inurl:administrator OR inurl:wp-admin`,
      description: 'Admin panels indexed by search engines',
      severity: 'medium', cvss: 5.3,
      paths: ['/admin/', '/administrator/', '/wp-admin/', '/admin/login', '/admin/dashboard'],
    },
    {
      query: `site:${h} inurl:".git" OR inurl:".svn" OR inurl:".hg"`,
      description: 'Version control metadata exposed',
      severity: 'critical', cvss: 9.8,
      paths: ['/.git/HEAD', '/.git/config', '/.svn/wc.db', '/.hg/store'],
      contentPattern: /(ref: refs\/|repositoryformatversion)/i,
    },
    {
      query: `site:${h} filetype:yaml OR filetype:yml inurl:config`,
      description: 'YAML configuration files potentially exposing secrets',
      severity: 'high', cvss: 7.5,
      paths: ['/config.yml', '/config.yaml', '/.travis.yml', '/docker-compose.yml',
               '/k8s/config.yml', '/kubernetes.yml', '/app.yml'],
      contentPattern: /(password:|secret:|token:|api_key:|private_key:)/i,
    },
    {
      query: `site:${h} "API_KEY" OR "api_key" OR "SECRET_KEY" OR "password" filetype:txt`,
      description: 'Exposed credentials or API keys in text files',
      severity: 'critical', cvss: 9.8,
      paths: ['/credentials.txt', '/config.txt', '/secrets.txt', '/keys.txt', '/passwords.txt'],
      contentPattern: /(api.?key|secret|password|token)\s*[:=]/i,
    },
    // Infrastructure/stack exposure
    {
      query: `site:${h} inurl:swagger OR inurl:api-docs OR inurl:openapi`,
      description: 'API documentation exposed (Swagger/OpenAPI)',
      severity: 'medium', cvss: 5.3,
      paths: ['/swagger-ui/', '/swagger-ui.html', '/api-docs', '/openapi.json', '/api/swagger'],
    },
    {
      query: `site:${h} inurl:actuator OR inurl:health OR inurl:metrics`,
      description: 'Spring Boot / management actuator endpoints exposed',
      severity: 'high', cvss: 7.5,
      paths: ['/actuator', '/actuator/health', '/actuator/env', '/actuator/beans',
               '/health', '/metrics', '/info', '/env'],
    },
    {
      query: `site:${h} intitle:"Kibana" OR intitle:"Elasticsearch" OR intitle:"Grafana"`,
      description: 'Monitoring dashboards publicly accessible',
      severity: 'high', cvss: 8.1,
      paths: [':5601', ':9200', ':9200/_cat/indices', ':3000/login'],
    },
    // Credentials and tokens
    {
      query: `site:${h} "begin rsa private key" OR "begin openssh private key"`,
      description: 'SSH/RSA private keys indexed by Google',
      severity: 'critical', cvss: 10.0,
      paths: ['/id_rsa', '/.ssh/id_rsa', '/private.key', '/server.key'],
      contentPattern: /-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----/i,
    },
  ];
}

export async function checkGoogleDorking(
  target: Target,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const dorks = buildDorks(target.hostname);

  await onLog(`[${ts()}] Google dorking: generating ${dorks.length} dork queries + active path probing...`);

  // Emit the dork queries as an informational finding (for manual use)
  const dorkList = dorks.map((d) => `  "${d.query}"\n    → ${d.description}`).join('\n');
  findings.push({
    title: `Google Dork Intelligence (${dorks.length} queries)`,
    severity: 'low',
    cvss: 0,
    cve: null,
    verification: 'informational',
    confidence: 99,
    description:
      'Google dork queries have been generated for this target. Run these manually to discover indexed sensitive content. ' +
      'Active probing has been performed on the most common associated paths.',
    evidence: `Dork queries for ${target.hostname}:\n${dorkList}`,
    remediation:
      'Search Google with these queries to find any publicly-indexed sensitive content. ' +
      'Submit removal requests via Google Search Console and block access at the web server level.',
  });

  // Actively probe paths from dorks that have path hints
  const probedPaths = new Set<string>();
  const baseUrl = target.url.replace(/\/$/, '');

  // Baseline 404
  const notFoundUrl = `${baseUrl}/sentinelx-dork-probe-${Date.now()}`;
  const baseline = await probe(notFoundUrl, { timeoutMs: 8_000 });

  for (const dork of dorks) {
    if (!dork.paths) continue;
    for (const path of dork.paths) {
      if (probedPaths.has(path)) continue;
      probedPaths.add(path);

      // Skip if it looks like a host:port (external service, skip)
      if (path.startsWith(':')) continue;

      const url = `${baseUrl}${path}`;
      const result = await probe(url, { timeoutMs: 8_000 });
      if (!result || result.status === 404 || result.status === 410) continue;
      if (result.status !== 200 && result.status !== 403) continue;

      // Check baseline similarity
      if (baseline && result.status === 200) {
        const bodyLen = result.body.length;
        const baseLen = baseline.body.length;
        if (Math.abs(bodyLen - baseLen) < 50) continue; // Same as 404 page
      }

      // Content match
      if (dork.contentPattern && !dork.contentPattern.test(result.body)) {
        if (result.status === 200) {
          // Low confidence match — still report but informational
          findings.push({
            title: `Dork Path Accessible: ${path}`,
            severity: 'low',
            cvss: 3.1,
            cve: null,
            verification: 'informational',
            confidence: 55,
            affectedEndpoint: url,
            description: `Path found via Google dork pattern is accessible (HTTP ${result.status}). Content did not match expected pattern.`,
            evidence: `URL: ${url}\nHTTP: ${result.status}\nContent snippet: ${result.body.slice(0, 300)}`,
            remediation: 'Investigate whether this path should be publicly accessible.',
          });
        }
        continue;
      }

      findings.push({
        title: `[Dork Confirmed] ${dork.description}: ${path}`,
        severity: dork.severity,
        cvss: dork.cvss,
        cve: null,
        verified: true,
        verification: 'verified',
        confidence: 90,
        affectedEndpoint: url,
        description:
          `Active probing confirmed the dork-targeted path "${path}" is accessible. ` +
          dork.description,
        evidence:
          `Dork: ${dork.query}\nURL: ${url}\nHTTP: ${result.status}\n` +
          `Content:\n${result.body.slice(0, 500)}`,
        remediation:
          dork.severity === 'critical'
            ? 'Immediately remove or block this path. Rotate any exposed credentials.'
            : 'Restrict access to this path. Review whether it should be publicly accessible.',
      });
      await onLog(`[${ts()}] Dork hit: ${path} (${result.status}) — ${dork.description}`);
    }
  }

  return findings;
}
