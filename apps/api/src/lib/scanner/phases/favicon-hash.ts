/**
 * Phase 9b — Favicon Hash Fingerprinting (Shodan / reconFTW-style)
 *
 * Fetches the target's favicon, computes a MurmurHash3 (Shodan-compatible),
 * and matches against a database of known application fingerprints.
 * This technique is used by Shodan and reconFTW to identify apps hidden behind CDNs.
 */

import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

// MurmurHash3 (32-bit) — Shodan uses this for favicon fingerprinting
function murmurHash3(data: Buffer): number {
  let h1 = 0;
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;
  const len = data.length;
  let i = 0;

  while (i + 4 <= len) {
    let k1 =
      (data[i] & 0xff) |
      ((data[i + 1] & 0xff) << 8) |
      ((data[i + 2] & 0xff) << 16) |
      ((data[i + 3] & 0xff) << 24);

    k1 = Math.imul(k1, c1) >>> 0;
    k1 = ((k1 << 15) | (k1 >>> 17)) >>> 0;
    k1 = Math.imul(k1, c2) >>> 0;

    h1 ^= k1;
    h1 = ((h1 << 13) | (h1 >>> 19)) >>> 0;
    h1 = (Math.imul(h1, 5) + 0xe6546b64) >>> 0;
    i += 4;
  }

  let k1 = 0;
  const tail = len & 3;
  if (tail >= 3) k1 ^= (data[i + 2] & 0xff) << 16;
  if (tail >= 2) k1 ^= (data[i + 1] & 0xff) << 8;
  if (tail >= 1) {
    k1 ^= data[i] & 0xff;
    k1 = Math.imul(k1, c1) >>> 0;
    k1 = ((k1 << 15) | (k1 >>> 17)) >>> 0;
    k1 = Math.imul(k1, c2) >>> 0;
    h1 ^= k1;
  }

  h1 ^= len;
  h1 ^= h1 >>> 16;
  h1 = Math.imul(h1, 0x85ebca6b) >>> 0;
  h1 ^= h1 >>> 13;
  h1 = Math.imul(h1, 0xc2b2ae35) >>> 0;
  h1 ^= h1 >>> 16;
  return h1 | 0; // Convert to signed 32-bit
}

// Known favicon hashes (Shodan-compatible) → application fingerprint
const KNOWN_FAVICONS: Record<number, { name: string; severity: RealFinding['severity']; cvss: number; note: string }> = {
  [-247388890]: { name: 'Jenkins', severity: 'high', cvss: 7.5, note: 'Jenkins CI/CD — check for unauthenticated access and script console.' },
  [116323821]: { name: 'Kibana', severity: 'medium', cvss: 5.3, note: 'Elasticsearch Kibana — ensure authentication is enabled.' },
  [-1326906043]: { name: 'Grafana', severity: 'medium', cvss: 5.3, note: 'Grafana dashboard — check default credentials (admin/admin).' },
  [1278313330]: { name: 'GitLab', severity: 'medium', cvss: 5.3, note: 'GitLab CE/EE — check for unauthenticated access, version CVEs.' },
  [-1856287685]: { name: 'phpMyAdmin', severity: 'high', cvss: 8.1, note: 'phpMyAdmin — restrict to internal IPs.' },
  [1585186354]: { name: 'Adminer', severity: 'critical', cvss: 9.8, note: 'Adminer database manager — should not be publicly accessible.' },
  [-2137199778]: { name: 'Spring Boot (Actuator)', severity: 'high', cvss: 7.5, note: 'Spring Boot app — probe /actuator/env for credential exposure.' },
  [708578099]: { name: 'Jira', severity: 'medium', cvss: 5.3, note: 'Atlassian Jira — check for anonymous browsing and CVEs.' },
  [-978521182]: { name: 'Confluence', severity: 'medium', cvss: 5.3, note: 'Atlassian Confluence — check for anonymous access.' },
  [-1616143106]: { name: 'Jupyter Notebook', severity: 'critical', cvss: 9.8, note: 'Jupyter Notebook — often unauthenticated, full code execution.' },
  [1609871732]: { name: 'Rancher', severity: 'high', cvss: 8.1, note: 'Rancher Kubernetes management — check auth requirements.' },
  [-476231906]: { name: 'Portainer', severity: 'high', cvss: 8.1, note: 'Portainer Docker manager — check for default credentials.' },
  [1061502220]: { name: 'Netdata', severity: 'medium', cvss: 5.3, note: 'Netdata monitoring — typically unauthenticated, exposes system metrics.' },
  [999357577]: { name: 'Prometheus', severity: 'medium', cvss: 5.3, note: 'Prometheus metrics — check for unauthenticated access to /metrics.' },
  [-1701369204]: { name: 'HashiCorp Vault', severity: 'high', cvss: 7.5, note: 'HashiCorp Vault — verify authentication is properly configured.' },
  [1584713865]: { name: 'Sonarqube', severity: 'medium', cvss: 6.5, note: 'SonarQube — may expose code and security issues.' },
  [2141724739]: { name: 'Nexus Repository', severity: 'medium', cvss: 6.5, note: 'Sonatype Nexus — check for default credentials and anonymous access.' },
  [-1322906143]: { name: 'RabbitMQ Management', severity: 'high', cvss: 8.1, note: 'RabbitMQ Management UI — check default credentials (guest/guest).' },
  [-2046927042]: { name: 'Elasticsearch', severity: 'critical', cvss: 9.8, note: 'Elasticsearch — unauthenticated access exposes all indexed data.' },
};

const FAVICON_PATHS = [
  '/favicon.ico',
  '/favicon.png',
  '/apple-touch-icon.png',
  '/assets/favicon.ico',
  '/static/favicon.ico',
  '/public/favicon.ico',
  '/img/favicon.ico',
  '/images/favicon.ico',
];

export async function checkFaviconHash(
  target: Target,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const baseUrl = target.url.replace(/\/$/, '');

  await onLog(`[${ts()}] Favicon hash fingerprinting (Shodan-compatible MurmurHash3)...`);

  let faviconUrl: string | null = null;
  let faviconData: Buffer | null = null;

  // Try to find favicon from HTML first
  const homePage = await probe(`${baseUrl}/`, { timeoutMs: 8_000 });
  if (homePage) {
    const linkMatch = homePage.body.match(/<link[^>]+rel=["'](?:shortcut )?icon["'][^>]+href=["']([^"']+)["']/i)
      ?? homePage.body.match(/<link[^>]+href=["']([^"']+)["'][^>]+rel=["'](?:shortcut )?icon["']/i);
    if (linkMatch?.[1]) {
      const href = linkMatch[1];
      faviconUrl = href.startsWith('http') ? href : `${baseUrl}${href.startsWith('/') ? '' : '/'}${href}`;
    }
  }

  // Probe common favicon paths
  const pathsToTry = faviconUrl ? [faviconUrl, ...FAVICON_PATHS] : FAVICON_PATHS;

  for (const path of pathsToTry) {
    const url = path.startsWith('http') ? path : `${baseUrl}${path}`;
    const result = await probe(url, { timeoutMs: 8_000 });
    if (!result || result.status !== 200) continue;
    if (result.body.length < 10) continue;
    // Check it looks like image data (not HTML)
    if (result.body.startsWith('<!') || result.body.startsWith('<html')) continue;

    faviconData = Buffer.from(result.body, 'binary');
    faviconUrl = url;
    break;
  }

  if (!faviconData || !faviconUrl) {
    await onLog(`[${ts()}] No favicon found`);
    return findings;
  }

  // Compute Shodan-compatible MurmurHash3
  // Shodan uses base64-encoded favicon for the hash
  const b64 = faviconData.toString('base64');
  // Shodan splits base64 into 76-char lines + \n
  const formatted = b64.match(/.{1,76}/g)?.join('\n') ?? b64;
  const hashInput = Buffer.from(formatted + '\n', 'utf8');
  const hash = murmurHash3(hashInput);

  await onLog(`[${ts()}] Favicon hash: ${hash} (Shodan: favicon.hash:${hash})`);

  // Always emit the hash as informational
  findings.push({
    title: `Favicon Fingerprint: hash ${hash}`,
    severity: 'low',
    cvss: 0,
    cve: null,
    verification: 'informational',
    confidence: 95,
    affectedEndpoint: faviconUrl,
    description:
      `Favicon MurmurHash3: ${hash}. ` +
      'This hash can be used to find all servers running the same application via Shodan (favicon.hash query). ' +
      'It enables passive infrastructure discovery and technology fingerprinting.',
    evidence: `Favicon URL: ${faviconUrl}\nMurmurHash3 (Shodan-compatible): ${hash}\nShodan query: favicon.hash:${hash}\nBase64 length: ${b64.length} chars`,
    remediation:
      'Use a custom favicon to prevent technology fingerprinting via hash. ' +
      'Consider using a unique favicon that does not reveal the application stack.',
  });

  // Match against known vulnerable applications
  const knownApp = KNOWN_FAVICONS[hash];
  if (knownApp) {
    findings.push({
      title: `${knownApp.name} Identified via Favicon Hash`,
      severity: knownApp.severity,
      cvss: knownApp.cvss,
      cve: null,
      verified: true,
      verification: 'verified',
      confidence: 97,
      affectedEndpoint: faviconUrl,
      description:
        `The favicon hash ${hash} matches the known fingerprint for ${knownApp.name}. ` +
        knownApp.note,
      evidence: `Favicon URL: ${faviconUrl}\nHash: ${hash}\nMatched application: ${knownApp.name}`,
      remediation:
        `Secure the ${knownApp.name} instance: ${knownApp.note} ` +
        'Replace the default favicon. Review the instance for default credentials and known CVEs.',
    });
    await onLog(`[${ts()}] ⚠ Favicon hash matched: ${knownApp.name}`);
  }

  return findings;
}
