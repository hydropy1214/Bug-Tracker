/**
 * Virtual Host Discovery
 *
 * Sends requests with manipulated Host headers to discover:
 *   1. Hidden vhosts serving different content
 *   2. Internal admin vhosts
 *   3. Development/staging environments on same IP
 *   4. Host header injection (cache poisoning, SSRF)
 *   5. Internal service routing via Host header
 */

import { ts, execFileAsync, dnsResolve } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, LogFn, Target } from '../context';

// Common vhost prefixes to enumerate
const VHOST_PREFIXES = [
  'admin', 'internal', 'dev', 'development', 'staging', 'stage', 'test',
  'uat', 'qa', 'beta', 'alpha', 'demo', 'preview', 'preprod', 'pre-prod',
  'api', 'api2', 'v2', 'v3', 'backend', 'backoffice', 'private',
  'intranet', 'corp', 'corporate', 'dashboard', 'portal', 'console',
  'management', 'manager', 'staff', 'employee', 'ops', 'operations',
  'monitor', 'monitoring', 'kibana', 'grafana', 'jenkins', 'git',
  'gitlab', 'jira', 'confluence', 'wiki', 'docs', 'support',
  'static', 'cdn', 'media', 'assets', 'upload', 'mail', 'smtp',
  'vpn', 'proxy', 'gateway', 'auth', 'sso', 'oauth', 'login',
  'shop', 'store', 'pay', 'payment', 'billing', 'account',
  'old', 'legacy', 'archive', 'backup', 'mirror',
  'ftp', 'sftp', 'ssh', 'remote', 'rdp', 'citrix',
  'db', 'database', 'mysql', 'postgres', 'redis', 'elastic',
  'phpmyadmin', 'adminer', 'pgadmin',
  'localhost', '127.0.0.1', '0.0.0.0',
];

// Host header injection payloads for cache poisoning / SSRF
const HOST_INJECTION_PAYLOADS = [
  'attacker.sentinelx.invalid',
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '169.254.169.254',        // AWS IMDS
  '169.254.170.2',          // ECS metadata
  'metadata.google.internal', // GCP metadata
  '192.168.1.1',
  '10.0.0.1',
  '172.16.0.1',
];

function responseDiffers(
  base: { status: number; body: string },
  test: { status: number; body: string },
): boolean {
  if (base.status !== test.status) return true;
  // If content differs significantly
  const baseTrimmed = base.body.slice(0, 2000).replace(/\s+/g, ' ').trim();
  const testTrimmed = test.body.slice(0, 2000).replace(/\s+/g, ' ').trim();
  if (baseTrimmed === testTrimmed) return false;

  const baseWords = new Set(baseTrimmed.toLowerCase().split(/\W+/).filter((w) => w.length > 4));
  const testWords = new Set(testTrimmed.toLowerCase().split(/\W+/).filter((w) => w.length > 4));
  let overlap = 0;
  for (const w of testWords) if (baseWords.has(w)) overlap++;
  const similarity = overlap / Math.max(baseWords.size, 1);
  return similarity < 0.75;
}

export async function discoverVhosts(
  target: Target,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const parts = target.hostname.split('.');
  const rootDomain = parts.length >= 2 ? parts.slice(-2).join('.') : target.hostname;
  const protocol = target.isHttps ? 'https' : 'http';
  const port = target.port !== 80 && target.port !== 443 ? `:${target.port}` : '';

  await onLog(`[${ts()}] [VHost] Resolving IP for ${target.hostname}...`);

  // Get the target's IP for direct connection
  let targetIp: string | null = null;
  try {
    const addrs = await dnsResolve.resolve4(target.hostname);
    targetIp = addrs[0] ?? null;
  } catch {}

  if (!targetIp) {
    await onLog(`[${ts()}] [VHost] Cannot resolve IP — skipping vhost discovery`);
    return findings;
  }

  await onLog(`[${ts()}] [VHost] IP: ${targetIp} — probing ${VHOST_PREFIXES.length} virtual host(s)...`);

  // Get baseline response for the real hostname
  const baselineResponse = await probe(`${protocol}://${target.hostname}${port}/`, {
    headers: { Host: target.hostname },
    timeoutMs: 8_000,
  });
  if (!baselineResponse) return findings;

  const baselineFingerprint = {
    status: baselineResponse.status,
    body: baselineResponse.body,
  };

  // Probe each vhost prefix in parallel batches of 20
  const BATCH = 20;
  const foundVhosts: Array<{ vhost: string; status: number; evidence: string }> = [];

  for (let i = 0; i < VHOST_PREFIXES.length; i += BATCH) {
    const batch = VHOST_PREFIXES.slice(i, i + BATCH);
    const results = await Promise.allSettled(
      batch.map(async (prefix) => {
        const vhost = `${prefix}.${rootDomain}`;
        const r = await probe(`${protocol}://${targetIp}${port}/`, {
          headers: {
            Host: vhost,
            'X-Original-Host': vhost,
          },
          timeoutMs: 6_000,
        });
        if (!r) return null;
        if (!responseDiffers(baselineFingerprint, { status: r.status, body: r.body })) return null;
        // Skip obvious 404/400 responses
        if (r.status === 404 && r.body.length < 500) return null;
        if (r.status === 400) return null;

        return {
          vhost,
          status: r.status,
          evidence: `Host: ${vhost} → HTTP ${r.status} (${r.body.length} bytes)\nPreview: ${r.body.slice(0, 150).replace(/\s+/g, ' ')}`,
        };
      }),
    );

    for (const r of results) {
      if (r.status === 'fulfilled' && r.value) {
        foundVhosts.push(r.value);
        await onLog(`[${ts()}] [VHost] Found: ${r.value.vhost} (HTTP ${r.value.status})`);
      }
    }
  }

  if (foundVhosts.length > 0) {
    const sensitive = foundVhosts.filter((v) =>
      /admin|internal|dev|staging|backend|private|intranet|corp|management/i.test(v.vhost),
    );

    findings.push({
      title: `Virtual Host Discovery — ${foundVhosts.length} Hidden Host(s) Found`,
      severity: sensitive.length > 0 ? 'high' : 'medium',
      verified: true,
      verification: 'verified',
      confidence: 88,
      evidenceQuality: 'strong',
      verificationMethod: 'Host header manipulation returned content materially different from baseline — distinct vhost confirmed.',
      reproducibility: 'reproducible',
      affectedEndpoint: `${protocol}://${targetIp}${port}/`,
      cvss: sensitive.length > 0 ? 7.5 : 5.3,
      cve: null,
      description: `${foundVhosts.length} hidden virtual host(s) were discovered on the same IP address as ${target.hostname}. ${sensitive.length > 0 ? `${sensitive.length} of these appear to be internal/admin hosts that may have weaker authentication.` : ''} These vhosts may host unprotected admin panels, development versions, or internal services.`,
      evidence: foundVhosts
        .slice(0, 10)
        .map((v) => v.evidence)
        .join('\n\n'),
      remediation: 'Ensure all virtual hosts behind the same IP have appropriate authentication and are not publicly accessible unless intended. Use network-level access controls for internal vhosts. Remove development/staging vhosts from production infrastructure.',
      compliance: { owasp: ['A01', 'A05'], pci: ['6.2.4'], nist: ['CM-7', 'AC-3'] },
    });
  }

  // ── Host header injection for cache poisoning ─────────────────────────────
  const injectionResults = await Promise.allSettled(
    HOST_INJECTION_PAYLOADS.slice(0, 5).map(async (injHost) => {
      const r = await probe(`${protocol}://${target.hostname}${port}/`, {
        headers: { 'X-Forwarded-Host': injHost, 'X-Host': injHost },
        timeoutMs: 6_000,
      });
      if (!r) return null;
      // Check if the injected host appears in response (cache poisoning indicator)
      if (r.body.toLowerCase().includes(injHost.toLowerCase())) {
        return { host: injHost, body: r.body.slice(0, 400) };
      }
      return null;
    }),
  );

  for (const r of injectionResults) {
    if (r.status === 'fulfilled' && r.value) {
      const { host, body } = r.value;
      findings.push({
        title: `Host Header Injection — "${host}" Reflected in Response`,
        severity: 'high',
        verified: true,
        verification: 'verified',
        confidence: 90,
        evidenceQuality: 'strong',
        verificationMethod: `X-Forwarded-Host: ${host} was reflected in the HTTP response body.`,
        reproducibility: 'reproducible',
        affectedEndpoint: `${protocol}://${target.hostname}${port}/`,
        affectedParameter: 'X-Forwarded-Host',
        cvss: 8.1,
        cve: null,
        description: `The application reflects the X-Forwarded-Host header in its response. This enables web cache poisoning attacks where an attacker poisons shared caches to deliver malicious content to legitimate users, or SSRF where the server makes requests to attacker-controlled hosts.`,
        evidence: `X-Forwarded-Host: ${host}\nReflected in response:\n${body}`,
        remediation: 'Do not use X-Forwarded-Host or Host header values in generated URLs without strict validation against an allowlist. Configure web servers and proxies to strip untrusted forwarding headers from external requests.',
        compliance: { owasp: ['A03', 'A05'], pci: ['6.2.4'], nist: ['SI-10', 'SC-8'] },
      });
      await onLog(`[${ts()}] [VHost] Host injection reflected: ${host}`);
      break;
    }
  }

  await onLog(`[${ts()}] [VHost] Complete — ${findings.length} finding(s)`);
  return findings;
}
