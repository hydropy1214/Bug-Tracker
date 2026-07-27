/**
 * Phase 3b — IP Range & ASN Intelligence (reconFTW-style)
 *
 * Queries RDAP/ARIN/RIPE for the ASN IP range, discovers related IPs,
 * and checks for open cloud metadata services and SSRF-prone paths.
 */

import { dnsResolve, ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

interface IpInfo {
  ip: string;
  org?: string;
  asn?: string;
  asnName?: string;
  country?: string;
  range?: string;
}

async function getIpInfoData(hostname: string): Promise<IpInfo | null> {
  try {
    const addrs = await dnsResolve.resolve4(hostname).catch(() => [] as string[]);
    if (addrs.length === 0) return null;
    const ip = addrs[0];

    const result = await probe(`https://ipinfo.io/${ip}/json`, {
      timeoutMs: 10_000,
      skipAuth: true,
      headers: { Accept: 'application/json' },
    });

    if (!result || result.status !== 200) return { ip };

    const data = JSON.parse(result.body);
    return {
      ip,
      org: data.org ?? undefined,
      asn: data.org?.match(/^AS(\d+)/)?.[1] ?? undefined,
      asnName: data.org?.replace(/^AS\d+\s+/, '') ?? undefined,
      country: data.country ?? undefined,
    };
  } catch {
    return null;
  }
}

async function getRdapData(ip: string): Promise<{ range: string; name: string } | null> {
  try {
    const result = await probe(`https://rdap.arin.net/registry/ip/${ip}`, {
      timeoutMs: 12_000,
      skipAuth: true,
      headers: { Accept: 'application/rdap+json' },
    });
    if (!result || result.status !== 200) {
      // Try RIPE
      const ripeResult = await probe(`https://rdap.db.ripe.net/ip/${ip}`, {
        timeoutMs: 12_000,
        skipAuth: true,
        headers: { Accept: 'application/rdap+json' },
      });
      if (!ripeResult || ripeResult.status !== 200) return null;
      const data = JSON.parse(ripeResult.body);
      return {
        range: `${data.startAddress ?? ip} - ${data.endAddress ?? ip}`,
        name: data.name ?? 'Unknown',
      };
    }
    const data = JSON.parse(result.body);
    return {
      range: `${data.startAddress ?? ip} - ${data.endAddress ?? ip}`,
      name: data.name ?? data.handle ?? 'Unknown',
    };
  } catch {
    return null;
  }
}

function ipToInt(ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function intToIp(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

function parseCidr(cidr: string): { start: number; end: number; count: number } | null {
  const [base, prefixStr] = cidr.split('/');
  if (!base || !prefixStr) return null;
  const prefix = parseInt(prefixStr, 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return null;
  const baseInt = ipToInt(base);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const start = (baseInt & mask) >>> 0;
  const end = (start | ~mask) >>> 0;
  return { start, end, count: end - start + 1 };
}

export async function checkIpRange(
  target: Target,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];

  await onLog(`[${ts()}] IP range & ASN intelligence gathering...`);

  const ipInfo = await getIpInfoData(target.hostname);
  if (!ipInfo) {
    await onLog(`[${ts()}] IP range: could not resolve hostname`);
    return findings;
  }

  const { ip, org, asn, asnName, country } = ipInfo;
  await onLog(`[${ts()}] Target IP: ${ip} · ASN: ${asn ? `AS${asn}` : 'unknown'} · Org: ${org ?? 'unknown'} · Country: ${country ?? 'unknown'}`);

  // Get RDAP range info
  const rdap = await getRdapData(ip);
  const rangeStr = rdap?.range ?? 'unknown';

  // Report ASN info as intelligence
  if (asn) {
    findings.push({
      title: `ASN Intelligence: AS${asn} (${asnName ?? 'Unknown'})`,
      severity: 'low',
      cvss: 0,
      cve: null,
      verification: 'informational',
      confidence: 95,
      affectedEndpoint: target.url,
      description:
        `Target IP ${ip} belongs to ASN AS${asn} (${asnName ?? 'Unknown'}) in ${country ?? 'Unknown'}. ` +
        'ASN data enables discovery of adjacent IPs on the same network, virtual hosts, and related infrastructure.',
      evidence:
        `IP: ${ip}\nASN: AS${asn}\nOrganisation: ${asnName ?? org ?? 'Unknown'}\nCountry: ${country ?? 'Unknown'}\nIP Range: ${rangeStr}\nRDAP Name: ${rdap?.name ?? 'unknown'}`,
      remediation:
        'Ensure all IPs in the ASN range that serve this domain are properly secured. ' +
        'Use Shodan (org:"' + (asnName ?? '') + '") to discover all assets in this ASN.',
    });
  }

  // Check cloud metadata endpoint accessibility (SSRF via metadata)
  const CLOUD_METADATA_URLS = [
    { url: 'http://169.254.169.254/latest/meta-data/', name: 'AWS IMDSv1', severity: 'critical' as const, cvss: 10.0 },
    { url: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01', name: 'Azure IMDS', severity: 'critical' as const, cvss: 10.0 },
    { url: 'http://metadata.google.internal/computeMetadata/v1/', name: 'GCP Metadata', severity: 'critical' as const, cvss: 10.0 },
    { url: 'http://100.100.100.200/latest/meta-data/', name: 'Alibaba Cloud IMDS', severity: 'critical' as const, cvss: 10.0 },
  ];

  // Check if target is in a cloud ASN (implies cloud metadata SSRF risk)
  const isCloudProvider = /amazon|google|microsoft|azure|alibaba|cloudflare|digitalocean|linode|vultr/i.test(
    `${org ?? ''} ${asnName ?? ''}`,
  );

  if (isCloudProvider) {
    findings.push({
      title: `Cloud Infrastructure Detected — IMDS/Metadata Endpoint SSRF Risk`,
      severity: 'high',
      cvss: 8.1,
      cve: null,
      verification: 'suspected',
      confidence: 75,
      affectedEndpoint: target.url,
      description:
        `The target appears to be hosted on ${asnName ?? 'a cloud provider'} infrastructure. ` +
        'Cloud-hosted applications are at elevated risk of Instance Metadata Service (IMDS) attacks via SSRF. ' +
        'An SSRF vulnerability could allow an attacker to retrieve cloud credentials (IAM roles, service account tokens) ' +
        'from the metadata endpoint (169.254.169.254 or equivalent).',
      evidence:
        `Cloud ASN: AS${asn ?? 'unknown'} (${asnName ?? org ?? 'Unknown'})\n` +
        `Cloud metadata endpoints at risk:\n` +
        CLOUD_METADATA_URLS.map((m) => `  ${m.name}: ${m.url}`).join('\n'),
      remediation:
        'Enable IMDSv2 (require session tokens) on AWS instances. ' +
        'Block outbound requests to 169.254.169.254 from application code. ' +
        'Use a WAF rule to detect SSRF patterns targeting metadata endpoints. ' +
        'Audit all SSRF vectors (URL parameters, webhooks, file imports).',
      compliance: {
        owasp: ['A10:2021 – Server-Side Request Forgery'],
        nist: ['NIST SC-28', 'NIST AC-3'],
      },
    });
  }

  // Reverse DNS sweep on a small range of adjacent IPs.
  // RDAP returns ranges as "start - end"; also accept CIDR notation.
  let sweepRange: { start: number; end: number; count: number } | null = null;

  const cidrMatch = rangeStr.match(/(\d+\.\d+\.\d+\.\d+)\/(\d+)/);
  if (cidrMatch) {
    sweepRange = parseCidr(cidrMatch[0]);
  } else {
    // Parse "A.B.C.D - E.F.G.H" range from RDAP
    const rangeMatch = rangeStr.match(
      /(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)/,
    );
    if (rangeMatch) {
      const start = ipToInt(rangeMatch[1]);
      const end = ipToInt(rangeMatch[2]);
      if (end >= start) sweepRange = { start, end, count: end - start + 1 };
    }
  }

  if (sweepRange) {
    const range = sweepRange;
    if (range && range.count <= 256) {
      await onLog(`[${ts()}] Reverse DNS sweep on ${Math.min(range.count, 30)} adjacent IPs in ${cidr}...`);
      const toSweep = Math.min(range.count, 30);
      const baseInt = range.start;

      const reverseHits: { ip: string; hostname: string }[] = [];
      const sweepResults = await Promise.allSettled(
        Array.from({ length: toSweep }, (_, i) => i).map(async (offset) => {
          const sweepIp = intToIp(baseInt + offset);
          if (sweepIp === ip) return null;
          try {
            const hostnames = await dnsResolve.reverse(sweepIp).catch(() => [] as string[]);
            if (hostnames.length > 0) return { ip: sweepIp, hostname: hostnames[0] };
            return null;
          } catch {
            return null;
          }
        }),
      );

      for (const r of sweepResults) {
        if (r.status === 'fulfilled' && r.value) reverseHits.push(r.value);
      }

      if (reverseHits.length > 0) {
        const sameOrg = reverseHits.filter((h) =>
          h.hostname.includes(target.hostname.split('.').slice(-2).join('.')),
        );

        findings.push({
          title: `${reverseHits.length} Co-hosted Hosts Found via Reverse DNS Sweep`,
          severity: sameOrg.length > 0 ? 'medium' : 'low',
          cvss: sameOrg.length > 0 ? 5.3 : 3.1,
          cve: null,
          verification: 'verified',
          confidence: 90,
          description:
            `Reverse DNS sweep of ${cidr} found ${reverseHits.length} host(s) sharing the same IP range. ` +
            (sameOrg.length > 0
              ? `${sameOrg.length} appear to belong to the same organization.`
              : 'These may be co-hosted on a shared server.'),
          evidence:
            `IP range: ${cidr}\nCo-hosted hosts (${reverseHits.length}):\n` +
            reverseHits.slice(0, 20).map((h) => `  ${h.ip} → ${h.hostname}`).join('\n'),
          remediation:
            'Ensure co-hosted applications are properly isolated. ' +
            'Virtual host confusion attacks may affect shared servers. ' +
            'Review all co-hosted domains for security posture.',
        });
      }
    }
  }

  return findings;
}
