import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

export async function checkHostHeaderInjection(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing host header injection...`);
  const canary = `attacker-${Math.random().toString(36).slice(2, 10)}.evil.example.com`;
  const payloads = [
    { header: 'Host', value: canary },
    { header: 'Host', value: `${target.hostname}:80@${canary}` },
    { header: 'X-Forwarded-Host', value: canary },
    { header: 'X-Host', value: canary },
    { header: 'X-Forwarded-Server', value: canary },
    { header: 'X-Original-URL', value: `https://${canary}/` },
  ];
  const baseline = await probe(target.url, { timeoutMs: 8_000 });
  for (const { header, value } of payloads) {
    const r = await probe(target.url, { headers: { [header]: value }, timeoutMs: 8_000 });
    if (!r) continue;
    if (r.body.includes(canary) || r.headers['location']?.includes(canary)) {
      findings.push({
        title: `Host Header Injection — Canary Reflected via ${header}`,
        severity: 'high',
        verification: 'verified',
        confidence: 90,
        cvss: 7.5,
        cve: null,
        description: `The attacker-controlled host canary was reflected in the response via the ${header} header.`,
        evidence: `${header}: ${value}\nHTTP ${r.status} — canary '${canary}' in response body or Location header`,
        remediation: 'Validate and sanitise the Host header; use an allowlist.',
      });
      await onLog(`[${ts()}] ⚠ HOST HEADER INJECTION via ${header}`);
      break;
    }
    // Cache poisoning signal: different response from baseline without reflection
    if (baseline && r.status === baseline.status && Math.abs(r.body.length - baseline.body.length) > 200) {
      findings.push({
        title: `Host Header Cache Poisoning Signal (${header})`,
        severity: 'medium',
        verification: 'suspected',
        confidence: 55,
        cvss: 5.3,
        cve: null,
        description: `The ${header} header produced a significantly different response, suggesting cache poisoning potential.`,
        evidence: `${header}: ${value}\nBaseline: ${baseline.body.length} bytes\nProbe: ${r.body.length} bytes`,
        remediation: 'Validate Host header; do not use it in cache key generation without normalisation.',
      });
      break;
    }
  }
  return findings;
}
