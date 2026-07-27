import { ts } from '../../context';
import { probe } from '../../utils/http';
import type { RealFinding, Target, LogFn } from '../../context';

export async function checkCommandInjection(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing OS command injection (basic)...`);

  const canary = `sentinelx_cmd_${Math.random().toString(36).slice(2, 10)}`;
  const params = ['cmd', 'exec', 'command', 'run', 'shell', 'ping', 'host', 'ip', 'target', 'arg', 'args'];
  const payloads = [
    `; printf ${canary}`,
    `| printf ${canary}`,
    `\`printf ${canary}\``,
    `$(printf ${canary})`,
    `; echo ${canary}`,
    `&& printf ${canary}`,
  ];

  for (const param of params) {
    for (const payload of payloads) {
      const probeUrl = `${target.url.replace(/\/$/, '')}?${param}=${encodeURIComponent(payload)}`;
      const r = await probe(probeUrl, { timeoutMs: 8_000 });
      if (r && r.body.includes(canary)) {
        findings.push({
          title: 'OS Command Injection — Canary String Executed',
          severity: 'critical',
          verification: 'verified',
          confidence: 99,
          cvss: 10.0,
          cve: null,
          description: `Parameter '${param}' executed an injected shell command. Canary output "${canary}" confirmed.`,
          evidence: `PROBE: ${probeUrl}\nPAYLOAD: ${param}=${payload}\nHTTP ${r.status} — canary "${canary}" in response`,
          remediation: 'Never pass user input to shell commands. Use execFile with argument arrays.',
        });
        await onLog(`[${ts()}] ⚠ COMMAND INJECTION CONFIRMED: ${param}`);
        return findings;
      }
    }
  }

  return findings;
}

export async function checkCommandInjectionDeep(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing OS command injection (deep — time + canary file)...`);

  const canary = `sentinelx_deep_${Math.random().toString(36).slice(2, 10)}`;
  const params = ['cmd', 'exec', 'command', 'host', 'ip', 'url', 'source', 'input', 'run'];

  // Time-based detection
  const SLEEP_SEC = 5;
  const sleepPayloads = [`; sleep ${SLEEP_SEC}`, `| sleep ${SLEEP_SEC}`, `\`sleep ${SLEEP_SEC}\``, `$(sleep ${SLEEP_SEC})`];
  for (const param of params.slice(0, 6)) {
    const baseStart = Date.now();
    const bl = await probe(`${target.url}?${param}=sentinelx`, { timeoutMs: 8_000 });
    const baseMs = Date.now() - baseStart;
    if (!bl) continue;
    for (const payload of sleepPayloads) {
      const t0 = Date.now();
      const r = await probe(`${target.url.replace(/\/$/, '')}?${param}=${encodeURIComponent(payload)}`, { timeoutMs: (SLEEP_SEC + 6) * 1000 });
      const elapsed = Date.now() - t0;
      if (r && elapsed > baseMs + 4000 && elapsed >= SLEEP_SEC * 1000 - 500) {
        // Confirm with canary write + read
        const writePayload = `${payload.split(' ')[0]} ${SLEEP_SEC}; printf ${canary} > /tmp/${canary}`;
        const readPayload = `; cat /tmp/${canary}`;
        await probe(`${target.url.replace(/\/$/, '')}?${param}=${encodeURIComponent(writePayload)}`, { timeoutMs: 10_000 });
        const confirmR = await probe(`${target.url.replace(/\/$/, '')}?${param}=${encodeURIComponent(readPayload)}`, { timeoutMs: 8_000 });
        const fileConfirmed = confirmR && confirmR.body.includes(canary);
        findings.push({
          title: `Time-Based OS Command Injection ${fileConfirmed ? '(File-Read Confirmed)' : 'Signal'}`,
          severity: 'critical',
          verification: fileConfirmed ? ('verified' as const) : ('suspected' as const),
          confidence: fileConfirmed ? 98 : 72,
          cvss: 10.0,
          cve: null,
          description: `Parameter '${param}' caused ${elapsed}ms delay (baseline: ${baseMs}ms).${fileConfirmed ? ' Canary file write/read confirmed.' : ''}`,
          evidence: `Baseline: ${baseMs}ms\nPayload: ${payload}\nDelay: ${elapsed}ms\n${fileConfirmed ? 'File read confirmed: canary present' : 'Confirmation inconclusive'}`,
          remediation: 'Never pass user input to shell commands.',
        });
        await onLog(`[${ts()}] ⚠ TIME-BASED CMDI ${fileConfirmed ? 'CONFIRMED' : 'SIGNAL'}: ${param}`);
        return findings;
      }
    }
  }

  return findings;
}
