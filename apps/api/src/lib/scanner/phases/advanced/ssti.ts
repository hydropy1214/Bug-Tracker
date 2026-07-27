import { activeProbesAllowed, isContextualReflection, ts } from '../../context';
import { probe } from '../../utils/http';
import type { RealFinding, Target, LogFn } from '../../context';

export async function checkSSTI(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing SSTI with canary + dual-math hardening...`);

  const canary = `ssti_${Math.random().toString(36).slice(2, 10)}`;
  // Dual-math: both payloads must produce the expected numeric result
  const mathProbes = [
    { template: '{{7*7}}', expected: '49', engine: 'Jinja2/Twig', rce: '{{__import__("os").popen("id").read()}}' },
    { template: '${7*7}', expected: '49', engine: 'FreeMarker/Thymeleaf', rce: '${T(java.lang.Runtime).getRuntime().exec("id")}' },
    { template: '#{7*7}', expected: '49', engine: 'Jinja2 (alt)', rce: '#{class.forName("java.lang.Runtime").getRuntime().exec("id")}' },
    { template: '<%= 7*7 %>', expected: '49', engine: 'ERB/EJS', rce: '<%= `id` %>' },
    { template: '*{7*7}', expected: '49', engine: 'Thymeleaf', rce: '*{T(java.lang.Runtime).getRuntime().exec("id")}' },
  ];
  const canaryTemplate2 = `{{${canary}}}`;

  const params = ['template', 'q', 'search', 'name', 'text', 'message', 'subject', 'content', 'input', 'body', 'page'];

  for (const param of params.slice(0, 8)) {
    for (const { template, expected, engine, rce } of mathProbes) {
      if (!activeProbesAllowed()) break;
      const probeUrl = `${target.url.replace(/\/$/, '')}?${param}=${encodeURIComponent(template)}`;
      const r = await probe(probeUrl, { timeoutMs: 8_000 });
      if (!r) continue;
      const reflected = isContextualReflection(r.body, expected);
      const rawPresent = r.body.includes(expected) && !r.body.includes(template);
      if (reflected && rawPresent) {
        // Canary probe to reduce false positives
        const canaryUrl = `${target.url.replace(/\/$/, '')}?${param}=${encodeURIComponent(canaryTemplate2)}`;
        const canaryR = await probe(canaryUrl, { timeoutMs: 8_000 });
        const canaryTriggered = canaryR && !canaryR.body.includes(canaryTemplate2) && !canaryR.body.toLowerCase().includes('error');
        // Second math: 7*7 = 49, check 7*8 = 56 to confirm evaluation
        const verify = `${template.replace('7*7', '7*8')}`;
        const verifyUrl = `${target.url.replace(/\/$/, '')}?${param}=${encodeURIComponent(verify)}`;
        const verifyR = await probe(verifyUrl, { timeoutMs: 8_000 });
        const dualMath = verifyR && verifyR.body.includes('56') && !verifyR.body.includes(verify);
        const confidence = dualMath ? 94 : canaryTriggered ? 78 : 60;
        const verification = dualMath ? ('verified' as const) : ('suspected' as const);
        findings.push({
          title: `Server-Side Template Injection (SSTI) — ${engine}`,
          severity: 'critical',
          verification,
          confidence,
          cvss: 10.0,
          cve: null,
          description: `Parameter '${param}' evaluates template expressions (${template} → ${expected}).${dualMath ? ' Confirmed with dual-math.' : ''}`,
          evidence: `PROBE: ${probeUrl}\nPayload: ${template}\nExpected: ${expected}\nDual-math confirmed: ${dualMath}\nRCE payload: ${rce}`,
          remediation: 'Do not render user input through template engines. Use sandboxed engines or escape user data.',
        });
        await onLog(`[${ts()}] ⚠ SSTI ${verification.toUpperCase()} (${engine}): ${param}`);
        return findings;
      }
    }
  }

  // POST body SSTI
  for (const { template, expected, engine } of mathProbes.slice(0, 3)) {
    const r = await probe(target.url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ message: template, subject: template, body: template }), timeoutMs: 8_000 });
    if (r && r.body.includes(expected) && !r.body.includes(template)) {
      findings.push({
        title: `Server-Side Template Injection (SSTI via POST) — ${engine}`,
        severity: 'critical',
        verification: 'suspected',
        confidence: 70,
        cvss: 10.0,
        cve: null,
        description: `POST body field evaluates template expression (${template} → ${expected}).`,
        evidence: `POST ${target.url}\nBody: {"message": "${template}"}\nHTTP ${r.status} — result: ${expected} in response`,
        remediation: 'Never render user-supplied content through a template engine.',
      });
      await onLog(`[${ts()}] ⚠ SSTI VIA POST BODY (${engine})`);
      break;
    }
  }

  return findings;
}
