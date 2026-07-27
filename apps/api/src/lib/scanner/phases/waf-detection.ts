/**
 * Phase 1 — WAF/CDN Detection & Bypass Testing
 *
 * Identifies WAF/CDN products from response signatures and optionally tests
 * bypass techniques (IP spoofing headers, Googlebot UA, encoding tricks,
 * direct origin IP access).
 */
import { digQuery, isWafChallengeDetected, ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

const WAF_SIGNATURES: Record<string, { headers: string[]; body: string[]; cookies: string[] }> = {
  Cloudflare: { headers: ['cf-ray','cf-cache-status','cf-worker','cf-request-id'], body: ['cloudflare','attention required! | cloudflare'], cookies: ['__cfduid','cf_clearance'] },
  'AWS WAF': { headers: ['x-amzn-requestid','x-amz-cf-id','x-amz-apigw-id'], body: [], cookies: [] },
  Akamai: { headers: ['akamai-origin-hop','x-akamai-transformed'], body: ['reference #18.'], cookies: ['ak_bmsc'] },
  Sucuri: { headers: ['x-sucuri-id','x-sucuri-cache'], body: ['sucuri website firewall'], cookies: [] },
  'Imperva/Incapsula': { headers: ['x-iinfo','x-cdn'], body: ['incapsula incident id'], cookies: ['incap_ses','visid_incap'] },
  'F5 BIG-IP ASM': { headers: ['x-cnection','x-wa-info'], body: ['the requested url was rejected'], cookies: ['TS','bigipserver'] },
  Barracuda: { headers: [], body: ['barracuda networks'], cookies: ['barra_counter_session'] },
  ModSecurity: { headers: ['x-mod-security-message'], body: ['mod_security','not acceptable'], cookies: [] },
  Fastly: { headers: ['x-fastly-request-id','fastly-debug-digest'], body: [], cookies: [] },
  Varnish: { headers: ['x-varnish'], body: [], cookies: [] },
};

export async function checkWafAndBypass(
  target: Target,
  onLog: LogFn,
  allowBypass = false,
): Promise<{ findings: RealFinding[]; wafName: string | null }> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Detecting WAF/CDN${allowBypass ? ' and testing bypass techniques' : ' passively'}...`);
  const r = await probe(target.url, { timeoutMs: 12_000 });
  if (!r) return { findings, wafName: null };
  if (isWafChallengeDetected()) {
    await onLog(`[${ts()}] WAF challenge response received; bypass probes skipped.`);
    return { findings, wafName: 'Cloudflare' };
  }

  let detectedWaf: string | null = null;
  const allHeaders = JSON.stringify(r.headers).toLowerCase();
  const allCookies = (r.headers['set-cookie'] ?? '').toLowerCase();
  const bodyLower = r.body.toLowerCase();
  for (const [waf, sigs] of Object.entries(WAF_SIGNATURES)) {
    const headerMatch = sigs.headers.some((h) => allHeaders.includes(h.toLowerCase()));
    const bodyMatch = sigs.body.some((b) => bodyLower.includes(b.toLowerCase()));
    const cookieMatch = sigs.cookies.some((c) => allCookies.includes(c.toLowerCase()));
    if (headerMatch || bodyMatch || cookieMatch) { detectedWaf = waf; break; }
  }

  if (detectedWaf) {
    await onLog(`[${ts()}] WAF/CDN detected: ${detectedWaf}`);
    findings.push({ title: `WAF/CDN Detected: ${detectedWaf}`, severity: 'low', verification: 'informational', confidence: 92, cvss: 0, cve: null, description: `A Web Application Firewall (${detectedWaf}) is in front of this target.`, evidence: `WAF: ${detectedWaf}`, remediation: 'Keep the underlying application patched.' });

    if (!allowBypass) {
      await onLog(`[${ts()}] Passive WAF detection complete — bypass and origin discovery disabled.`);
      return { findings, wafName: detectedWaf };
    }

    // IP-spoofing bypass
    await onLog(`[${ts()}] Testing WAF bypass via IP-spoofing headers...`);
    const bypassHeaderSets: Record<string, string>[] = [
      { 'X-Forwarded-For': '127.0.0.1' },
      { 'X-Real-IP': '127.0.0.1' },
      { 'X-Originating-IP': '127.0.0.1' },
      { 'X-Client-IP': '127.0.0.1' },
      { 'True-Client-IP': '127.0.0.1' },
      { 'CF-Connecting-IP': '127.0.0.1' },
    ];
    for (const hdrs of bypassHeaderSets) {
      const bypassR = await probe(target.url, { headers: hdrs, timeoutMs: 10_000 });
      if (bypassR && Math.abs(bypassR.body.length - r.body.length) > 300) {
        const hdrKey = Object.keys(hdrs)[0]!;
        findings.push({ title: `WAF Bypass Signal: IP Header Spoofing (${hdrKey})`, severity: 'high', verification: 'suspected', confidence: 72, cvss: 7.5, cve: null, description: `Adding ${hdrKey}: ${Object.values(hdrs)[0]} produced a significantly different response.`, evidence: `Baseline: ${r.body.length} bytes\nWith ${hdrKey}: ${bypassR.body.length} bytes`, remediation: 'Only trust IP override headers from verified internal proxy IP ranges.' });
        await onLog(`[${ts()}] ⚠ WAF BYPASS SIGNAL: ${hdrKey}`);
        break;
      }
    }

    // Googlebot UA bypass
    const botR = await probe(target.url, { headers: { 'User-Agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)' }, timeoutMs: 10_000 });
    if (botR && Math.abs(botR.body.length - r.body.length) > 500) {
      findings.push({ title: 'WAF Bypass Signal: Googlebot User-Agent Treated Differently', severity: 'medium', verification: 'suspected', confidence: 60, cvss: 5.3, cve: null, description: 'Server returns different response for Googlebot.', evidence: `Normal: ${r.body.length} bytes\nGooglebot: ${botR.body.length} bytes`, remediation: 'Do not apply different security rules based on User-Agent.' });
      await onLog(`[${ts()}] ⚠ WAF BYPASS SIGNAL: Googlebot UA`);
    }

    // Direct origin IP access
    await onLog(`[${ts()}] Checking for direct origin IP exposure...`);
    try {
      const ips = await digQuery(target.hostname, 'A');
      for (const ip of ips.slice(0, 2)) {
        const originR = await probe(`http://${ip}/`, { headers: { Host: target.hostname }, timeoutMs: 8_000, followRedirects: false });
        if (originR && originR.status >= 200 && originR.status < 400) {
          const originHeaders = JSON.stringify(originR.headers).toLowerCase();
          const hasWafHeader = WAF_SIGNATURES[detectedWaf]?.headers.some((h) => originHeaders.includes(h)) ?? false;
          if (!hasWafHeader) {
            findings.push({ title: `Origin IP Bypasses ${detectedWaf} WAF — Direct Access Confirmed (${ip})`, severity: 'critical', verification: 'verified', confidence: 92, cvss: 9.8, cve: null, description: `The origin server at ${ip} responds directly over HTTP without passing through ${detectedWaf}.`, evidence: `WAF-protected host: ${target.hostname}\nDirect IP: ${ip}\nHTTP GET http://${ip}/ → HTTP ${originR.status} without WAF headers`, remediation: `Firewall the origin to accept connections only from ${detectedWaf}'s IP ranges.` });
            await onLog(`[${ts()}] ⚠ ORIGIN IP EXPOSED: ${ip} reachable without ${detectedWaf}`);
          }
        }
      }
    } catch {}

    // Encoding bypass test
    const pathR = await probe(`${target.url.replace(/\/$/, '')}/..%2f`, { timeoutMs: 6_000 });
    const dotR = await probe(`${target.url.replace(/\/$/, '')}/.%2e/`, { timeoutMs: 6_000 });
    if ((pathR && pathR.status === 200) || (dotR && dotR.status === 200)) {
      findings.push({ title: 'WAF Path Normalisation Bypass (URL-Encoded Traversal)', severity: 'medium', verification: 'suspected', confidence: 60, cvss: 5.3, cve: null, description: 'URL-encoded path segments returned 200, suggesting WAF does not normalise paths.', evidence: `GET ${target.url}..%2f → HTTP ${pathR?.status}\nGET ${target.url}.%2e/ → HTTP ${dotR?.status}`, remediation: 'Configure WAF to normalise URLs.' });
    }
  } else {
    await onLog(`[${ts()}] No WAF/CDN signature detected — unprotected origin`);
  }

  return { findings, wafName: detectedWaf };
}
