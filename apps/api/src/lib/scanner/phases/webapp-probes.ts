import { activeProbesAllowed, isContextualReflection, ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

const SQLI_PATTERNS = [
  /you have an error in your sql syntax/i,
  /warning.*mysql.*query/i,
  /supplied argument is not a valid mysql/i,
  /pg_query\(\): query failed/i,
  /unterminated quoted string at or near/i,
  /pgsql:.*error/i,
  /unclosed quotation mark after the character string/i,
  /odbc.*sql server.*error/i,
  /ora-\d{5}/i,
  /quoted string not properly terminated/i,
  /microsoft.*ole db.*provider.*error/i,
  /80040e14/i,
  /sqlite3\.operationalerror/i,
  /sqlexception.*syntax error/i,
  /invalid sql statement/i,
  /syntax error.*near/i,
  /sql command not properly ended/i,
  /division by zero/i,
];

export async function checkWebApp(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing SQL injection (error-based and blind)...`);
  const sqliParams = ['id','search','q','query','page','cat','user','item','product','order','filter','sort','name'];
  const sqliPayloads = ["'", '1 OR 1=1--', "1' OR '1'='1", "1'--", '1 AND 1=2--', "' OR 'x'='x"];
  const sqliBaseline = await probe(target.url, { timeoutMs: 8_000 });
  let sqliFound = false;

  for (const param of sqliParams.slice(0, 8)) {
    if (sqliFound) break;
    for (const payload of sqliPayloads.slice(0, 6)) {
      if (sqliFound) break;
      const probeUrl = `${target.url.replace(/\/$/, '')}?${param}=${encodeURIComponent(payload)}`;
      const r = await probe(probeUrl, { timeoutMs: 8_000 });
      if (!r) continue;
      const matched = SQLI_PATTERNS.find((p) => p.test(r.body));
      const baselineHasSameError = sqliBaseline ? SQLI_PATTERNS.some((p) => p.test(sqliBaseline.body)) : false;
      const responseChanged = !sqliBaseline || r.status !== sqliBaseline.status || Math.abs(r.body.length - sqliBaseline.body.length) > 50;
      if (matched && responseChanged && !baselineHasSameError) {
        findings.push({ title: 'SQL Injection — Database Error Leaked', severity: 'high', verification: 'suspected', confidence: 72, cvss: 7.5, cve: null, description: `Parameter '${param}' produced a database error absent from baseline.`, evidence: `BASELINE: ${target.url} → HTTP ${sqliBaseline?.status}\nPROBE: ${probeUrl} → HTTP ${r.status}\nPattern: ${matched}\nBody excerpt: ${r.body.slice(0, 400)}`, remediation: 'Use parameterised queries.' });
        sqliFound = true;
        break;
      }
    }
  }

  if (!sqliFound) {
    await onLog(`[${ts()}] Testing time-based blind SQL injection...`);
    const sleepSec = 5;
    const confirmSec = 3;
    const blindPayloads = [
      { payload: `1' AND SLEEP(${sleepSec})--`, db: 'MySQL', confirmPayload: `1' AND SLEEP(${confirmSec})--` },
      { payload: `1; WAITFOR DELAY '0:0:${sleepSec}'--`, db: 'MSSQL', confirmPayload: `1; WAITFOR DELAY '0:0:${confirmSec}'--` },
      { payload: `1' AND pg_sleep(${sleepSec})--`, db: 'PostgreSQL', confirmPayload: `1' AND pg_sleep(${confirmSec})--` },
    ];
    for (const param of sqliParams.slice(0, 4)) {
      if (sqliFound) break;
      const baselineStart = Date.now();
      const bl = await probe(`${target.url.replace(/\/$/, '')}?${param}=1`, { timeoutMs: 8_000 });
      const baselineMs = Date.now() - baselineStart;
      if (!bl) continue;
      for (const { payload, db, confirmPayload } of blindPayloads) {
        const t0 = Date.now();
        const r = await probe(`${target.url.replace(/\/$/, '')}?${param}=${encodeURIComponent(payload)}`, { timeoutMs: (sleepSec + 6) * 1000 });
        const elapsed = Date.now() - t0;
        if (r && elapsed > baselineMs + 4000 && elapsed >= sleepSec * 1000 - 500) {
          const t1 = Date.now();
          const confirmR = await probe(`${target.url.replace(/\/$/, '')}?${param}=${encodeURIComponent(confirmPayload)}`, { timeoutMs: (confirmSec + 6) * 1000 });
          const confirmMs = Date.now() - t1;
          const confirmed = confirmR !== null && confirmMs > baselineMs + 2500;
          findings.push({ title: `Time-Based Blind SQL Injection — ${db} ${confirmed ? 'Confirmed' : 'Signal'}`, severity: 'high', verification: confirmed ? 'verified' : 'suspected', confidence: confirmed ? 88 : 65, cvss: 8.1, cve: null, description: `Parameter '${param}' caused ${elapsed}ms delay (baseline: ${baselineMs}ms).${confirmed ? ' Confirmed with second payload.' : ''}`, evidence: `Baseline: ${baselineMs}ms\nPrimary: ${elapsed}ms\n${confirmed ? `Confirm: ${confirmMs}ms` : ''}`, remediation: 'Use parameterised queries.' });
          sqliFound = true;
          await onLog(`[${ts()}] ⚠ TIME-BASED BLIND SQLI ${confirmed ? 'CONFIRMED' : 'SIGNAL'}: ${db}`);
          break;
        }
      }
    }
  }

  if (!sqliFound) {
    await onLog(`[${ts()}] Testing boolean-based blind SQL injection...`);
    for (const param of sqliParams.slice(0, 5)) {
      if (sqliFound) break;
      const baseR = await probe(`${target.url}?${param}=1`, { timeoutMs: 8_000 });
      const trueR = await probe(`${target.url}?${param}=${encodeURIComponent('1 AND 1=1--')}`, { timeoutMs: 8_000 });
      const falseR = await probe(`${target.url}?${param}=${encodeURIComponent('1 AND 1=2--')}`, { timeoutMs: 8_000 });
      if (!baseR || !trueR || !falseR) continue;
      const pctDiff = trueR.body.length > 0 ? Math.abs(trueR.body.length - falseR.body.length) / trueR.body.length : 0;
      const statusDiff = trueR.status !== falseR.status;
      if ((pctDiff > 0.2 || statusDiff) && Math.abs(trueR.body.length - baseR.body.length) < 50) {
        findings.push({ title: 'Blind SQL Injection (Boolean-Based) — Response Differs', severity: 'high', verification: 'suspected', confidence: 72, cvss: 7.5, cve: null, description: `Parameter '${param}' shows significant difference between true/false conditions.`, evidence: `True: ${trueR.body.length} bytes, False: ${falseR.body.length} bytes, Diff: ${Math.round(pctDiff * 100)}%`, remediation: 'Use parameterised queries.' });
        sqliFound = true;
        await onLog(`[${ts()}] ⚠ BOOLEAN BLIND SQLI SIGNAL`);
      }
    }
  }

  if (!sqliFound) {
    await onLog(`[${ts()}] Testing SQLi in JSON body/cookies/headers...`);
    const r = await probe(target.url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: "' OR '1'='1", username: "' OR '1'='1" }), timeoutMs: 8_000 });
    if (r && SQLI_PATTERNS.some((p) => p.test(r.body))) {
      findings.push({ title: 'SQL Injection via JSON Request Body', severity: 'high', verification: 'suspected', confidence: 70, cvss: 7.5, cve: null, description: 'SQL error after JSON body injection.', evidence: `POST ${target.url}\nBody excerpt: ${r.body.slice(0, 300)}`, remediation: 'Use parameterised queries for all inputs.' });
      sqliFound = true;
    }
  }

  // XSS
  await onLog(`[${ts()}] Testing XSS reflection...`);
  const xssToken = Math.random().toString(36).slice(2, 10);
  const xssPayload = `<script>xss${xssToken}</script>`;
  const xssParams = ['q','search','name','msg','message','text','content','input','title','value','data','error','callback','return','next','redirect'];
  let xssFound = false;
  for (const param of xssParams.slice(0, 10)) {
    if (xssFound) break;
    for (const payload of [xssPayload, `"><img src=x onerror=alert(${xssToken})>`]) {
      const probeUrl = `${target.url.replace(/\/$/, '')}?${param}=${encodeURIComponent(payload)}`;
      const r = await probe(probeUrl, { timeoutMs: 8_000 });
      if (!r || !activeProbesAllowed()) break;
      const reflected = isContextualReflection(r.body, payload) || isContextualReflection(r.body, `xss${xssToken}`);
      if (reflected && /<script\b[^>]*>xss[a-z0-9]+<\/script>/i.test(r.body)) {
        findings.push({ title: 'Reflected XSS — Script/Event Payload Returned Unescaped', severity: 'high', verification: 'suspected', confidence: 78, cvss: 7.4, cve: null, description: `Parameter '${param}' reflects user-supplied HTML/JS without encoding.`, evidence: `PROBE: ${probeUrl}\nPAYLOAD: ${param}=${payload}\nContent-Type: ${r.headers['content-type']}\nHTTP ${r.status}: payload reflected`, remediation: 'HTML-encode all user-controlled output.' });
        xssFound = true;
        await onLog(`[${ts()}] ⚠ REFLECTED XSS SIGNAL`);
        break;
      }
    }
  }

  // NoSQL
  await onLog(`[${ts()}] Testing NoSQL injection...`);
  const nosqlBaseline = await probe(target.url, { timeoutMs: 8_000 });
  const nosqlPayloads = [
    { body: '{"username":{"$gt":""},"password":{"$gt":""}}', ct: 'application/json' },
    { body: 'username[$gt]=&password[$gt]=', ct: 'application/x-www-form-urlencoded' },
  ];
  for (const ep of [`${target.url}api/login`, `${target.url}login`, `${target.url}auth`]) {
    for (const { body, ct } of nosqlPayloads) {
      const r = await probe(ep, { method: 'POST', headers: { 'Content-Type': ct }, body, timeoutMs: 8_000 });
      if (!r) continue;
      const blStatus = nosqlBaseline?.status ?? 0;
      const bodyLower = r.body.toLowerCase();
      const successSignals = ['welcome','dashboard','logged in','token','access_token','session','"user":','"id":','"role":'];
      const isSuccess = successSignals.some((s) => bodyLower.includes(s));
      if (r.status === 200 && isSuccess && (blStatus !== 200 || Math.abs(r.body.length - (nosqlBaseline?.body.length ?? 0)) > 100)) {
        findings.push({ title: 'NoSQL Injection — MongoDB Operator Authentication Bypass', severity: 'critical', verification: 'suspected', confidence: 75, cvss: 9.8, cve: null, description: `MongoDB operator injection produced success response at ${ep}.`, evidence: `POST ${ep}\nBody: ${body}\nHTTP ${r.status} — success signals in response\nResponse: ${r.body.slice(0, 300)}`, remediation: 'Sanitise input — strip $ operators.' });
        await onLog(`[${ts()}] ⚠ NOSQL INJECTION SIGNAL`);
        break;
      }
    }
  }

  // Command injection
  await onLog(`[${ts()}] Testing command injection...`);
  const cmdCanary = `sentinelx-cmd-${Math.random().toString(36).slice(2, 10)}`;
  const cmdPayloads = [`; printf ${cmdCanary}`, `| printf ${cmdCanary}`, `\`printf ${cmdCanary}\``, `$(printf ${cmdCanary})`];
  const cmdParams = ['cmd','exec','command','run','shell','ping','host','ip','target','file','path','name','url'];
  for (const param of cmdParams.slice(0, 6)) {
    for (const payload of cmdPayloads.slice(0, 3)) {
      const probeUrl = `${target.url.replace(/\/$/, '')}?${param}=${encodeURIComponent(payload)}`;
      const r = await probe(probeUrl, { timeoutMs: 8_000 });
      if (r && r.body.includes(cmdCanary)) {
        findings.push({ title: 'OS Command Injection — Canary Executed', severity: 'critical', verification: 'verified', confidence: 98, cvss: 10.0, cve: null, description: `The application executed a shell command via '${param}' parameter. Canary '${cmdCanary}' returned.`, evidence: `PROBE: ${probeUrl}\nPAYLOAD: ${param}=${payload}\nHTTP ${r.status} — canary found in response`, remediation: 'Never pass user input to shell execution functions.' });
        await onLog(`[${ts()}] ⚠ COMMAND INJECTION CONFIRMED`);
        break;
      }
    }
  }

  // Open redirect
  await onLog(`[${ts()}] Testing open redirect...`);
  const redirectMarker = 'redirect-test-sentinel-x';
  for (const probeUrl of [target.url + `?redirect=https://${redirectMarker}.example.com`, target.url + `?next=https://${redirectMarker}.example.com`, target.url + `?url=https://${redirectMarker}.example.com`]) {
    const r = await probe(probeUrl, { followRedirects: false, timeoutMs: 8_000 });
    if (r && [301, 302, 303, 307, 308].includes(r.status)) {
      const loc = r.headers['location'] ?? '';
      if (loc.includes(redirectMarker)) {
        findings.push({ title: 'Open Redirect Vulnerability', severity: 'medium', cvss: 6.1, cve: null, description: 'The application redirects to attacker-controlled URLs.', evidence: `Probe URL: ${probeUrl}\nHTTP ${r.status} Location: ${loc}`, remediation: 'Validate redirect destinations against allowlist.' });
        break;
      }
    }
  }

  // HTTP methods enumeration
  await onLog(`[${ts()}] Enumerating HTTP methods...`);
  const optR = await probe(target.url, { method: 'OPTIONS', timeoutMs: 6_000 });
  if (optR) {
    const allow = optR.headers['allow'] ?? optR.headers['public'] ?? '';
    const dangerous = ['PUT', 'DELETE', 'TRACE', 'CONNECT'].filter((m) => allow.toUpperCase().includes(m));
    if (dangerous.length > 0) {
      findings.push({ title: `Dangerous HTTP Methods Advertised: ${dangerous.join(', ')}`, severity: 'medium', cvss: 5.3, cve: null, description: `OPTIONS response lists dangerous methods.`, evidence: `OPTIONS ${target.url} → HTTP ${optR.status}\nAllow: ${allow}`, remediation: 'Restrict to GET, POST, HEAD.' });
    }
  }

  // Error page disclosure
  await onLog(`[${ts()}] Checking error page disclosure...`);
  const errorR = await probe(target.url + '__nonexistent__sentinelx', { timeoutMs: 6_000 });
  if (errorR) {
    const body = errorR.body.toLowerCase();
    if (body.match(/traceback|stack trace|exception in|at \w+\.\w+\(|file ".*\.py"/i)) {
      findings.push({ title: 'Stack Trace Disclosed in Error Response', severity: 'high', cvss: 7.5, cve: null, description: 'The application returns detailed stack traces.', evidence: `GET ${target.url}__nonexistent__sentinelx → HTTP ${errorR.status}\nStack trace detected`, remediation: 'Disable debug mode in production.' });
    }
  }

  // Directory listing
  for (const dirPath of ['/images/','/uploads/','/static/','/assets/','/files/','/backup/','/css/','/js/']) {
    const dirUrl = target.url.replace(/\/$/, '') + dirPath;
    const r = await probe(dirUrl, { timeoutMs: 6_000 });
    if (r && r.status === 200 && (r.body.includes('Index of ') || r.body.includes('Directory listing'))) {
      findings.push({ title: `Directory Listing Enabled (${dirPath})`, severity: 'medium', cvss: 5.3, cve: null, description: `Directory listing enabled for ${dirPath}.`, evidence: `GET ${dirUrl} → HTTP ${r.status}`, remediation: 'Disable directory listing.' });
      break;
    }
  }

  await onLog(`[${ts()}] Web app probes complete — ${findings.length} finding(s)`);
  return findings;
}
