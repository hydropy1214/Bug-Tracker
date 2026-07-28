/**
 * Scan orchestrator — wires all phase modules together into scanTarget().
 *
 * Pipeline design (4 parallel rounds):
 *   Round 1  — WAF/CDN detection (solo; sets shared WAF context before any active probe)
 *   Round 2  — All passive recon + OSINT in parallel (DNS, ports, TLS, subdomains, Wayback, dorking…)
 *   Round 3  — All active web probes + attack-surface crawl in parallel
 *   Round 4  — All deep-attack phases in parallel (uses surface from R3, techs from R2)
 *   Round 5  — Weaponised verification (only when policy.allowVerification)
 */

import {
  normalizeTarget,
  scanContext,
  ts,
  runActiveChecks,
  isWafChallengeDetected,
  suppressWafSensitiveFindings,
  downgradeWafChallengeFindings,
  getCapturedSession,
  remainingScanRequests,
  type ScanType,
  type LogFn,
  type ScanPolicy,
  type ScanResult,
  type RealFinding,
} from './context';

import { applyComplianceMapping } from './phases/compliance';
import { checkWafAndBypass } from './phases/waf-detection';
import { checkDns } from './phases/dns';
import { getIpInfo } from './phases/ip-info';
import { checkWhois } from './phases/whois';
import { discoverSubdomains, checkSubdomainTakeover } from './phases/subdomains';
import { checkSubdomainPermutations } from './phases/subdomain-permutations';
import { checkPorts } from './phases/ports';
import { checkTls } from './phases/tls';
import { checkHeaders } from './phases/headers';
import { fingerprint, type TechProfile } from './phases/tech-fingerprint';
import { checkFaviconHash } from './phases/favicon-hash';
import { checkSensitivePaths } from './phases/sensitive-paths';
import { checkWayback } from './phases/wayback';
import { checkGoogleDorking } from './phases/google-dorking';
import { checkGitHubDorking } from './phases/github-dorking';
import { checkCloudBuckets } from './phases/cloud-buckets';
import { harvestEmails } from './phases/email-harvesting';
import { checkLeakDetection } from './phases/leak-detection';
import { checkWebApp } from './phases/webapp-probes';
import { checkApiSurface } from './phases/api-surface';
import { discoverAttackSurface } from './phases/surface-discovery';
import { runDeepInputTesting } from './phases/deep-input-testing';
import { discoverParameters } from './phases/parameter-discovery';
import { checkHostHeaderInjection } from './phases/host-header';
import { checkCrlfInjection } from './phases/crlf';
import { checkPathTraversal } from './phases/path-traversal';
import { checkJwtWeaknesses } from './phases/jwt';
import { checkIdorAndBola } from './phases/idor';
import { checkHttpRequestSmuggling } from './phases/request-smuggling';
import { checkLog4ShellSurface } from './phases/log4shell';
import { checkRateLimiting } from './phases/rate-limiting';
import { checkOpenRedirect } from './phases/open-redirect';
import { checkIpRange } from './phases/ip-range';
import {
  checkOpenRegistration,
  checkDefaultCredentials,
  checkSqliAuthBypass,
  checkIdorWithCapturedSession,
} from './phases/verification/active';

// ── New high-power phases ─────────────────────────────────────────────────────
import { runNucleiScan } from './phases/nuclei';
import { checkJsSecrets } from './phases/js-secrets';
import { checkCorsMisconfiguration } from './phases/cors-bypass';
import { checkGraphQLDeep } from './phases/graphql-deep';
import { checkSqliAdvanced } from './phases/sqli-advanced';
import { checkPrototypePollution } from './phases/prototype-pollution';
import { checkOAuthMisconfig } from './phases/oauth-misconfig';
import { discoverVhosts } from './phases/vhost-discovery';
import { runFfufDiscovery } from './phases/ffuf-discovery';

// ─── helpers ─────────────────────────────────────────────────────────────────

/** Run a phase, swallow errors, and return `fallback` on failure. */
async function safeRun<T>(label: string, fn: () => Promise<T>, fallback: T, onLog: LogFn): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    await onLog(`[${ts()}] [WARNING] ${label} error (skipped): ${msg}`);
    return fallback;
  }
}

/** Like safeRun but wraps with runActiveChecks (skipped when WAF blocks). */
async function activeRun<T>(label: string, fn: () => Promise<T>, fallback: T, onLog: LogFn): Promise<T> {
  return safeRun(label, () => runActiveChecks(fn, fallback), fallback, onLog);
}

/** Resolve a settled Promise.allSettled result to its value or the fallback. */
function settled<T>(result: PromiseSettledResult<T>, fallback: T): T {
  return result.status === 'fulfilled' ? result.value : fallback;
}

// ─── entry point ─────────────────────────────────────────────────────────────

export async function scanTarget(
  value: string,
  assetType: string,
  scanType: ScanType,
  onLog: LogFn,
  policy: ScanPolicy,
  authHeaders?: Record<string, string>,
): Promise<ScanResult> {
  const target = normalizeTarget(value, assetType);
  if (!target) {
    await onLog(`[${ts()}] ERROR: Cannot normalise target "${value}" — skipping`);
    return { findings: [], wafBlocked: false };
  }

  if (policy.originOverride) {
    const origHost = target.hostname;
    target.hostname = policy.originOverride;
    target.url = target.url.replace(`://${origHost}`, `://${policy.originOverride}`);
    await onLog(
      `[${ts()}] Origin override active — all requests routed to ${policy.originOverride} with Host: ${origHost}`,
    );
  }

  return scanContext.run(
    {
      remaining: policy.requestBudget,
      verificationRemaining: policy.verificationRequestBudget,
      exhaustedNotified: false,
      authHeaders,
      wafChallengeDetected: false,
      wafChallengeLogEmitted: false,
      activeProbeDepth: 0,
      onWafChallenge: () =>
        onLog(
          `[${ts()}] WAF challenge page detected — active probes suspended; only passive/informational checks running.`,
        ),
    },
    async () => {
      const all: RealFinding[] = [];
      const add = (f: RealFinding[]) => { all.push(...f); };

      await onLog(`[${ts()}] ═══════════════════════════════════════`);
      await onLog(`[${ts()}] TARGET  : ${target.url}`);
      await onLog(`[${ts()}] HOST    : ${target.hostname}`);
      await onLog(`[${ts()}] SCAN    : FULL DEEP SCAN / PROFILE ${policy.profile.toUpperCase()}`);
      await onLog(
        `[${ts()}] POLICY  : ${policy.requestBudget} req budget · ${policy.timeoutMs}ms timeout · concurrency ${policy.maxConcurrency}`,
      );
      await onLog(
        `[${ts()}] TOOLS   : nmap · dig · whois · openssl · fetch · crt.sh · ipinfo.io · Wayback · GitHub · S3/GCS/Azure · psbdmp`,
      );
      await onLog(
        authHeaders && Object.keys(authHeaders).length > 0
          ? `[${ts()}] AUTH    : Authenticated scanning enabled (${Object.keys(authHeaders).join(', ')})`
          : `[${ts()}] AUTH    : Unauthenticated scan`,
      );
      await onLog(`[${ts()}] PIPELINE: 5-round parallel pipeline (nuclei · ffuf · subfinder · sqli-time · GraphQL · PP · OAuth · vhost · JS-secrets)`);
      await onLog(`[${ts()}] ═══════════════════════════════════════`);

      // ════════════════════════════════════════════════════════════════════════
      // ROUND 1 — WAF / CDN detection
      //   Must complete before any active probe so the WAF context flag is set.
      // ════════════════════════════════════════════════════════════════════════
      await onLog(`[${ts()}] [Round 1] WAF/CDN detection and bypass testing...`);
      const r1Start = Date.now();
      const { findings: wafFindings } = await runActiveChecks(
        () => checkWafAndBypass(target, onLog),
        { findings: [], wafName: null },
      );
      add(wafFindings);
      await onLog(`[${ts()}] [Round 1] Complete (${Date.now() - r1Start}ms)`);

      // ════════════════════════════════════════════════════════════════════════
      // ROUND 2 — Passive recon + OSINT (all in parallel)
      //   None of these depend on each other. Subdomains are chained internally
      //   (discovery → takeover → permutations) but the chain runs as one task.
      // ════════════════════════════════════════════════════════════════════════
      await onLog(`[${ts()}] [Round 2] Launching parallel recon + OSINT (13 tasks)...`);
      await onLog(`[${ts()}] [Phase 2]  DNS enumeration`);
      await onLog(`[${ts()}] [Phase 3]  IP geolocation & ASN intelligence`);
      await onLog(`[${ts()}] [Phase 3b] IP range & reverse DNS`);
      if (assetType !== 'ip') await onLog(`[${ts()}] [Phase 4]  WHOIS domain intelligence`);
      if (assetType !== 'ip') await onLog(`[${ts()}] [Phase 5]  Subdomain discovery + takeover + permutations`);
      await onLog(`[${ts()}] [Phase 6]  Full port scan (nmap)`);
      if (target.isHttps) await onLog(`[${ts()}] [Phase 7]  TLS/SSL analysis`);
      await onLog(`[${ts()}] [Phase 8]  HTTP security headers`);
      await onLog(`[${ts()}] [Phase 9]  Technology fingerprinting + favicon hash`);
      await onLog(`[${ts()}] [Phase 11] Wayback Machine`);
      await onLog(`[${ts()}] [Phase 11c] Google dorking`);
      await onLog(`[${ts()}] [Phase 11d] GitHub dorking`);
      await onLog(`[${ts()}] [Phase 11e] Cloud bucket enumeration`);
      await onLog(`[${ts()}] [Phase 11f] Email harvesting & SPF/DMARC`);
      await onLog(`[${ts()}] [Phase 11g] Leak detection`);
      await onLog(`[${ts()}] [Phase N1]  Nuclei — CVE/misconfig/exposure/default-login/panel`);
      await onLog(`[${ts()}] [Phase N2]  JavaScript secret extraction & endpoint discovery`);

      const r2Start = Date.now();
      const [
        r2Dns,
        r2IpInfo,
        r2IpRange,
        r2Whois,
        r2Subs,
        r2Ports,
        r2Tls,
        r2Headers,
        r2Fingerprint,
        r2Favicon,
        r2Wayback,
        r2GoogleDork,
        r2GithubDork,
        r2CloudBuckets,
        r2Emails,
        r2Leaks,
        r2Nuclei,
        r2JsSecrets,
      ] = await Promise.allSettled([
        // Phase 2: DNS
        safeRun('Phase 2 (DNS)', () => checkDns(target.hostname, onLog), [], onLog),

        // Phase 3: IP geolocation
        safeRun('Phase 3 (IP info)', () => getIpInfo(target.hostname, onLog).then(() => [] as RealFinding[]), [], onLog),

        // Phase 3b: IP range
        safeRun('Phase 3b (IP range)', () => checkIpRange(target, onLog), [], onLog),

        // Phase 4: WHOIS (skipped for raw IPs)
        assetType !== 'ip'
          ? safeRun('Phase 4 (WHOIS)', () => checkWhois(target.hostname, onLog), [], onLog)
          : Promise.resolve([] as RealFinding[]),

        // Phase 5: Subdomains → takeover → permutations (chained, single task)
        assetType !== 'ip'
          ? safeRun(
              'Phase 5 (Subdomains)',
              async () => {
                const subResult = await discoverSubdomains(target.hostname, onLog);
                let discoveredSubs = subResult.subs;
                const findings: RealFinding[] = [...subResult.findings];

                await onLog(`[${ts()}] [Phase 5b] Subdomain takeover detection (${discoveredSubs.length} subs)...`);
                findings.push(...(await runActiveChecks(() => checkSubdomainTakeover(discoveredSubs, onLog), [])));

                await onLog(`[${ts()}] [Phase 5c] Subdomain permutation sweep...`);
                const permResult = await safeRun(
                  'Phase 5c (Subdomain permutations)',
                  () => checkSubdomainPermutations(target.hostname, discoveredSubs, onLog),
                  { subs: [] as string[], findings: [] as RealFinding[] },
                  onLog,
                );
                findings.push(...permResult.findings);
                if (permResult.subs.length > 0) {
                  discoveredSubs = [...discoveredSubs, ...permResult.subs];
                  await onLog(`[${ts()}] Permutation sweep added ${permResult.subs.length} new subdomain(s). Total: ${discoveredSubs.length}`);
                }
                return { findings, subs: discoveredSubs };
              },
              { findings: [] as RealFinding[], subs: [] as string[] },
              onLog,
            )
          : Promise.resolve({ findings: [] as RealFinding[], subs: [] as string[] }),

        // Phase 6: Ports
        activeRun('Phase 6 (Ports)', () => checkPorts(target.hostname, 'full', onLog), [], onLog),

        // Phase 7: TLS
        target.isHttps
          ? safeRun('Phase 7 (TLS)', () => checkTls(target.hostname, target.port, onLog), [], onLog)
          : Promise.resolve([] as RealFinding[]),

        // Phase 8: HTTP headers
        safeRun('Phase 8 (Headers)', () => checkHeaders(target, onLog), [], onLog),

        // Phase 9: Fingerprint
        safeRun(
          'Phase 9 (Fingerprint)',
          () => fingerprint(target, onLog),
          { techs: [] as TechProfile[], findings: [] as RealFinding[] },
          onLog,
        ),

        // Phase 9b: Favicon hash
        safeRun('Phase 9b (Favicon)', () => checkFaviconHash(target, onLog), [], onLog),

        // Phase 11: Wayback
        safeRun('Phase 11 (Wayback)', () => checkWayback(target.hostname, onLog), [], onLog),

        // Phase 11c: Google dorking
        safeRun('Phase 11c (Google dorking)', () => checkGoogleDorking(target, onLog), [], onLog),

        // Phase 11d: GitHub dorking
        safeRun('Phase 11d (GitHub dorking)', () => checkGitHubDorking(target, onLog), [], onLog),

        // Phase 11e: Cloud buckets
        safeRun('Phase 11e (Cloud buckets)', () => checkCloudBuckets(target, onLog), [], onLog),

        // Phase 11f: Email harvesting
        safeRun('Phase 11f (Email harvesting)', () => harvestEmails(target, onLog), [], onLog),

        // Phase 11g: Leak detection
        safeRun('Phase 11g (Leak detection)', () => checkLeakDetection(target, onLog), [], onLog),
      ]);

      // Collect Round 2 results
      add(settled(r2Dns, []));
      add(settled(r2IpInfo, []));
      add(settled(r2IpRange, []));
      add(settled(r2Whois, []));
      const subsResult = settled(r2Subs, { findings: [] as RealFinding[], subs: [] as string[] });
      add(subsResult.findings);
      add(settled(r2Ports, []));
      add(settled(r2Tls, []));
      add(settled(r2Headers, []));
      const fpResult = settled(r2Fingerprint, { techs: [] as TechProfile[], findings: [] as RealFinding[] });
      add(fpResult.findings);
      if (fpResult.techs.length > 0)
        await onLog(`[${ts()}] Stack detected: ${fpResult.techs.map((t) => `${t.name} (${t.category})`).join(' · ')}`);
      add(settled(r2Favicon, []));
      add(settled(r2Wayback, []));
      add(settled(r2GoogleDork, []));
      add(settled(r2GithubDork, []));
      add(settled(r2CloudBuckets, []));
      add(settled(r2Emails, []));
      add(settled(r2Leaks, []));

      await onLog(`[${ts()}] [Round 2] Complete (${Date.now() - r2Start}ms) — ${subsResult.subs.length} subdomains in scope`);

      // ════════════════════════════════════════════════════════════════════════
      // ROUND 3 — Active web probes + attack surface crawl (all in parallel)
      //   attack surface discovery (`surface`) must complete here because
      //   deep-input testing (Round 4) depends on it.
      // ════════════════════════════════════════════════════════════════════════
      await onLog(`[${ts()}] [Round 3] Launching parallel active probes + surface crawl (9 tasks)...`);
      await onLog(`[${ts()}] [Phase 10]  Sensitive path discovery`);
      await onLog(`[${ts()}] [Phase 11b] Crawling same-origin attack surface`);
      await onLog(`[${ts()}] [Phase 12]  Web app probes`);
      await onLog(`[${ts()}] [Phase 13]  API surface discovery`);
      await onLog(`[${ts()}] [Phase 14]  Host header injection`);
      await onLog(`[${ts()}] [Phase 15]  CRLF injection`);
      await onLog(`[${ts()}] [Phase 16]  Path traversal`);
      await onLog(`[${ts()}] [Phase 21]  Rate limiting / brute-force protection`);
      await onLog(`[${ts()}] [Phase 27]  Open redirect detection`);

      const r3Start = Date.now();
      const [
        r3SensitivePaths,
        r3Surface,
        r3WebApp,
        r3ApiSurface,
        r3HostHeader,
        r3Crlf,
        r3PathTraversal,
        r3RateLimiting,
        r3OpenRedirect,
      ] = await Promise.allSettled([
        // Phase 10: Sensitive paths
        activeRun('Phase 10 (Sensitive paths)', () => checkSensitivePaths(target, true, onLog), [], onLog),

        // Phase 11b: Attack surface crawl
        safeRun(
          'Phase 11b (Attack surface)',
          () => discoverAttackSurface(target, policy, onLog),
          { endpoints: [], parameters: [], crawled: [], forms: 0, truncated: false },
          onLog,
        ),

        // Phase 12: Web app probes
        activeRun('Phase 12 (Web app)', () => checkWebApp(target, onLog), [], onLog),

        // Phase 13: API surface
        activeRun('Phase 13 (API surface)', () => checkApiSurface(target, onLog), [], onLog),

        // Phase 14: Host header injection
        activeRun('Phase 14 (Host header)', () => checkHostHeaderInjection(target, onLog), [], onLog),

        // Phase 15: CRLF injection
        activeRun('Phase 15 (CRLF)', () => checkCrlfInjection(target, onLog), [], onLog),

        // Phase 16: Path traversal
        activeRun('Phase 16 (Path traversal)', () => checkPathTraversal(target, onLog), [], onLog),

        // Phase 21: Rate limiting
        activeRun('Phase 21 (Rate limiting)', () => checkRateLimiting(target, onLog), [], onLog),

        // Phase 27: Open redirect
        activeRun('Phase 27 (Open redirect)', () => checkOpenRedirect(target, onLog), [], onLog),
      ]);

      const surface = settled(r3Surface, { endpoints: [], parameters: [], crawled: [], forms: 0, truncated: false });
      add(settled(r3SensitivePaths, []));
      add(settled(r3WebApp, []));
      add(settled(r3ApiSurface, []));
      add(settled(r3HostHeader, []));
      add(settled(r3Crlf, []));
      add(settled(r3PathTraversal, []));
      add(settled(r3RateLimiting, []));
      add(settled(r3OpenRedirect, []));

      await onLog(
        `[${ts()}] [Round 3] Complete (${Date.now() - r3Start}ms) — ${surface.endpoints.length} endpoints · ${surface.forms} forms crawled`,
      );

      // ════════════════════════════════════════════════════════════════════════
      // ROUND 4 — Deep attack phases (all in parallel)
      //   Phases that depend on surface (R3) or techs (R2) use the collected
      //   values.  The 6 advanced probes also run in parallel within this round.
      // ════════════════════════════════════════════════════════════════════════
      await onLog(`[${ts()}] [Round 4] Launching parallel deep-attack phases (11 tasks)...`);
      await onLog(`[${ts()}] [Phase 13b] API credential leak checks`);
      await onLog(`[${ts()}] [Phase 13c] Configuration exposure`);
      await onLog(`[${ts()}] [Phase 13d] XSS verification`);
      await onLog(`[${ts()}] [Phase 13e] Deep discovered-input testing`);
      await onLog(`[${ts()}] [Phase 13f] Parameter discovery`);
      await onLog(`[${ts()}] [Phase 17]  JWT algorithm & secret weakness`);
      await onLog(`[${ts()}] [Phase 18]  IDOR / BOLA`);
      await onLog(`[${ts()}] [Phase 19]  HTTP request smuggling`);
      await onLog(`[${ts()}] [Phase 20]  Log4Shell / Spring4Shell surface`);
      await onLog(`[${ts()}] [Phase 22]  Advanced probes — SSTI · XXE · SSRF · Deser · CMDi · NoSQL (parallel)`);
      await onLog(`[${ts()}] [Phase 23]  CVE database lookup`);

      const r4Start = Date.now();

      // Load advanced + CVE modules once (shared across parallel tasks)
      let advancedModule: Awaited<typeof import('./phases/advanced')> | null = null;
      let cveModule: Awaited<typeof import('./phases/advanced/cve-lookup')> | null = null;
      try {
        [advancedModule, cveModule] = await Promise.all([
          import('./phases/advanced'),
          import('./phases/advanced/cve-lookup'),
        ]);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        await onLog(`[${ts()}] [WARNING] Advanced module load failed: ${msg}`);
      }

      const [
        r4ApiLeaks,
        r4ConfigExposure,
        r4Xss,
        r4DeepInput,
        r4ParamDiscovery,
        r4Jwt,
        r4Idor,
        r4Smuggling,
        r4Log4Shell,
        r4Advanced,
        r4Cve,
      ] = await Promise.allSettled([
        // Phase 13b: API leaks
        safeRun('Phase 13b (API leaks)', async () => {
          const { runApiLeaksPhase } = await import('./phases/api-leaks');
          const found: RealFinding[] = [];
          await runApiLeaksPhase({ target, policy, log: onLog, addFindings: (f) => found.push(...f) });
          return found;
        }, [] as RealFinding[], onLog),

        // Phase 13c: Config exposure
        safeRun('Phase 13c (Config exposure)', async () => {
          const { runConfigExposurePhase } = await import('./phases/config-exposure');
          const found: RealFinding[] = [];
          await runConfigExposurePhase({ target, policy, log: onLog, addFindings: (f) => found.push(...f) });
          return found;
        }, [] as RealFinding[], onLog),

        // Phase 13d: XSS
        activeRun('Phase 13d (XSS)', async () => {
          const { runXssPhase } = await import('./phases/xss');
          const found: RealFinding[] = [];
          await runXssPhase({ target, policy, log: onLog, addFindings: (f) => found.push(...f) });
          return found;
        }, [] as RealFinding[], onLog),

        // Phase 13e: Deep input testing (needs surface)
        activeRun('Phase 13e (Deep input)', () => runDeepInputTesting(target, policy, surface, onLog), [] as RealFinding[], onLog),

        // Phase 13f: Parameter discovery (needs surface endpoints)
        activeRun(
          'Phase 13f (Parameter discovery)',
          () => discoverParameters(target, surface.endpoints.map((e) => e.url), onLog),
          [] as RealFinding[],
          onLog,
        ),

        // Phase 17: JWT
        activeRun('Phase 17 (JWT)', () => checkJwtWeaknesses(target, onLog), [] as RealFinding[], onLog),

        // Phase 18: IDOR / BOLA
        activeRun('Phase 18 (IDOR)', () => checkIdorAndBola(target, onLog), [] as RealFinding[], onLog),

        // Phase 19: HTTP smuggling
        activeRun('Phase 19 (Smuggling)', () => checkHttpRequestSmuggling(target, onLog), [] as RealFinding[], onLog),

        // Phase 20: Log4Shell
        activeRun('Phase 20 (Log4Shell)', () => checkLog4ShellSurface(target, onLog), [] as RealFinding[], onLog),

        // Phase 22: Advanced probes — all 6 in parallel
        advancedModule
          ? activeRun('Phase 22 (Advanced)', async () => {
              const {
                checkSSTI,
                checkXXE,
                checkSSRF,
                checkDeserialization,
                checkCommandInjection,
                checkNoSqlInjection,
              } = advancedModule!;
              const results = await Promise.allSettled([
                checkSSTI ? checkSSTI(target, onLog) : Promise.resolve([] as RealFinding[]),
                checkXXE ? checkXXE(target, onLog) : Promise.resolve([] as RealFinding[]),
                checkSSRF ? checkSSRF(target, onLog) : Promise.resolve([] as RealFinding[]),
                checkDeserialization ? checkDeserialization(target, onLog) : Promise.resolve([] as RealFinding[]),
                checkCommandInjection ? checkCommandInjection(target, onLog) : Promise.resolve([] as RealFinding[]),
                checkNoSqlInjection ? checkNoSqlInjection(target, onLog) : Promise.resolve([] as RealFinding[]),
              ]);
              return results.flatMap((r) => settled(r, [] as RealFinding[]));
            }, [] as RealFinding[], onLog)
          : Promise.resolve([] as RealFinding[]),

        // Phase 23: CVE lookup (needs techs from Round 2)
        cveModule && fpResult.techs.length > 0
          ? safeRun('Phase 23 (CVE)', () => cveModule!.lookupCvesForTechs(fpResult.techs, onLog), [] as RealFinding[], onLog)
          : (async () => {
              if (!cveModule) await onLog(`[${ts()}] [Phase 23] Skipped — advanced module not loaded`);
              else await onLog(`[${ts()}] [Phase 23] Skipped — no technologies detected`);
              return [] as RealFinding[];
            })(),
      ]);

      add(settled(r4ApiLeaks, []));
      add(settled(r4ConfigExposure, []));
      add(settled(r4Xss, []));
      add(settled(r4DeepInput, []));
      add(settled(r4ParamDiscovery, []));
      add(settled(r4Jwt, []));
      add(settled(r4Idor, []));
      add(settled(r4Smuggling, []));
      add(settled(r4Log4Shell, []));
      add(settled(r4Advanced, []));
      add(settled(r4Cve, []));

      await onLog(`[${ts()}] [Round 4] Complete (${Date.now() - r4Start}ms)`);

      // ════════════════════════════════════════════════════════════════════════
      // ROUND 5 — Weaponised verification (parallel, only when allowed)
      // ════════════════════════════════════════════════════════════════════════
      if (policy.allowVerification) {
        await onLog(`[${ts()}] [Round 5] Launching verification phases (parallel)...`);
        await onLog(`[${ts()}] [Phase 24] Unsecured registration exploitation`);
        await onLog(`[${ts()}] [Phase 25] Default credential brute-force`);
        await onLog(`[${ts()}] [Phase 26] SQLi authentication bypass`);
        if (getCapturedSession()) await onLog(`[${ts()}] [Phase 28] IDOR with captured session`);

        const r5Start = Date.now();
        const [r5Reg, r5Creds, r5SqliAuth, r5IdorSession] = await Promise.allSettled([
          safeRun('Phase 24 (Open registration)', () => checkOpenRegistration(target, onLog), [] as RealFinding[], onLog),
          safeRun('Phase 25 (Default credentials)', () => checkDefaultCredentials(target, onLog), [] as RealFinding[], onLog),
          safeRun('Phase 26 (SQLi auth bypass)', () => checkSqliAuthBypass(target, onLog), [] as RealFinding[], onLog),
          getCapturedSession()
            ? safeRun('Phase 28 (IDOR session)', () => checkIdorWithCapturedSession(target, onLog), [] as RealFinding[], onLog)
            : Promise.resolve([] as RealFinding[]),
        ]);

        add(settled(r5Reg, []));
        add(settled(r5Creds, []));
        add(settled(r5SqliAuth, []));
        add(settled(r5IdorSession, []));
        await onLog(`[${ts()}] [Round 5] Complete (${Date.now() - r5Start}ms)`);
      }

      // ── Post-processing ───────────────────────────────────────────────────
      suppressWafSensitiveFindings(all);
      downgradeWafChallengeFindings(all);
      applyComplianceMapping(all);

      // ── Executive summary ─────────────────────────────────────────────────
      const reportable = all.filter((f) => f.cvss > 0 || f.severity !== 'low');
      const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const f of reportable) {
        if (f.severity in bySeverity) bySeverity[f.severity as keyof typeof bySeverity]++;
      }

      const riskGrade =
        bySeverity.critical > 0
          ? 'F'
          : bySeverity.high >= 3
            ? 'D'
            : bySeverity.high >= 1
              ? 'C'
              : bySeverity.medium >= 3
                ? 'C'
                : bySeverity.medium >= 1
                  ? 'B'
                  : reportable.length === 0
                    ? 'A'
                    : 'B';

      const top3 = reportable
        .slice()
        .sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0))
        .slice(0, 3)
        .map((f) => `  • ${f.title} (CVSS ${f.cvss}, ${f.severity.toUpperCase()})`)
        .join('\n');

      await onLog(`[${ts()}] ═══════════════════════════════════════`);
      await onLog(`[${ts()}] SCAN COMPLETE — EXECUTIVE SUMMARY`);
      await onLog(`[${ts()}] Risk Grade : ${riskGrade}`);
      await onLog(
        `[${ts()}] Total findings : ${reportable.length} (C:${bySeverity.critical} H:${bySeverity.high} M:${bySeverity.medium} L:${bySeverity.low})`,
      );
      await onLog(
        `[${ts()}] Requests used: ${policy.requestBudget - (remainingScanRequests() ?? 0)}/${policy.requestBudget}`,
      );
      const verified = reportable.filter((f) => f.verified || f.verification === 'verified');
      await onLog(
        `[${ts()}] Verified vulnerabilities: ${verified.filter((f) => f.severity === 'critical').length} critical, ${verified.filter((f) => f.severity === 'high').length} high (${verified.length} total)`,
      );
      if (top3) {
        await onLog(`[${ts()}] Top findings by CVSS:`);
        await onLog(top3);
      }
      await onLog(
        `[${ts()}] Compliance: OWASP Top 10 · PCI DSS v4.0 · NIST 800-53 mapped to findings`,
      );
      await onLog(`[${ts()}] ═══════════════════════════════════════`);

      return { findings: reportable, wafBlocked: isWafChallengeDetected() };
    },
  );
}
