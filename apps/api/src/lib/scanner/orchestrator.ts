/**
 * Scan orchestrator — wires all phase modules together into scanTarget().
 *
 * Every import comes from scanner/context or scanner/phases/*.
 * Nothing in this file imports from the legacy scanner.ts.
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

  // Apply origin override if set
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

      const safePhase = async <T>(label: string, fn: () => Promise<T>, fallback: T): Promise<T> => {
        try {
          return await fn();
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          await onLog(`[${ts()}] [WARNING] ${label} encountered an error and was skipped: ${msg}`);
          return fallback;
        }
      };

      await onLog(`[${ts()}] ═══════════════════════════════════════`);
      await onLog(`[${ts()}] TARGET  : ${target.url}`);
      await onLog(`[${ts()}] HOST    : ${target.hostname}`);
      await onLog(`[${ts()}] SCAN    : FULL DEEP SCAN / PROFILE ${policy.profile.toUpperCase()}`);
      await onLog(
        `[${ts()}] POLICY  : ${policy.requestBudget} request budget · ${policy.timeoutMs}ms timeout · concurrency ${policy.maxConcurrency}`,
      );
      await onLog(
        `[${ts()}] TOOLS   : nmap · dig · whois · openssl · fetch · crt.sh · ipinfo.io · Wayback · GitHub · S3/GCS/Azure · psbdmp`,
      );
      if (authHeaders && Object.keys(authHeaders).length > 0) {
        await onLog(
          `[${ts()}] AUTH    : Authenticated scanning enabled (${Object.keys(authHeaders).join(', ')})`,
        );
      } else {
        await onLog(`[${ts()}] AUTH    : Unauthenticated scan`);
      }
      await onLog(`[${ts()}] ═══════════════════════════════════════`);

      // Phase 1: WAF detection and bypass
      await onLog(`[${ts()}] [Phase 1] WAF/CDN detection and bypass testing...`);
      const { findings: wafFindings } = await runActiveChecks(
        () => checkWafAndBypass(target, onLog),
        { findings: [], wafName: null },
      );
      add(wafFindings);

      // Phase 2: DNS enumeration
      await onLog(`[${ts()}] [Phase 2] DNS enumeration (dig)...`);
      add(await safePhase('Phase 2 (DNS)', () => checkDns(target.hostname, onLog), []));

      // Phase 3: IP geolocation & ASN
      await onLog(`[${ts()}] [Phase 3] IP geolocation & ASN intelligence...`);
      await safePhase('Phase 3 (IP info)', () => getIpInfo(target.hostname, onLog), undefined as void);

      // Phase 3b: IP range / ASN / co-hosted hosts (reconFTW)
      await onLog(`[${ts()}] [Phase 3b] IP range, ASN mapping, and reverse DNS sweep...`);
      add(await safePhase('Phase 3b (IP range)', () => checkIpRange(target, onLog), []));

      // Phase 4: WHOIS
      if (assetType !== 'ip') {
        await onLog(`[${ts()}] [Phase 4] WHOIS domain intelligence...`);
        add(await safePhase('Phase 4 (WHOIS)', () => checkWhois(target.hostname, onLog), []));
      }

      // Phase 5: Subdomain discovery + takeover
      let discoveredSubs: string[] = [];
      if (assetType !== 'ip') {
        await onLog(`[${ts()}] [Phase 5] Subdomain discovery...`);
        const subResult = await safePhase(
          'Phase 5 (Subdomain discovery)',
          () => discoverSubdomains(target.hostname, onLog),
          { findings: [] as RealFinding[], subs: [] as string[] },
        );
        add(subResult.findings);
        discoveredSubs = subResult.subs;
        await onLog(`[${ts()}] Total subdomains in scope: ${discoveredSubs.length}`);
        await onLog(`[${ts()}] [Phase 5b] Subdomain takeover detection...`);
        add(await runActiveChecks(() => checkSubdomainTakeover(discoveredSubs, onLog), []));

        // Phase 5c: Subdomain permutations (reconFTW)
        await onLog(`[${ts()}] [Phase 5c] Subdomain permutation sweep...`);
        const permResult = await safePhase(
          'Phase 5c (Subdomain permutations)',
          () => checkSubdomainPermutations(target.hostname, discoveredSubs, onLog),
          { subs: [] as string[], findings: [] as RealFinding[] },
        );
        add(permResult.findings);
        if (permResult.subs.length > 0) {
          discoveredSubs.push(...permResult.subs);
          await onLog(`[${ts()}] Permutation added ${permResult.subs.length} new subdomain(s). Total: ${discoveredSubs.length}`);
        }
      }

      // Phase 6: Port scanning
      await onLog(`[${ts()}] [Phase 6] Full port scanning with nmap...`);
      add(await runActiveChecks(() => checkPorts(target.hostname, 'full', onLog), []));

      // Phase 7: TLS/SSL analysis
      if (target.isHttps) {
        await onLog(`[${ts()}] [Phase 7] TLS/SSL analysis...`);
        add(await safePhase('Phase 7 (TLS)', () => checkTls(target.hostname, target.port, onLog), []));
      }

      // Phase 8: HTTP security headers
      await onLog(`[${ts()}] [Phase 8] HTTP security header analysis...`);
      add(await safePhase('Phase 8 (Headers)', () => checkHeaders(target, onLog), []));

      // Phase 9: Technology fingerprinting
      await onLog(`[${ts()}] [Phase 9] Technology fingerprinting...`);
      const { techs, findings: fpFindings } = await safePhase(
        'Phase 9 (Fingerprint)',
        () => fingerprint(target, onLog),
        { techs: [] as TechProfile[], findings: [] as RealFinding[] },
      );
      add(fpFindings);
      if (techs.length > 0)
        await onLog(
          `[${ts()}] Stack detected: ${techs.map((t) => `${t.name} (${t.category})`).join(' · ')}`,
        );

      // Phase 9b: Favicon hash fingerprinting (reconFTW / Shodan-style)
      await onLog(`[${ts()}] [Phase 9b] Favicon hash fingerprinting (Shodan MurmurHash3)...`);
      add(await safePhase('Phase 9b (Favicon hash)', () => checkFaviconHash(target, onLog), []));

      // Phase 10: Sensitive path discovery
      await onLog(`[${ts()}] [Phase 10] Sensitive path discovery...`);
      add(await runActiveChecks(() => checkSensitivePaths(target, true, onLog), []));

      // Phase 11: Wayback Machine
      await onLog(`[${ts()}] [Phase 11] Wayback Machine...`);
      add(await safePhase('Phase 11 (Wayback)', () => checkWayback(target.hostname, onLog), []));

      // Phase 11c: Google dorking — generate dork queries + active path probing (reconFTW)
      await onLog(`[${ts()}] [Phase 11c] Google dorking & sensitive file probing...`);
      add(await safePhase('Phase 11c (Google dorking)', () => checkGoogleDorking(target, onLog), []));

      // Phase 11d: GitHub dorking — search public repos/code for secrets (reconFTW)
      await onLog(`[${ts()}] [Phase 11d] GitHub dorking — searching public repos/code...`);
      add(await safePhase('Phase 11d (GitHub dorking)', () => checkGitHubDorking(target, onLog), []));

      // Phase 11e: Cloud bucket enumeration — S3/GCS/Azure (reconFTW)
      await onLog(`[${ts()}] [Phase 11e] Cloud bucket enumeration (S3 · GCS · Azure)...`);
      add(await safePhase('Phase 11e (Cloud buckets)', () => checkCloudBuckets(target, onLog), []));

      // Phase 11f: Email harvesting + SPF/DMARC analysis (reconFTW)
      await onLog(`[${ts()}] [Phase 11f] Email harvesting & SPF/DMARC analysis...`);
      add(await safePhase('Phase 11f (Email harvesting)', () => harvestEmails(target, onLog), []));

      // Phase 11g: Paste site / leak detection (reconFTW)
      await onLog(`[${ts()}] [Phase 11g] Leak detection — paste sites & public dumps...`);
      add(await safePhase('Phase 11g (Leak detection)', () => checkLeakDetection(target, onLog), []));

      // Phase 11b: Crawl and inventory the real attack surface before
      // parameter-based testing. This avoids treating the home page as the
      // entire application.
      await onLog(`[${ts()}] [Phase 11b] Crawling same-origin attack surface...`);
      const surface = await safePhase(
        'Phase 11b (Attack-surface discovery)',
        () => discoverAttackSurface(target, policy, onLog),
        { endpoints: [], parameters: [], crawled: [], forms: 0, truncated: false },
      );

      // Phase 12: Web app probes
      await onLog(`[${ts()}] [Phase 12] Web app probes...`);
      add(await runActiveChecks(() => checkWebApp(target, onLog), []));

      // Phase 13: API surface
      await onLog(`[${ts()}] [Phase 13] API surface discovery...`);
      add(await runActiveChecks(() => checkApiSurface(target, onLog), []));

      // Phase 13e: use the discovered routes, forms, and parameters for
      // baseline-aware SQLi, XSS, redirect, and traversal verification.
      await onLog(`[${ts()}] [Phase 13e] Deep discovered-input testing...`);
      add(
        await runActiveChecks(
          () => runDeepInputTesting(target, policy, surface, onLog),
          [],
        ),
      );

      // Phase 13f: Parameter discovery (Arjun-style, reconFTW)
      await onLog(`[${ts()}] [Phase 13f] Parameter discovery (hidden/undocumented params)...`);
      add(
        await runActiveChecks(
          () => discoverParameters(target, surface.endpoints.map((e) => e.url), onLog),
          [],
        ),
      );

      // Phase 13b: API credential leak checks
      await onLog(`[${ts()}] [Phase 13b] API credential leak checks...`);
      await safePhase('Phase 13b (API leaks)', async () => {
        const { runApiLeaksPhase } = await import('./phases/api-leaks');
        const phaseFindings: RealFinding[] = [];
        await runApiLeaksPhase({ target, policy, log: onLog, addFindings: (f) => phaseFindings.push(...f) });
        add(phaseFindings);
      }, undefined as void);

      // Phase 13c: Configuration exposure checks
      await onLog(`[${ts()}] [Phase 13c] Configuration exposure checks...`);
      await safePhase('Phase 13c (Configuration exposure)', async () => {
        const { runConfigExposurePhase } = await import('./phases/config-exposure');
        const phaseFindings: RealFinding[] = [];
        await runConfigExposurePhase({ target, policy, log: onLog, addFindings: (f) => phaseFindings.push(...f) });
        add(phaseFindings);
      }, undefined as void);

      // Phase 13d: Focused XSS verification
      await onLog(`[${ts()}] [Phase 13d] Focused XSS verification...`);
      add(await runActiveChecks(async () => {
        const { runXssPhase } = await import('./phases/xss');
        const phaseFindings: RealFinding[] = [];
        await runXssPhase({ target, policy, log: onLog, addFindings: (f) => phaseFindings.push(...f) });
        return phaseFindings;
      }, []));

      // Phase 14: Host header injection
      await onLog(`[${ts()}] [Phase 14] Host header injection...`);
      add(await runActiveChecks(() => checkHostHeaderInjection(target, onLog), []));

      // Phase 15: CRLF injection
      await onLog(`[${ts()}] [Phase 15] CRLF injection...`);
      add(await runActiveChecks(() => checkCrlfInjection(target, onLog), []));

      // Phase 16: Path traversal
      await onLog(`[${ts()}] [Phase 16] Path traversal...`);
      add(await runActiveChecks(() => checkPathTraversal(target, onLog), []));

      // Phase 17: JWT weaknesses
      await onLog(
        `[${ts()}] [Phase 17] JWT algorithm, secret weakness, and advanced attack suite...`,
      );
      add(await runActiveChecks(() => checkJwtWeaknesses(target, onLog), []));

      // Phase 18: IDOR / BOLA
      await onLog(`[${ts()}] [Phase 18] IDOR / Broken Object-Level Access Control...`);
      add(await runActiveChecks(() => checkIdorAndBola(target, onLog), []));

      // Phase 19: HTTP request smuggling
      await onLog(`[${ts()}] [Phase 19] HTTP request smuggling...`);
      add(await runActiveChecks(() => checkHttpRequestSmuggling(target, onLog), []));

      // Phase 20: Log4Shell / Spring4Shell surface
      await onLog(`[${ts()}] [Phase 20] Log4Shell/Spring4Shell surface...`);
      add(await runActiveChecks(() => checkLog4ShellSurface(target, onLog), []));

      // Phase 21: Rate limiting absence
      await onLog(`[${ts()}] [Phase 21] Rate limiting / brute-force protection check...`);
      add(await runActiveChecks(() => checkRateLimiting(target, onLog), []));

      // Phase 27: Open redirect (reconFTW)
      await onLog(`[${ts()}] [Phase 27] Open redirect detection...`);
      add(await runActiveChecks(() => checkOpenRedirect(target, onLog), []));

      // Phase 22: Advanced probes (SSTI, XXE, SSRF, Deserialization, CMDi, NoSQL)
      await onLog(
        `[${ts()}] [Phase 22] Advanced probes — SSTI · XXE · SSRF · Deserialization · CMDi · NoSQL...`,
      );
      let lookupCvesForTechs: ((t: TechProfile[], l: LogFn) => Promise<RealFinding[]>) | undefined;
      await safePhase('Phase 22 (Advanced probes / module load)', async () => {
        const {
          checkSSTI,
          checkXXE,
          checkSSRF,
          checkDeserialization,
          checkCommandInjection,
          checkNoSqlInjection,
        } = await import('./phases/advanced');
        const { lookupCvesForTechs: _lookupCves } = await import('./phases/advanced/cve-lookup');
        lookupCvesForTechs = _lookupCves;
        add(
          await runActiveChecks(async () => {
            const advancedFindings: RealFinding[] = [];
            if (checkSSTI) advancedFindings.push(...(await checkSSTI(target, onLog)));
            if (checkXXE) advancedFindings.push(...(await checkXXE(target, onLog)));
            if (checkSSRF) advancedFindings.push(...(await checkSSRF(target, onLog)));
            if (checkDeserialization)
              advancedFindings.push(...(await checkDeserialization(target, onLog)));
            if (checkCommandInjection)
              advancedFindings.push(...(await checkCommandInjection(target, onLog)));
            if (checkNoSqlInjection)
              advancedFindings.push(...(await checkNoSqlInjection(target, onLog)));
            return advancedFindings;
          }, []),
        );
      }, undefined as void);

      // Phase 23: CVE database lookup
      await onLog(`[${ts()}] [Phase 23] CVE database lookup...`);
      if (lookupCvesForTechs) {
        add(await safePhase('Phase 23 (CVE lookup)', () => lookupCvesForTechs!(techs, onLog), []));
      } else {
        await onLog(`[${ts()}] [Phase 23] Skipped — advanced probe module not loaded`);
      }

      // ── WEAPONISED PHASES (only when allowVerification is true) ──
      if (policy.allowVerification) {
        await onLog(`[${ts()}] [Phase 24] Unsecured registration exploitation...`);
        add(await safePhase('Phase 24 (Open registration)', () => checkOpenRegistration(target, onLog), []));

        await onLog(`[${ts()}] [Phase 25] Default credential brute-force...`);
        add(await safePhase('Phase 25 (Default credentials)', () => checkDefaultCredentials(target, onLog), []));

        await onLog(`[${ts()}] [Phase 26] SQLi authentication bypass...`);
        add(await safePhase('Phase 26 (SQLi auth bypass)', () => checkSqliAuthBypass(target, onLog), []));

        if (getCapturedSession()) {
          await onLog(`[${ts()}] [Phase 28] IDOR with captured session...`);
          add(await safePhase('Phase 28 (IDOR session)', () => checkIdorWithCapturedSession(target, onLog), []));
        }
      }

      suppressWafSensitiveFindings(all);
      downgradeWafChallengeFindings(all);
      applyComplianceMapping(all);

      // ── Summary ──
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
