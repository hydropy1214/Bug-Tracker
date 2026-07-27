/**
 * Public scanner facade.
 *
 * All exports come from the modular scanner/ subdirectory.
 * The legacy monolithic scanner.ts has been removed.
 */

// ── Context / shared utilities ───────────────────────────────────────────────
export {
  SCAN_POLICIES,
  activeProbesAllowed,
  discoverToolCapabilities,
  getScanAuthHeaders,
  isContextualReflection,
  isWafChallengeDetected,
  isWafChallengeResponse,
  normalizeTarget,
  noteWafChallengeDetected,
  remainingScanRequests,
  remainingVerificationRequests,
  reserveScanRequest,
  reserveVerificationRequest,
  resolveScanPolicy,
  runActiveChecks,
} from './context';

export type {
  LogFn,
  RealFinding,
  ScanPolicy,
  ScanProfile,
  ScanResult,
  ScanType,
  Target,
  ToolCapability,
} from './context';

// ── Phases ───────────────────────────────────────────────────────────────────
export { checkApiSurface } from './phases/api-surface';
export { checkCrlfInjection } from './phases/crlf';
export { checkDns } from './phases/dns';
export { checkHeaders } from './phases/headers';
export { checkHostHeaderInjection } from './phases/host-header';
export { checkHttpRequestSmuggling } from './phases/request-smuggling';
export { checkIdorAndBola } from './phases/idor';
export { checkJwtWeaknesses } from './phases/jwt';
export { checkLog4ShellSurface } from './phases/log4shell';
export { checkPathTraversal } from './phases/path-traversal';
export { checkPorts } from './phases/ports';
export { checkRateLimiting } from './phases/rate-limiting';
export { checkSensitivePaths } from './phases/sensitive-paths';
export { checkSubdomainTakeover, discoverSubdomains } from './phases/subdomains';
export { checkTls } from './phases/tls';
export { checkWayback } from './phases/wayback';
export { checkWebApp } from './phases/webapp-probes';
export { checkWhois } from './phases/whois';
export { fingerprint } from './phases/tech-fingerprint';
export { getIpInfo } from './phases/ip-info';

// ── Orchestrator ─────────────────────────────────────────────────────────────
export { scanTarget } from './orchestrator';
