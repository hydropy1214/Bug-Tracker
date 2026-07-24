/**
 * Public scanner facade.
 *
 * Keeping the facade separate from the compatibility implementation makes the
 * phase-by-phase migration safe for the worker, routes, and future consumers.
 */
export {
  SCAN_POLICIES,
  activeProbesAllowed,
  checkApiSurface,
  checkCrlfInjection,
  checkDns,
  checkHeaders,
  checkHostHeaderInjection,
  checkHttpRequestSmuggling,
  checkIdorAndBola,
  checkJwtWeaknesses,
  checkLog4ShellSurface,
  checkPathTraversal,
  checkPorts,
  checkRateLimiting,
  checkSensitivePaths,
  checkSubdomainTakeover,
  checkTls,
  checkWayback,
  checkWebApp,
  checkWhois,
  discoverToolCapabilities,
  discoverSubdomains,
  fingerprint,
  getScanAuthHeaders,
  getIpInfo,
  isContextualReflection,
  isWafChallengeDetected,
  isWafChallengeResponse,
  normalizeTarget,
  noteWafChallengeDetected,
  remainingScanRequests,
  reserveScanRequest,
  resolveScanPolicy,
  runActiveChecks,
  scanTarget,
} from "../scanner";
export type {
  LogFn,
  RealFinding,
  ScanPolicy,
  ScanProfile,
  ScanResult,
  ScanType,
  Target,
  ToolCapability,
} from "../scanner";