import {
  activeProbesAllowed,
  getScanAuthHeaders,
  noteWafChallengeDetected,
  reserveScanRequest,
} from '../../scanner';
import { isWafOrRateLimit } from './waf';

export interface HttpProbeResult {
  status: number;
  headers: Record<string, string>;
  body: string;
  finalUrl: string;
  durationMs: number;
}

export interface HttpProbeOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  followRedirects?: boolean;
  maxRetries?: number;
}

/**
 * Shared fetch wrapper for extracted phases.
 *
 * It applies scan budget, auth headers, timeouts, bounded retries, and WAF
 * detection consistently. Active phase callers receive null after a challenge.
 */
export async function probe(
  url: string,
  options: HttpProbeOptions = {},
): Promise<HttpProbeResult | null> {
  if (!activeProbesAllowed() || !reserveScanRequest()) return null;

  const retries = Math.max(0, Math.min(options.maxRetries ?? 1, 2));
  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const started = Date.now();
    const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 10_000);
    try {
      const response = await fetch(url, {
        method: options.method ?? 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; SentinelX/2.0; security-scanner)',
          ...getScanAuthHeaders(),
          ...(options.headers ?? {}),
        },
        body: options.body,
        signal: controller.signal,
        redirect: options.followRedirects === false ? 'manual' : 'follow',
      });
      const headers: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });
      const body = (await response.text().catch(() => '')).slice(0, 15_000);
      if (isWafOrRateLimit(response.status, headers)) {
        if (response.status !== 429) await noteWafChallengeDetected();
        return null;
      }
      return {
        status: response.status,
        headers,
        body,
        finalUrl: response.url,
        durationMs: Date.now() - started,
      };
    } catch {
      if (attempt === retries) return null;
    } finally {
      clearTimeout(timer);
    }
  }
  return null;
}
