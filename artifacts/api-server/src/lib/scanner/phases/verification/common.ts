import {
  activeProbesAllowed,
  reserveVerificationRequest,
} from "../../../scanner";
import { probe, type HttpProbeResult } from "../../utils/http";

export function endpointFromFinding(title: string, evidence: string, targetUrl: string): string | null {
  const explicit = evidence.match(/(?:GET|POST|PUT|PATCH)\s+(https?:\/\/[^\s]+)/i)?.[1];
  if (explicit) return explicit.replace(/[),]+$/, "");
  const url = evidence.match(/https?:\/\/[^\s)]+/)?.[0];
  if (url) return url.replace(/[),]+$/, "");
  if (/GraphQL/i.test(title)) return `${targetUrl.replace(/\/$/, "")}/graphql`;
  return null;
}

export function parameterFromFinding(title: string, evidence: string): string | null {
  return (
    evidence.match(/(?:parameter|param)\s*['"`:]?\s*([A-Za-z0-9_.-]+)/i)?.[1] ??
    title.match(/(?:via|in)\s+(?:parameter|param)\s*['"`]?([A-Za-z0-9_.-]+)/i)?.[1] ??
    null
  );
}

export async function verificationProbe(
  url: string,
  options: Parameters<typeof probe>[1] = {},
): Promise<HttpProbeResult | null> {
  if (!activeProbesAllowed() || !reserveVerificationRequest()) return null;
  return probe(url, { ...options, maxRetries: 0 });
}

export function redact(value: string, maxLength = 900): string {
  return value
    .replace(/(authorization\s*:\s*bearer\s+)[^\s]+/gi, "$1[REDACTED]")
    .replace(/(cookie\s*:\s*)[^\r\n]+/gi, "$1[REDACTED]")
    .replace(/(set-cookie\s*:\s*)[^\r\n]+/gi, "$1[REDACTED]")
    .replace(/(password|token|secret|api[_-]?key)\s*[=:]\s*["']?[^"',\s]+/gi, "$1=[REDACTED]")
    .slice(0, maxLength);
}

export function canaryEvidence(
  endpoint: string,
  method: string,
  canary: string,
  response: HttpProbeResult,
  note: string,
): string {
  return [
    `REQUEST: ${method} ${endpoint}`,
    `CANARY: ${canary}`,
    `RESPONSE: HTTP ${response.status} (${response.body.length} bytes)`,
    `EVIDENCE: ${note}`,
    `RESPONSE SNIPPET: ${redact(response.body)}`,
  ].join("\n");
}