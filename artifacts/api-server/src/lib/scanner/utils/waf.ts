import { isWafChallengeResponse as legacyIsWafChallengeResponse } from "../../scanner";

/** Returns true when a response is a known WAF challenge rather than an app response. */
export function isWafOrRateLimit(
  status: number,
  headers: Record<string, string>,
): boolean {
  return status === 429 || legacyIsWafChallengeResponse(status, headers);
}

export { legacyIsWafChallengeResponse as isWafChallengeResponse };