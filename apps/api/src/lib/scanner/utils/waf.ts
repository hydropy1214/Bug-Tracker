import { isWafChallengeResponse } from '../context';

export function isWafOrRateLimit(
  status: number,
  headers: Record<string, string>,
): boolean {
  if (status === 429) return true;
  return isWafChallengeResponse(status, headers);
}
