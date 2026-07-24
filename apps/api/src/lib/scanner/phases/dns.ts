import { checkDns } from '../../scanner';
import type { PhaseContext } from '../types';

/** Phase 2 DNS enumeration adapter. */
export async function runDnsPhase(context: PhaseContext): Promise<void> {
  context.addFindings(await checkDns(context.target.hostname, context.log));
}
