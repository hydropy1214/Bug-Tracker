import { checkWhois } from '../../scanner';
import type { PhaseContext } from '../types';

/** Phase 4 WHOIS intelligence adapter. */
export async function runWhoisPhase(context: PhaseContext): Promise<void> {
  context.addFindings(await checkWhois(context.target.hostname, context.log));
}
