import { checkWayback } from '../../scanner';
import type { PhaseContext } from '../types';

/** Phase 11 historical endpoint discovery adapter. */
export async function runWaybackPhase(context: PhaseContext): Promise<void> {
  context.addFindings(await checkWayback(context.target.hostname, context.log));
}
