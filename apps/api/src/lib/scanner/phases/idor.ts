import { checkIdorAndBola, runActiveChecks } from '../../scanner';
import type { PhaseContext } from '../types';

/** Phase 18/28 access-control adapter. */
export async function runIdorPhase(context: PhaseContext): Promise<void> {
  context.addFindings(
    await runActiveChecks(() => checkIdorAndBola(context.target, context.log), []),
  );
}
