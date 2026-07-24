import { checkHostHeaderInjection, runActiveChecks } from '../../scanner';
import type { PhaseContext } from '../types';

/** Phase 14 host-header injection adapter. */
export async function runHostHeaderPhase(context: PhaseContext): Promise<void> {
  context.addFindings(
    await runActiveChecks(() => checkHostHeaderInjection(context.target, context.log), []),
  );
}
