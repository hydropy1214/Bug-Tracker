import { checkSensitivePaths, runActiveChecks } from '../../scanner';
import type { PhaseContext } from '../types';

/** Phase 10 sensitive path discovery adapter. */
export async function runSensitivePathsPhase(context: PhaseContext): Promise<void> {
  context.addFindings(
    await runActiveChecks(() => checkSensitivePaths(context.target, true, context.log), []),
  );
}
