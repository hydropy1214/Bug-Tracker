import { checkLog4ShellSurface, runActiveChecks } from '../../scanner';
import type { PhaseContext } from '../types';

/** Phase 20 Log4Shell/Spring4Shell adapter. */
export async function runLog4ShellPhase(context: PhaseContext): Promise<void> {
  context.addFindings(
    await runActiveChecks(() => checkLog4ShellSurface(context.target, context.log), []),
  );
}
