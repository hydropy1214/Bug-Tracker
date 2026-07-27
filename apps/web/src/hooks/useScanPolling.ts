import { useCallback, useEffect, useRef } from 'react';
import { ScanStatus } from '@/components/dashboard/scan-types';

export function useScanPolling(
  applyScanStatus: (data: ScanStatus) => boolean,
  onMissing: () => void,
  onError?: (message: string) => void,
  onRecovered?: () => void,
) {
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const startPolling = useCallback(
    (id: number) => {
      if (pollRef.current) clearTimeout(pollRef.current);
      let stopped = false;
      let consecutiveFailures = 0;
      const poll = async () => {
        try {
          const response = await fetch(`/api/scans/${id}/status`, { cache: 'no-store' });
          if (response.status === 404) {
            onMissing();
            stopped = true;
          } else if (!response.ok) {
            throw new Error(`status ${response.status}`);
          } else {
            const data = (await response.json()) as ScanStatus;
            if (consecutiveFailures > 0) onRecovered?.();
            consecutiveFailures = 0;
            stopped = !applyScanStatus(data);
          }
        } catch (error) {
          consecutiveFailures += 1;
          if (consecutiveFailures === 3) {
            onError?.(
              error instanceof Error
                ? `Live scan updates paused (${error.message}). Retrying…`
                : 'Live scan updates paused. Retrying…',
            );
          }
        }
        if (!stopped) pollRef.current = setTimeout(poll, 1200);
        else pollRef.current = null;
      };
      void poll();
    },
    [applyScanStatus, onError, onMissing, onRecovered],
  );

  useEffect(
    () => () => {
      if (pollRef.current) clearTimeout(pollRef.current);
    },
    [],
  );

  return startPolling;
}
