import { useCallback, useEffect, useRef } from "react";
import { ScanStatus } from "@/components/dashboard/scan-types";

export function useScanPolling(
  applyScanStatus: (data: ScanStatus) => boolean,
  onMissing: () => void,
) {
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const startPolling = useCallback((id: number) => {
    if (pollRef.current) clearTimeout(pollRef.current);
    let stopped = false;
    const poll = async () => {
      try {
        const response = await fetch(`/api/scans/${id}/status`, { cache: "no-store" });
        if (response.status === 404) {
          onMissing();
          stopped = true;
        } else if (!response.ok) {
          throw new Error(`status ${response.status}`);
        } else {
          const data = (await response.json()) as ScanStatus;
          stopped = !applyScanStatus(data);
        }
      } catch {
        // Keep polling through transient API restarts.
      }
      if (!stopped) pollRef.current = setTimeout(poll, 1200);
      else pollRef.current = null;
    };
    void poll();
  }, [applyScanStatus, onMissing]);

  useEffect(() => () => {
    if (pollRef.current) clearTimeout(pollRef.current);
  }, []);

  return startPolling;
}