import { digQuery, ts } from '../context';
import { probe } from '../utils/http';
import type { LogFn } from '../context';

export async function getIpInfo(hostname: string, onLog: LogFn): Promise<void> {
  try {
    const ips = await digQuery(hostname, 'A');
    if (ips.length === 0) return;
    const ip = ips[0]!;
    const r = await probe(`https://ipinfo.io/${ip}/json`, { timeoutMs: 8_000 });
    if (r && r.status === 200) {
      const info = JSON.parse(r.body);
      await onLog(
        `[${ts()}] IP Intel: ${ip} | ${info.org ?? 'Unknown ASN'} | ${info.city ?? ''}, ${info.country ?? ''} | Hosting: ${info.hostname ?? '—'}`,
      );
    }
  } catch {}
}
