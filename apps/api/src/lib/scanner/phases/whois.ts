import { execFileAsync, ts } from '../context';
import type { RealFinding, LogFn } from '../context';

export async function checkWhois(hostname: string, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const parts = hostname.split('.');
  const rootDomain = parts.length > 2 ? parts.slice(-2).join('.') : hostname;
  await onLog(`[${ts()}] Running whois for ${rootDomain}...`);
  try {
    const { stdout } = await execFileAsync('whois', [rootDomain], { timeout: 20_000 });
    const w = stdout.toLowerCase();
    const expiryMatch = stdout.match(
      /(?:Registry Expiry Date|Expiry Date|Expiration Date|paid-till):\s*(\S+)/i,
    );
    if (expiryMatch) {
      const expiryStr = expiryMatch[1]!;
      const expiry = new Date(expiryStr);
      if (!isNaN(expiry.getTime())) {
        const daysLeft = Math.floor((expiry.getTime() - Date.now()) / 86_400_000);
        if (daysLeft < 30) {
          findings.push({
            title: `Domain Expiring in ${daysLeft} Day(s)`,
            severity: daysLeft < 7 ? 'critical' : 'high',
            cvss: daysLeft < 7 ? 9.8 : 8.1,
            cve: null,
            description: `Domain ${rootDomain} expires in ${daysLeft} days.`,
            evidence: `whois ${rootDomain}\nExpiry: ${expiryStr}\nDays remaining: ${daysLeft}`,
            remediation: 'Renew domain immediately.',
          });
        }
      }
    }
    if (!w.includes('redacted') && !w.includes('privacy') && !w.includes('protected')) {
      const emailMatch = stdout.match(/Registrant Email:\s*(\S+@\S+)/i);
      if (emailMatch && !emailMatch[1]!.includes('redacted')) {
        findings.push({
          title: 'WHOIS Registrant Email Publicly Exposed',
          severity: 'low',
          cvss: 3.1,
          cve: null,
          description: `Registrant email ${emailMatch[1]} is visible.`,
          evidence: `whois ${rootDomain}\nRegistrant Email: ${emailMatch[1]}`,
          remediation: 'Enable WHOIS privacy protection.',
        });
      }
    }
  } catch (err: any) {
    await onLog(`[${ts()}] whois lookup failed: ${err?.message ?? String(err)}`);
  }
  return findings;
}
