import { execFileAsync, ts } from '../context';
import type { RealFinding, ScanType, LogFn } from '../context';

interface NmapService {
  port: number;
  protocol: string;
  state: string;
  service: string;
  version: string;
}

async function nmapScan(hostname: string, portRange: string, onLog: LogFn): Promise<NmapService[]> {
  await onLog(`[${ts()}] nmap -sV -p ${portRange} ${hostname} ...`);
  try {
    const { stdout } = await execFileAsync(
      'nmap',
      ['-sV', '-sT', '-p', portRange, '--open', '-T4', '--max-retries', '2', '--host-timeout', '45s', '-oG', '-', hostname],
      { timeout: 60_000 },
    );
    const services: NmapService[] = [];
    for (const line of stdout.split('\n')) {
      const m = line.match(/Ports:\s+(.+)/);
      if (!m) continue;
      for (const entry of m[1]!.split(',')) {
        const parts = entry.trim().split('/');
        if (parts.length >= 3 && parts[1] === 'open') {
          services.push({
            port: parseInt(parts[0]!),
            protocol: parts[2] ?? 'tcp',
            state: parts[1],
            service: parts[4] ?? '',
            version: parts[6] ?? '',
          });
        }
      }
    }
    await onLog(`[${ts()}] nmap found ${services.length} open port(s)`);
    return services;
  } catch (err: any) {
    await onLog(`[${ts()}] nmap scan error: ${err?.message ?? String(err)}`);
    return [];
  }
}

const SERVICE_RISKS: Record<string, { severity: 'critical' | 'high' | 'medium' | 'low'; cvss: number; cve: string | null; description: string; remediation: string }> = {
  ftp: { severity: 'high', cvss: 7.5, cve: null, description: 'FTP exposed. Plaintext credentials.', remediation: 'Replace with SFTP/FTPS.' },
  telnet: { severity: 'critical', cvss: 9.8, cve: null, description: 'Telnet exposed. Plaintext passwords.', remediation: 'Replace with SSH.' },
  smtp: { severity: 'medium', cvss: 5.3, cve: null, description: 'SMTP relay exposed.', remediation: 'Restrict SMTP to authenticated users.' },
  rdp: { severity: 'high', cvss: 7.5, cve: null, description: 'RDP exposed.', remediation: 'Block 3389, use VPN.' },
  smb: { severity: 'high', cvss: 7.5, cve: null, description: 'SMB exposed.', remediation: 'Block 445.' },
  mysql: { severity: 'critical', cvss: 9.4, cve: null, description: 'MySQL exposed.', remediation: 'Bind to 127.0.0.1.' },
  postgres: { severity: 'critical', cvss: 9.4, cve: null, description: 'PostgreSQL exposed.', remediation: 'Bind to localhost.' },
  mongodb: { severity: 'critical', cvss: 9.8, cve: null, description: 'MongoDB exposed.', remediation: 'Enable auth, bind to 127.0.0.1.' },
  redis: { severity: 'critical', cvss: 9.8, cve: null, description: 'Redis exposed.', remediation: 'Set requirepass, bind to 127.0.0.1.' },
  elasticsearch: { severity: 'critical', cvss: 9.8, cve: null, description: 'Elasticsearch exposed.', remediation: 'Enable X-Pack security.' },
  ssh: { severity: 'medium', cvss: 5.3, cve: null, description: 'SSH exposed.', remediation: 'Disable password auth, use keys.' },
  vnc: { severity: 'critical', cvss: 9.8, cve: null, description: 'VNC exposed.', remediation: 'Block VNC ports.' },
  docker: { severity: 'critical', cvss: 10.0, cve: null, description: 'Docker API exposed.', remediation: 'Disable remote API.' },
  kubernetes: { severity: 'critical', cvss: 10.0, cve: null, description: 'Kubernetes API exposed.', remediation: 'Restrict API to authorised IPs.' },
  memcached: { severity: 'high', cvss: 7.5, cve: null, description: 'Memcached exposed.', remediation: 'Bind to 127.0.0.1.' },
};

export async function checkPorts(
  hostname: string,
  scanType: ScanType,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const portRange =
    scanType === 'full'
      ? '1-65535'
      : scanType === 'vulnerability'
        ? '1-10000'
        : '21,22,23,25,80,443,445,1433,1521,2375,2376,3306,3389,4848,5432,5601,5900,5984,6379,7001,8080,8443,8888,9200,9300,10000,11211,27017,28017,50000';
  const services = await nmapScan(hostname, portRange, onLog);
  for (const svc of services) {
    await onLog(`[${ts()}] OPEN PORT ${svc.port}/${svc.protocol} — ${svc.service} ${svc.version}`.trim());
    const svcName = svc.service.toLowerCase();
    let matched = false;
    for (const [key, risk] of Object.entries(SERVICE_RISKS)) {
      if (
        svcName.includes(key) ||
        (key === 'smb' && svc.port === 445) ||
        (key === 'rdp' && svc.port === 3389) ||
        (key === 'docker' && (svc.port === 2375 || svc.port === 2376))
      ) {
        findings.push({
          title: `Exposed Service: ${svc.service || key.toUpperCase()} on Port ${svc.port}/${svc.protocol}`,
          severity: risk.severity,
          description: risk.description,
          cvss: risk.cvss,
          cve: risk.cve,
          evidence: `nmap detected open port ${svc.port}/${svc.protocol}\nService: ${svc.service} ${svc.version}\nHost: ${hostname}`,
          remediation: risk.remediation,
        });
        matched = true;
        break;
      }
    }
    if (!matched && ![80, 443, 8080, 8443].includes(svc.port)) {
      findings.push({
        title: `Unexpected Open Port: ${svc.port}/${svc.protocol} (${svc.service || 'unknown'})`,
        severity: 'low',
        cvss: 3.7,
        cve: null,
        description: `Port ${svc.port}/${svc.protocol} is open.`,
        evidence: `nmap: ${svc.port}/${svc.protocol} open — ${svc.service} ${svc.version}`,
        remediation: `Block port ${svc.port} if not needed.`,
      });
    }
  }
  return findings;
}
