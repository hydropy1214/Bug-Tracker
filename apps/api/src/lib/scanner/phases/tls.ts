import * as tls from 'node:tls';
import { execFileAsync, ts } from '../context';
import type { RealFinding, LogFn } from '../context';

async function opensslTlsInfo(hostname: string, port: number): Promise<string> {
  try {
    const { stdout } = await execFileAsync(
      'openssl',
      ['s_client', '-connect', `${hostname}:${port}`, '-servername', hostname, '-brief', '-no_ign_eof'],
      { timeout: 12_000 },
    );
    return stdout;
  } catch (err: any) {
    return err?.stdout ?? '';
  }
}

export async function checkTls(
  hostname: string,
  port: number,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Running openssl TLS analysis on ${hostname}:${port}...`);
  const opensslOut = await opensslTlsInfo(hostname, port);
  if (opensslOut) await onLog(`[${ts()}] openssl connected...`);

  const certResult = await new Promise<RealFinding[]>((resolve) => {
    const f: RealFinding[] = [];
    const socket = tls.connect(
      { host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout: 12_000 },
      async () => {
        try {
          const cert = socket.getPeerCertificate(true);
          const proto = socket.getProtocol() ?? 'unknown';
          const cipher = socket.getCipher();
          socket.destroy();
          if (proto === 'TLSv1' || proto === 'TLSv1.0') {
            f.push({ title: 'Deprecated TLS 1.0 Protocol Supported', severity: 'high', cvss: 7.4, cve: null, description: 'TLS 1.0 is deprecated.', evidence: `Protocol: ${proto}`, remediation: 'Disable TLS 1.0/1.1.' });
          } else if (proto === 'TLSv1.1') {
            f.push({ title: 'Deprecated TLS 1.1 Protocol Supported', severity: 'medium', cvss: 5.9, cve: null, description: 'TLS 1.1 is deprecated.', evidence: `Protocol: ${proto}`, remediation: 'Disable TLS 1.1.' });
          } else {
            f.push({ title: `TLS Configuration: ${proto}`, severity: 'low', cvss: 0, cve: null, description: `Negotiated ${proto}.`, evidence: `Protocol: ${proto}`, remediation: 'Monitor cipher suites.' });
          }
          const cipherName = cipher?.name?.toUpperCase() ?? '';
          if (cipherName.match(/RC4|DES|NULL|EXPORT|ANON|3DES/)) {
            f.push({ title: `Weak Cipher Suite: ${cipher?.name}`, severity: 'high', cvss: 7.4, cve: null, description: 'Weak cipher negotiated.', evidence: `Cipher: ${cipher?.name}`, remediation: 'Remove weak ciphers.' });
          }
          if (!cert || !cert.valid_to) { resolve(f); return; }
          const selfSigned = cert.issuer?.CN === cert.subject?.CN && cert.issuer?.O === cert.subject?.O;
          if (selfSigned) {
            f.push({ title: 'Self-Signed SSL Certificate', severity: 'medium', cvss: 5.9, cve: null, description: 'Certificate is self-signed.', evidence: `Subject: ${cert.subject?.CN}`, remediation: 'Use a trusted CA.' });
          }
          const expiresAt = new Date(cert.valid_to);
          const daysLeft = Math.floor((expiresAt.getTime() - Date.now()) / 86_400_000);
          if (daysLeft < 0) {
            f.push({ title: 'SSL Certificate Expired', severity: 'critical', cvss: 9.1, cve: null, description: `Expired ${Math.abs(daysLeft)} days ago.`, evidence: `Expired: ${cert.valid_to}`, remediation: 'Renew immediately.' });
          } else if (daysLeft < 14) {
            f.push({ title: `SSL Certificate Expiring in ${daysLeft} Day(s)`, severity: 'high', cvss: 7.5, cve: null, description: `Expires in ${daysLeft} days.`, evidence: `Expiry: ${cert.valid_to}`, remediation: 'Renew now.' });
          } else if (daysLeft < 30) {
            f.push({ title: `SSL Certificate Expiring Soon (${daysLeft} days)`, severity: 'medium', cvss: 5.3, cve: null, description: `Expires in ${daysLeft} days.`, evidence: `Expiry: ${cert.valid_to}`, remediation: 'Renew soon.' });
          }
          const cn = cert.subject?.CN ?? '';
          const altNames: string[] = (cert.subjectaltname ?? '').split(',').map((s) => s.trim().replace(/^DNS:/, ''));
          const hostCovered = cn === hostname || altNames.some((n) => n === hostname || (n.startsWith('*.') && hostname.endsWith(n.slice(1))));
          if (!hostCovered && cn) {
            f.push({ title: 'SSL Certificate Subject Mismatch', severity: 'high', cvss: 7.4, cve: null, description: `CN ${cn} does not match ${hostname}.`, evidence: `Host: ${hostname}\nCN: ${cn}`, remediation: 'Reissue certificate with correct hostname.' });
          }
          const issuedAt = cert.valid_from ? new Date(cert.valid_from) : null;
          if (issuedAt) {
            const totalDays = (expiresAt.getTime() - issuedAt.getTime()) / 86_400_000;
            if (totalDays > 398) {
              f.push({ title: 'Certificate Validity Exceeds 398 Days', severity: 'low', cvss: 3.1, cve: null, description: `${Math.round(totalDays)} days validity.`, evidence: `Validity: ${Math.round(totalDays)} days`, remediation: 'Issue certs with max 90 days.' });
            }
          }
          resolve(f);
        } catch { resolve(f); }
      },
    );
    socket.on('error', () => resolve(f));
    socket.setTimeout(12_000, () => { socket.destroy(); resolve(f); });
  });
  findings.push(...certResult);

  const legacyTests = [
    { flag: '-ssl3', proto: 'SSLv3', severity: 'critical' as const, cvss: 9.4, cve: 'CVE-2014-3566' },
    { flag: '-tls1', proto: 'TLS 1.0', severity: 'high' as const, cvss: 7.4, cve: null },
    { flag: '-tls1_1', proto: 'TLS 1.1', severity: 'medium' as const, cvss: 5.9, cve: null },
  ];
  for (const test of legacyTests) {
    try {
      const { stdout, stderr } = await execFileAsync(
        'openssl',
        ['s_client', '-connect', `${hostname}:${port}`, '-servername', hostname, test.flag, '-brief'],
        { timeout: 8_000 },
      ).catch((err: any) => ({ stdout: err.stdout ?? '', stderr: err.stderr ?? '' }));
      const combined = stdout + stderr;
      if (combined.includes('Verification:') || combined.includes('CONNECTED') || combined.includes('Protocol  :')) {
        findings.push({ title: `Legacy Protocol Accepted: ${test.proto}`, severity: test.severity, cvss: test.cvss, cve: test.cve, description: `Server accepted ${test.proto} handshake.`, evidence: `openssl s_client ${test.flag} succeeded`, remediation: `Disable ${test.proto}.` });
      }
    } catch {}
  }
  await onLog(`[${ts()}] TLS analysis complete — ${findings.length} finding(s)`);
  return findings;
}
