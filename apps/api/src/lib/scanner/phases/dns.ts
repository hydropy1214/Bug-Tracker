import { digQuery, execFileAsync, ts } from '../context';
import type { RealFinding, LogFn } from '../context';

export async function checkDns(hostname: string, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Running DNS enumeration with dig...`);

  const aRecords = await digQuery(hostname, 'A');
  const aaaaRecords = await digQuery(hostname, 'AAAA');
  const allIPs = [...aRecords, ...aaaaRecords];
  if (allIPs.length > 0) await onLog(`[${ts()}] Resolved IPs: ${allIPs.join(', ')}`);
  else await onLog(`[${ts()}] WARNING: ${hostname} did not resolve to any IP address`);

  const nsRecords = await digQuery(hostname, 'NS');
  await onLog(`[${ts()}] Nameservers: ${nsRecords.join(', ') || '(none)'}`);

  const mxRecords = await digQuery(hostname, 'MX');
  if (mxRecords.length === 0) {
    findings.push({
      title: 'No MX Records Configured',
      severity: 'low',
      cvss: 3.1,
      cve: null,
      description: `No MX records found for ${hostname}. Email may be misconfigured.`,
      evidence: `dig +short ${hostname} MX → (no results)`,
      remediation: 'If email is used, configure MX records. Otherwise publish SPF -all and DMARC p=reject.',
    });
  }

  const txtRecords = await digQuery(hostname, 'TXT');
  const allTxt = txtRecords.map((r) => r.replace(/^"|"$/g, ''));
  await onLog(`[${ts()}] TXT records found: ${allTxt.length}`);

  const spf = allTxt.find((r) => r.startsWith('v=spf1'));
  if (!spf) {
    findings.push({
      title: 'Missing SPF Record — Email Spoofing Risk',
      severity: 'medium',
      cvss: 6.5,
      cve: null,
      description: `No SPF record found for ${hostname}.`,
      evidence: `dig +short ${hostname} TXT → no v=spf1 record`,
      remediation: 'Publish: "v=spf1 include:your-mail-provider.com -all".',
    });
  } else if (spf.includes('+all')) {
    findings.push({
      title: 'SPF Record Permits Any Sender (+all)',
      severity: 'high',
      cvss: 7.5,
      cve: null,
      description: 'SPF record ends with +all, authorising any mail server.',
      evidence: `SPF record: ${spf}`,
      remediation: 'Replace +all with -all to hard-reject unauthorised senders.',
    });
  } else if (spf.includes('~all')) {
    findings.push({
      title: 'SPF Record Uses Soft Fail (~all) — Weak Protection',
      severity: 'low',
      cvss: 3.7,
      cve: null,
      description: 'SPF ~all marks unauthorised senders as suspicious but does not reject them.',
      evidence: `SPF record: ${spf}`,
      remediation: 'Change ~all to -all for hard rejection.',
    });
  }

  const dmarcTxt = await digQuery(`_dmarc.${hostname}`, 'TXT');
  const dmarc = dmarcTxt.map((r) => r.replace(/"/g, '')).find((r) => r.startsWith('v=DMARC1'));
  if (!dmarc) {
    findings.push({
      title: 'Missing DMARC Record — No Email Authentication Policy',
      severity: 'medium',
      cvss: 6.5,
      cve: null,
      description: `No DMARC record at _dmarc.${hostname}.`,
      evidence: `dig +short _dmarc.${hostname} TXT → no v=DMARC1 record`,
      remediation: `Start with "v=DMARC1; p=none; rua=mailto:dmarc@${hostname}".`,
    });
  } else {
    const pMatch = dmarc.match(/p=(\w+)/i);
    const policy = pMatch?.[1]?.toLowerCase() ?? 'none';
    if (policy === 'none') {
      findings.push({
        title: "DMARC Policy Is 'none' — Spoofed Emails Reach Inboxes",
        severity: 'medium',
        cvss: 5.3,
        cve: null,
        description: 'DMARC p=none only generates reports.',
        evidence: `DMARC record: ${dmarc}`,
        remediation: 'Escalate to p=quarantine then p=reject after reviewing reports.',
      });
    } else await onLog(`[${ts()}] DMARC policy: ${policy} (OK)`);
  }

  const caaRecords = await digQuery(hostname, 'CAA');
  if (caaRecords.length === 0) {
    findings.push({
      title: 'No CAA Records — Any CA Can Issue Certificates',
      severity: 'low',
      cvss: 3.7,
      cve: null,
      description: `No CAA records found for ${hostname}.`,
      evidence: `dig +short ${hostname} CAA → (no results)`,
      remediation: `Add CAA records to restrict certificate issuance.\n${hostname}. CAA 0 issue "letsencrypt.org"`,
    });
  } else await onLog(`[${ts()}] CAA records: ${caaRecords.join(', ')}`);

  if (nsRecords.length > 0) {
    const ns = nsRecords[0]!.replace(/\.$/, '');
    try {
      const { stdout } = await execFileAsync('dig', ['AXFR', hostname, `@${ns}`, '+time=5'], {
        timeout: 12_000,
      });
      if (stdout.includes('Transfer failed') || stdout.includes('REFUSED')) {
        await onLog(`[${ts()}] Zone transfer refused by ${ns} (expected)`);
      } else if (stdout.split('\n').length > 15) {
        findings.push({
          title: 'DNS Zone Transfer Allowed — Full Zone Exposed',
          severity: 'high',
          cvss: 7.5,
          cve: null,
          description: `The nameserver ${ns} allows unauthenticated DNS zone transfers.`,
          evidence: `dig AXFR ${hostname} @${ns}\nResponse contained ${stdout.split('\n').length} lines`,
          remediation: 'Configure the nameserver to refuse AXFR requests from unauthorised IPs.',
        });
      }
    } catch {}
  }

  await onLog(`[${ts()}] DNS enumeration complete — ${findings.length} finding(s)`);
  return findings;
}
