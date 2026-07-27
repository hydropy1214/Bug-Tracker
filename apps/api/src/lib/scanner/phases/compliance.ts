import type { RealFinding } from '../context';

interface ComplianceEntry {
  owasp?: string[];
  pci?: string[];
  nist?: string[];
}

const COMPLIANCE_MAP: Record<string, ComplianceEntry> = {
  'SQL Injection': { owasp: ['A03:2021'], pci: ['6.3.1'], nist: ['SI-10'] },
  'NoSQL Injection': { owasp: ['A03:2021'], pci: ['6.3.1'], nist: ['SI-10'] },
  'XSS': { owasp: ['A03:2021'], pci: ['6.3.1'], nist: ['SI-10'] },
  'Command Injection': { owasp: ['A03:2021'], pci: ['6.3.1'], nist: ['SI-10'] },
  'SSTI': { owasp: ['A03:2021'], pci: ['6.3.1'], nist: ['SI-10'] },
  'XXE': { owasp: ['A05:2021'], pci: ['6.3.1'], nist: ['SI-10'] },
  'SSRF': { owasp: ['A10:2021'], pci: ['6.4.1'], nist: ['SI-10'] },
  'IDOR': { owasp: ['A01:2021'], pci: ['7.1', '7.2'], nist: ['AC-3'] },
  'BOLA': { owasp: ['A01:2021'], pci: ['7.1', '7.2'], nist: ['AC-3'] },
  'JWT': { owasp: ['A02:2021'], pci: ['8.3.6'], nist: ['IA-5'] },
  'HSTS': { owasp: ['A05:2021'], pci: ['4.2.1'], nist: ['SC-8'] },
  'CSP': { owasp: ['A05:2021'], pci: ['6.4.3'], nist: ['SI-10'] },
  'CORS': { owasp: ['A05:2021'], pci: ['6.4.1'], nist: ['AC-17'] },
  'TLS': { owasp: ['A02:2021'], pci: ['4.2.1'], nist: ['SC-8'] },
  'SSL': { owasp: ['A02:2021'], pci: ['4.2.1'], nist: ['SC-8'] },
  'Certificate': { owasp: ['A02:2021'], pci: ['4.2.1'], nist: ['SC-8'] },
  'Authentication': { owasp: ['A07:2021'], pci: ['8.2.1'], nist: ['IA-2'] },
  'Default Credentials': { owasp: ['A07:2021'], pci: ['8.3.6'], nist: ['IA-5'] },
  'Rate Limiting': { owasp: ['A04:2021'], pci: ['6.4.1'], nist: ['SC-5'] },
  'Sensitive': { owasp: ['A01:2021'], pci: ['6.2.4'], nist: ['SC-28'] },
  'Directory Listing': { owasp: ['A05:2021'], pci: ['6.2.4'], nist: ['AC-6'] },
  'Subdomain Takeover': { owasp: ['A05:2021'], pci: ['6.2.4'], nist: ['CM-6'] },
  'WAF': { owasp: ['A05:2021'], pci: ['6.4.1'], nist: ['SI-3'] },
  'Path Traversal': { owasp: ['A01:2021'], pci: ['6.3.1'], nist: ['SI-10'] },
  'Host Header': { owasp: ['A03:2021'], pci: ['6.3.1'], nist: ['SI-10'] },
  'CRLF': { owasp: ['A03:2021'], pci: ['6.3.1'], nist: ['SI-10'] },
  'HTTP Smuggling': { owasp: ['A03:2021'], pci: ['6.4.1'], nist: ['SC-8'] },
  'Log4Shell': { owasp: ['A06:2021'], pci: ['6.3.3'], nist: ['SI-2'] },
  'Open Redirect': { owasp: ['A01:2021'], pci: ['6.3.1'], nist: ['SI-10'] },
  'Deserialization': { owasp: ['A08:2021'], pci: ['6.3.1'], nist: ['SI-10'] },
  'SPF': { owasp: ['A05:2021'], pci: ['5.3.3'], nist: ['SI-8'] },
  'DMARC': { owasp: ['A05:2021'], pci: ['5.3.3'], nist: ['SI-8'] },
  'DNS': { owasp: ['A05:2021'], pci: ['6.2.4'], nist: ['CM-6'] },
  'MX': { owasp: ['A05:2021'], pci: ['5.3.3'], nist: ['SI-8'] },
  'Exposed Service': { owasp: ['A05:2021'], pci: ['1.3.2'], nist: ['CM-7'] },
  'Open Port': { owasp: ['A05:2021'], pci: ['1.3.2'], nist: ['CM-7'] },
  'CVE': { owasp: ['A06:2021'], pci: ['6.3.3'], nist: ['SI-2'] },
};

export function applyComplianceMapping(findings: RealFinding[]): void {
  for (const finding of findings) {
    if (finding.compliance) continue;
    let matched: ComplianceEntry | null = null;
    for (const [keyword, entry] of Object.entries(COMPLIANCE_MAP)) {
      if (finding.title.includes(keyword) || finding.description.includes(keyword)) {
        matched = entry;
        break;
      }
    }
    if (matched) finding.compliance = matched;
  }
}
