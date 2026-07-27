import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

export interface TechProfile {
  name: string;
  version?: string;
  category: string;
}

export async function fingerprint(
  target: Target,
  onLog: LogFn,
): Promise<{ techs: TechProfile[]; findings: RealFinding[] }> {
  const techs: TechProfile[] = [];
  const findings: RealFinding[] = [];
  const r = await probe(target.url);
  if (!r) return { techs, findings };
  const h = r.headers;
  const body = r.body;

  const server = h['server'] ?? '';
  if (server) techs.push({ name: server, category: 'Web Server' });

  if (body.includes('/wp-content/') || body.includes('/wp-includes/') || h['x-pingback']) {
    const vMatch = body.match(/WordPress\s+([\d.]+)/i);
    techs.push({ name: 'WordPress', version: vMatch?.[1], category: 'CMS' });
    findings.push({ title: 'WordPress CMS Detected', severity: 'low', cvss: 3.7, cve: null, description: `WordPress${vMatch?.[1] ? ` ${vMatch[1]}` : ''} detected.`, evidence: `WordPress indicators in response body`, remediation: 'Keep WordPress and plugins updated.' });
  }
  if (body.includes('Drupal') || h['x-generator']?.includes('Drupal'))
    techs.push({ name: 'Drupal', category: 'CMS' });
  if (body.includes('/components/com_') || body.includes('Joomla'))
    techs.push({ name: 'Joomla', category: 'CMS' });
  if (body.includes('__REACT_DEVTOOLS') || body.includes('react-dom') || body.includes('_react'))
    techs.push({ name: 'React', category: 'Frontend Framework' });
  if (h['x-powered-by']?.includes('Next.js') || body.includes('__NEXT_DATA__')) {
    techs.push({ name: 'Next.js', category: 'Frontend Framework' });
    if (body.includes('"props"') && body.includes('"pageProps"') && body.includes('"buildId"')) {
      const buildIdMatch = body.match(/"buildId":"([^"]+)"/);
      findings.push({ title: 'Next.js Build ID Exposed', severity: 'low', cvss: 3.1, cve: null, description: `Next.js build ID${buildIdMatch ? ` (${buildIdMatch[1]})` : ''} exposed.`, evidence: `__NEXT_DATA__ present`, remediation: 'Acceptable for public pages.' });
    }
  }
  if (body.includes('laravel_session') || h['set-cookie']?.includes('laravel'))
    techs.push({ name: 'Laravel (PHP)', category: 'Backend Framework' });
  if (h['x-frame-options'] === 'SAMEORIGIN' && h['x-content-type-options'] === 'nosniff' && !h['content-security-policy'])
    techs.push({ name: 'Possibly Django (Python)', category: 'Backend Framework' });
  if (server.includes('nginx'))
    techs.push({ name: `Nginx ${server.match(/nginx\/([\d.]+)/i)?.[1] ?? ''}`.trim(), category: 'Web Server' });
  if (server.toLowerCase().includes('apache'))
    techs.push({ name: `Apache ${server.match(/apache\/([\d.]+)/i)?.[1] ?? ''}`.trim(), category: 'Web Server' });
  if (h['cf-ray'] || h['cf-cache-status']) {
    techs.push({ name: 'Cloudflare CDN', category: 'CDN/WAF' });
    await onLog(`[${ts()}] Cloudflare WAF/CDN detected`);
  }
  if (h['x-amz-request-id'] || h['x-amzn-trace-id'] || h['x-amz-cf-id'])
    techs.push({ name: 'AWS (CloudFront/ALB)', category: 'Cloud' });
  if (h['x-amz-function-arn'] || h['x-amz-executed-version']) {
    techs.push({ name: 'AWS Lambda', category: 'Serverless' });
    findings.push({ title: 'AWS Lambda Function Detected', severity: 'low', cvss: 3.1, cve: null, description: 'AWS Lambda ARN header exposed.', evidence: `x-amz-function-arn: ${h['x-amz-function-arn'] ?? '(detected)'}`, remediation: 'Strip AWS Lambda metadata headers.' });
  }
  if (body.includes('"kind":"Status"') || (body.includes('"apiVersion"') && body.includes('"items"'))) {
    techs.push({ name: 'Kubernetes API', category: 'Container Orchestration' });
    findings.push({ title: 'Kubernetes API Response Detected', severity: 'high', cvss: 8.1, cve: null, description: 'Kubernetes API response detected.', evidence: `Response contains Kubernetes JSON fields`, remediation: 'Restrict Kubernetes API server to internal IPs.' });
  }
  if (h['server']?.toLowerCase().includes('docker') || (body.includes('"ApiVersion"') && body.includes('"Os"'))) {
    techs.push({ name: 'Docker API', category: 'Container' });
    findings.push({ title: 'Docker Daemon API Exposed', severity: 'critical', cvss: 10.0, cve: null, description: 'Docker API is publicly accessible.', evidence: `Docker API indicators in response`, remediation: 'Disable remote Docker API.' });
  }
  if (body.includes('org.apache.struts') || body.includes('struts.apache.org') || /\.action(\?|$)/i.test(r.finalUrl)) {
    techs.push({ name: 'Apache Struts', category: 'Backend Framework' });
    findings.push({ title: 'Apache Struts Framework Detected', severity: 'medium', cvss: 6.1, cve: null, description: 'Apache Struts detected.', evidence: `Struts indicators found`, remediation: 'Update Struts to latest.' });
  }
  if (techs.length > 0)
    await onLog(`[${ts()}] Technologies: ${techs.map((t) => `${t.name} (${t.category})`).join(', ')}`);
  return { techs, findings };
}
