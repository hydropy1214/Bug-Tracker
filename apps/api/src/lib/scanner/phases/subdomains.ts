import { execFileAsync, digQuery, dnsResolve, ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, LogFn } from '../context';

export async function discoverSubdomains(
  hostname: string,
  onLog: LogFn,
): Promise<{ subs: string[]; findings: RealFinding[] }> {
  const findings: RealFinding[] = [];
  const subs: string[] = [];
  const parts = hostname.split('.');
  const rootDomain = parts.length > 2 ? parts.slice(-2).join('.') : hostname;
  await onLog(`[${ts()}] Querying crt.sh certificate transparency for ${rootDomain} subdomains...`);
  try {
    const r = await probe(`https://crt.sh/?q=%.${rootDomain}&output=json`, { timeoutMs: 20_000 });
    if (r && r.status === 200 && r.body.startsWith('[')) {
      const records: Array<{ name_value: string }> = JSON.parse(r.body);
      const nameSet = new Set<string>();
      for (const rec of records) {
        for (const name of rec.name_value.split('\n')) {
          const n = name.trim().toLowerCase().replace(/^\*\./, '');
          if (n.endsWith(`.${rootDomain}`) || n === rootDomain) nameSet.add(n);
        }
      }
      const uniqueSubs = [...nameSet].filter((n) => n !== rootDomain);
      subs.push(...uniqueSubs.slice(0, 50));
      const interesting = uniqueSubs.filter((s) =>
        /admin|dev|staging|test|internal|api|vpn|uat|qa|demo|beta|old|legacy/i.test(s),
      );
      if (interesting.length > 0) {
        findings.push({
          title: `${interesting.length} Sensitive Subdomain(s) via Certificate Transparency`,
          severity: 'medium',
          cvss: 5.3,
          cve: null,
          description: `crt.sh reveals ${interesting.length} potentially internal subdomains.`,
          evidence: `Sensitive subdomains:\n${interesting.slice(0, 15).join('\n')}`,
          remediation: 'Audit each subdomain.',
        });
      }
      if (uniqueSubs.length > 20) {
        findings.push({
          title: `Large Attack Surface: ${uniqueSubs.length} Subdomains`,
          severity: 'low',
          cvss: 3.7,
          cve: null,
          description: `${uniqueSubs.length} subdomains discovered.`,
          evidence: `Sample: ${uniqueSubs.slice(0, 10).join(', ')}`,
          remediation: 'Regularly audit subdomains.',
        });
      }
    }
  } catch (err: any) {
    await onLog(`[${ts()}] crt.sh lookup error: ${err?.message ?? String(err)}`);
  }

  const COMMON_SUBS = [
    // Core services
    'www','www2','mail','mail2','smtp','imap','pop','pop3','webmail','email','mx','mx1','mx2',
    // API / Application
    'api','api2','api3','apiv1','apiv2','app','app2','application','apps','gateway','gw',
    // Dev / Staging environments
    'dev','dev2','dev3','staging','stage','stg','test','test2','uat','qa','qa2','demo',
    'beta','alpha','preprod','pre-prod','prod','production','release','sandbox','lab',
    // Admin / Management
    'admin','administrator','portal','dashboard','manage','management','console','panel',
    'control','cpanel','whm','webadmin','sysadmin',
    // Infrastructure
    'cdn','static','assets','img','images','media','upload','uploads','files','file',
    'storage','bucket','blob','data','download','downloads',
    // Database / Cache
    'db','db2','database','mysql','postgres','postgresql','mongodb','redis','memcache',
    'elastic','elasticsearch','solr','cassandra',
    // Monitoring / Logging
    'monitoring','monitor','metrics','kibana','grafana','prometheus','logs','log',
    'logging','splunk','datadog','newrelic','apm','tracing',
    // CI/CD / Dev Tools
    'jenkins','gitlab','github','bitbucket','git','svn','ci','cd','deploy','build',
    'jira','confluence','wiki','docs','documentation','artifactory','nexus','sonar',
    // Auth / SSO
    'login','auth','sso','oauth','oidc','idp','identity','accounts','account','register',
    // Support / Customer
    'support','help','helpdesk','ticket','tickets','service','servicedesk','status',
    'statuspage','uptime','feedback',
    // Networking
    'vpn','remote','citrix','rdp','jump','bastion','ssh','proxy','firewall','router',
    'switch','gateway','nat','loadbalancer','lb',
    // Cloud / Container
    'k8s','kubernetes','docker','registry','harbor','rancher','nomad','vault','consul',
    // Communication
    'chat','slack','teams','meet','video','conference','ftp','sftp','transfer',
    // Old / Backup
    'old','legacy','archive','backup','bak','tmp','temp',
    // Misc common
    'internal','intranet','extranet','corp','corporate','secure','private','public',
    'home','host','server','web','site','www-dev','www-staging','m','mobile','wap',
    'ns1','ns2','ns3','dns','dns1','dns2',
  ];
  await onLog(`[${ts()}] DNS brute-forcing ${COMMON_SUBS.length} common subdomains...`);
  let bruteFound = 0;
  const results = await Promise.allSettled(
    COMMON_SUBS.map(async (sub) => {
      const fqdn = `${sub}.${rootDomain}`;
      if (subs.includes(fqdn)) return null;
      try {
        const addrs = await dnsResolve.resolve4(fqdn).catch(() => [] as string[]);
        if (addrs.length > 0) return { fqdn, ips: addrs };
        return null;
      } catch {
        return null;
      }
    }),
  );
  const bruteResults: { fqdn: string; ips: string[] }[] = [];
  for (const r of results) {
    if (r.status === 'fulfilled' && r.value) {
      bruteResults.push(r.value);
      bruteFound++;
      if (!subs.includes(r.value.fqdn)) subs.push(r.value.fqdn);
    }
  }
  if (bruteFound > 0) {
    await onLog(`[${ts()}] DNS brute-force found ${bruteFound} additional subdomain(s)`);
    const devSubs = bruteResults.filter((r) =>
      /dev|staging|test|qa|uat|admin|internal/i.test(r.fqdn),
    );
    if (devSubs.length > 0) {
      findings.push({
        title: `Development/Staging Subdomains Accessible (${devSubs.length} found)`,
        severity: 'medium',
        cvss: 6.1,
        cve: null,
        description: `${devSubs.length} dev/staging subdomains are publicly accessible.`,
        evidence: `DNS brute-force:\n${devSubs.map((r) => `${r.fqdn} → ${r.ips.join(', ')}`).join('\n')}`,
        remediation: 'Restrict access via IP allowlisting or VPN.',
      });
    }
  }
  return { subs, findings };
}

const TAKEOVER_FINGERPRINTS: Array<{ service: string; cnamePattern: RegExp; indicator: string }> = [
  { service: 'GitHub Pages', cnamePattern: /github\.io$/i, indicator: "there isn't a github pages site here" },
  { service: 'Heroku', cnamePattern: /herokudns\.com$/i, indicator: 'no such app' },
  { service: 'AWS S3', cnamePattern: /s3\.amazonaws\.com$/i, indicator: 'nosuchbucket' },
  { service: 'AWS CloudFront', cnamePattern: /cloudfront\.net$/i, indicator: 'the request could not be satisfied' },
  { service: 'Azure Web Apps', cnamePattern: /azurewebsites\.net$/i, indicator: '404 web site not found' },
  { service: 'Netlify', cnamePattern: /netlify\.app$/i, indicator: 'not found - request id' },
];

export async function checkSubdomainTakeover(
  subdomains: string[],
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  if (subdomains.length === 0) return findings;
  const toCheck = subdomains.slice(0, 40);
  await onLog(`[${ts()}] Checking ${toCheck.length} subdomains for takeover...`);
  await Promise.allSettled(
    toCheck.map(async (sub) => {
      try {
        const { stdout } = await execFileAsync('dig', ['+short', '+timeout=3', sub, 'CNAME'], { timeout: 8_000 });
        const cname = stdout.trim().replace(/\.$/, '');
        if (!cname || cname.length < 4) return;
        const fp = TAKEOVER_FINGERPRINTS.find((f) => f.cnamePattern.test(cname));
        if (!fp) return;
        const r = await probe(`https://${sub}`, { timeoutMs: 8_000 });
        const httpR = !r ? await probe(`http://${sub}`, { timeoutMs: 8_000 }) : null;
        const body = (r?.body ?? httpR?.body ?? '').toLowerCase();
        if (body.includes(fp.indicator)) {
          findings.push({
            title: `Subdomain Takeover: ${sub} → ${fp.service}`,
            severity: 'critical',
            verification: 'verified',
            confidence: 96,
            cvss: 9.8,
            cve: null,
            description: `${sub} has dangling CNAME to ${cname} (${fp.service}).`,
            evidence: `CNAME: ${sub} → ${cname}\nService: ${fp.service}\nIndicator: "${fp.indicator}"`,
            remediation: `Remove CNAME or register the resource on ${fp.service}.`,
          });
          await onLog(`[${ts()}] ⚠ SUBDOMAIN TAKEOVER: ${sub} → ${fp.service}`);
        }
      } catch {}
    }),
  );
  return findings;
}
