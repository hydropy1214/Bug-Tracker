import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

const SENSITIVE_PATHS: { path: string; deep?: boolean; finding: Omit<RealFinding, 'evidence'> }[] = [
  { path: '/.env', finding: { title: '.env File Exposed', severity: 'critical', cvss: 9.8, cve: null, description: 'The .env file is publicly accessible.', remediation: 'Block access to .env files.' } },
  { path: '/.git/config', finding: { title: 'Git Repository Exposed (.git/config)', severity: 'critical', cvss: 9.8, cve: null, description: '.git directory is accessible.', remediation: 'Block /.git/ access.' } },
  { path: '/robots.txt', finding: { title: 'robots.txt Reveals Internal Paths', severity: 'low', cvss: 3.1, cve: null, description: 'robots.txt is accessible.', remediation: 'Review for sensitive paths.' } },
  { path: '/phpinfo.php', finding: { title: 'PHP Info Page Exposed', severity: 'high', cvss: 7.5, cve: null, description: 'phpinfo() output publicly accessible.', remediation: 'Delete phpinfo.php.' } },
  { path: '/wp-login.php', finding: { title: 'WordPress Admin Login Exposed', severity: 'medium', cvss: 5.3, cve: null, description: 'WordPress login publicly accessible.', remediation: 'Rename wp-login.php, add IP restrictions.' } },
  { path: '/.env.local', finding: { title: '.env.local File Exposed', severity: 'critical', cvss: 9.8, cve: null, description: '.env.local publicly accessible.', remediation: 'Block all .env* files.' } },
  { path: '/.env.production', finding: { title: '.env.production Exposed', severity: 'critical', cvss: 9.8, cve: null, description: 'Production environment file exposed.', remediation: 'Block .env* files.' } },
  { path: '/.git/HEAD', finding: { title: 'Git Repository HEAD Exposed', severity: 'critical', cvss: 9.8, cve: null, description: '.git directory accessible.', remediation: 'Block /.git/ access.' } },
  { path: '/backup.sql', finding: { title: 'Database Backup Exposed (backup.sql)', severity: 'critical', cvss: 9.8, cve: null, description: 'SQL backup publicly downloadable.', remediation: 'Remove backup files from web root.' } },
  { path: '/dump.sql', finding: { title: 'Database Dump Exposed (dump.sql)', severity: 'critical', cvss: 9.8, cve: null, description: 'SQL dump publicly accessible.', remediation: 'Remove dump files.' } },
  { path: '/adminer.php', finding: { title: 'Adminer Database UI Exposed', severity: 'critical', cvss: 9.8, cve: null, description: 'Adminer is publicly accessible.', remediation: 'Remove Adminer from production.' } },
  { path: '/phpmyadmin/', finding: { title: 'phpMyAdmin Exposed', severity: 'high', cvss: 8.1, cve: null, description: 'phpMyAdmin publicly accessible.', remediation: 'Restrict to internal IPs.' } },
  { path: '/.DS_Store', finding: { title: '.DS_Store File Exposed', severity: 'medium', cvss: 5.3, cve: null, description: 'macOS .DS_Store exposed.', remediation: 'Block .DS_Store files.' } },
  { path: '/.htpasswd', finding: { title: '.htpasswd File Exposed', severity: 'critical', cvss: 9.8, cve: null, description: '.htpasswd credential file publicly readable.', remediation: 'Block .htpasswd.' } },
  { path: '/config.php', finding: { title: 'config.php Exposed', severity: 'high', cvss: 7.5, cve: null, description: 'Configuration file may contain credentials.', remediation: 'Move config outside web root.' } },
  { path: '/.well-known/security.txt', finding: { title: 'security.txt Present (Informational)', severity: 'low', cvss: 0, cve: null, description: 'RFC 9116 security.txt found.', remediation: 'Keep up-to-date.', verification: 'informational', confidence: 99 } },
  { path: '/api/v1/', finding: { title: 'API v1 Endpoint Accessible', severity: 'low', cvss: 3.1, cve: null, description: 'API endpoint discovered.', remediation: 'Ensure proper authentication.' } },
  { path: '/graphql', finding: { title: 'GraphQL Endpoint Exposed', severity: 'medium', cvss: 5.3, cve: null, description: 'GraphQL endpoint publicly accessible.', remediation: 'Disable introspection, require auth.' } },
  { path: '/crossdomain.xml', finding: { title: 'crossdomain.xml Present', severity: 'low', cvss: 3.1, cve: null, description: 'Flash crossdomain.xml found.', remediation: 'Remove if Flash not used.' } },
  { path: '/.aws/credentials', finding: { title: 'AWS Credentials File Exposed', severity: 'critical', cvss: 10.0, cve: null, description: 'AWS credentials publicly accessible.', remediation: 'Remove and revoke keys.' } },
  { path: '/id_rsa', finding: { title: 'SSH Private Key Exposed (id_rsa)', severity: 'critical', cvss: 10.0, cve: null, description: 'SSH private key publicly accessible.', remediation: 'Remove and rotate key pair.' } },
  // Extended paths — reconFTW coverage
  { path: '/.env.bak', finding: { title: '.env.bak Backup File Exposed', severity: 'critical', cvss: 9.8, cve: null, description: '.env.bak backup file is publicly accessible, likely containing credentials.', remediation: 'Remove all .env* files from the web root.' } },
  { path: '/.env.save', finding: { title: '.env.save File Exposed', severity: 'critical', cvss: 9.8, cve: null, description: '.env.save is publicly accessible.', remediation: 'Remove backup environment files.' } },
  { path: '/config.js', finding: { title: 'config.js Exposed', severity: 'high', cvss: 7.5, cve: null, description: 'JavaScript configuration file may contain hardcoded API keys.', remediation: 'Remove or restrict config.js. Move secrets to server-side.' } },
  { path: '/config.json', finding: { title: 'config.json Exposed', severity: 'high', cvss: 7.5, cve: null, description: 'JSON configuration file may contain credentials or internal endpoints.', remediation: 'Remove config.json from web root.' } },
  { path: '/settings.py', finding: { title: 'Django settings.py Exposed', severity: 'critical', cvss: 9.8, cve: null, description: 'Django settings file exposing SECRET_KEY and database credentials.', remediation: 'Block access to .py files. Move settings outside web root.' } },
  { path: '/wp-config.php', finding: { title: 'WordPress wp-config.php Exposed', severity: 'critical', cvss: 9.8, cve: null, description: 'WordPress configuration file contains database credentials.', remediation: 'Move wp-config.php above web root.' } },
  { path: '/wp-config.php.bak', finding: { title: 'wp-config.php.bak Backup Exposed', severity: 'critical', cvss: 9.8, cve: null, description: 'WordPress config backup is publicly accessible.', remediation: 'Delete backup configuration files.' } },
  { path: '/application.properties', finding: { title: 'Spring application.properties Exposed', severity: 'critical', cvss: 9.8, cve: null, description: 'Spring Boot application.properties may contain DB credentials and secrets.', remediation: 'Block access to .properties files.' } },
  { path: '/application.yml', finding: { title: 'Spring application.yml Exposed', severity: 'critical', cvss: 9.8, cve: null, description: 'Spring Boot application.yml may contain secrets.', remediation: 'Block access to .yml config files.' } },
  { path: '/docker-compose.yml', finding: { title: 'docker-compose.yml Exposed', severity: 'high', cvss: 7.5, cve: null, description: 'Docker Compose file reveals infrastructure and may contain credentials.', remediation: 'Block access to docker-compose.yml.' } },
  { path: '/.dockerenv', finding: { title: 'Running in Docker Container (Information Disclosure)', severity: 'low', cvss: 3.1, cve: null, description: '.dockerenv file indicates application runs in Docker.', remediation: 'Informational — confirm Docker security configuration.', verification: 'informational', confidence: 90 } },
  { path: '/Dockerfile', finding: { title: 'Dockerfile Exposed', severity: 'medium', cvss: 5.3, cve: null, description: 'Dockerfile reveals application build process and base image.', remediation: 'Block access to Dockerfile.' } },
  { path: '/.git/logs/HEAD', finding: { title: 'Git Commit Log Exposed', severity: 'critical', cvss: 9.8, cve: null, description: 'Git commit history accessible.', remediation: 'Block /.git/ access entirely.' } },
  { path: '/.svn/entries', finding: { title: 'Subversion Repository Exposed', severity: 'critical', cvss: 9.8, cve: null, description: '.svn directory is accessible.', remediation: 'Block /.svn/ access.' } },
  { path: '/.hg/store', finding: { title: 'Mercurial Repository Exposed', severity: 'critical', cvss: 9.8, cve: null, description: '.hg directory is accessible.', remediation: 'Block /.hg/ access.' } },
  { path: '/server-status', finding: { title: 'Apache server-status Exposed', severity: 'medium', cvss: 5.3, cve: null, description: 'Apache mod_status reveals active connections and request paths.', remediation: 'Restrict /server-status to localhost.' } },
  { path: '/server-info', finding: { title: 'Apache server-info Exposed', severity: 'medium', cvss: 5.3, cve: null, description: 'Apache mod_info reveals detailed server configuration.', remediation: 'Disable mod_info or restrict access.' } },
  { path: '/.well-known/acme-challenge/', finding: { title: 'ACME Challenge Directory Accessible', severity: 'low', cvss: 2.1, cve: null, description: 'ACME challenge directory is browsable.', remediation: 'Informational — ensure no sensitive files are placed here.', verification: 'informational', confidence: 90 } },
  { path: '/trace.axd', finding: { title: 'ASP.NET Trace Viewer Exposed', severity: 'high', cvss: 7.5, cve: null, description: 'ASP.NET trace.axd exposes request/response details.', remediation: 'Disable tracing in production web.config.' } },
  { path: '/elmah.axd', finding: { title: 'ELMAH Error Log Exposed', severity: 'high', cvss: 7.5, cve: null, description: 'ELMAH error log viewer publicly accessible, revealing stack traces.', remediation: 'Add authentication to elmah.axd.' } },
  { path: '/actuator/env', finding: { title: 'Spring Actuator /env Exposed', severity: 'critical', cvss: 9.8, cve: null, description: 'Spring Boot /actuator/env exposes environment variables and credentials.', remediation: 'Disable /actuator/env in production or require authentication.' } },
  { path: '/actuator/heapdump', finding: { title: 'Spring Actuator Heap Dump Exposed', severity: 'critical', cvss: 9.8, cve: null, description: 'Spring Boot heap dump endpoint can expose in-memory secrets.', remediation: 'Disable /actuator/heapdump in production.' } },
  { path: '/actuator/beans', finding: { title: 'Spring Actuator /beans Exposed', severity: 'medium', cvss: 5.3, cve: null, description: 'Spring Boot bean list reveals application structure.', remediation: 'Require authentication for all actuator endpoints.' } },
  { path: '/__debug__/', finding: { title: 'Django Debug Toolbar Exposed', severity: 'high', cvss: 7.5, cve: null, description: 'Django debug interface is publicly accessible.', remediation: 'Disable DEBUG=True in production. Restrict debug toolbar.' } },
  { path: '/telescope', finding: { title: 'Laravel Telescope Exposed', severity: 'high', cvss: 7.5, cve: null, description: 'Laravel Telescope debug panel is publicly accessible.', remediation: 'Add authentication gate to Telescope.' } },
  { path: '/horizon', finding: { title: 'Laravel Horizon Exposed', severity: 'high', cvss: 7.5, cve: null, description: 'Laravel Horizon queue dashboard is publicly accessible.', remediation: 'Add authentication gate to Horizon.' } },
  { path: '/_profiler', finding: { title: 'Symfony Profiler Exposed', severity: 'high', cvss: 7.5, cve: null, description: 'Symfony web profiler reveals request details and configuration.', remediation: 'Disable profiler in production or restrict by IP.' } },
  { path: '/private/', finding: { title: 'Private Directory Accessible', severity: 'medium', cvss: 5.3, cve: null, description: '/private/ directory is publicly accessible.', remediation: 'Move sensitive files outside web root.' } },
  { path: '/backup/', finding: { title: 'Backup Directory Accessible', severity: 'high', cvss: 7.5, cve: null, description: '/backup/ directory is publicly accessible.', remediation: 'Remove backup directories from web root.' } },
  { path: '/old/', finding: { title: 'Old Version Directory Accessible', severity: 'medium', cvss: 5.3, cve: null, description: '/old/ directory contains potentially outdated and vulnerable code.', remediation: 'Remove old version directories.' } },
  { path: '/composer.json', finding: { title: 'composer.json Exposed', severity: 'medium', cvss: 5.3, cve: null, description: 'PHP composer.json reveals dependency versions for CVE targeting.', remediation: 'Block access to composer.json.' } },
  { path: '/composer.lock', finding: { title: 'composer.lock Exposed', severity: 'medium', cvss: 5.3, cve: null, description: 'composer.lock reveals exact dependency versions for CVE targeting.', remediation: 'Block access to composer.lock.' } },
  { path: '/package.json', finding: { title: 'package.json Exposed', severity: 'low', cvss: 3.1, cve: null, description: 'package.json reveals Node.js dependency versions.', remediation: 'Block access to package.json.' } },
  { path: '/Gemfile', finding: { title: 'Gemfile Exposed', severity: 'low', cvss: 3.1, cve: null, description: 'Ruby Gemfile reveals dependency versions.', remediation: 'Block access to Gemfile.' } },
  { path: '/requirements.txt', finding: { title: 'requirements.txt Exposed', severity: 'low', cvss: 3.1, cve: null, description: 'Python requirements.txt reveals dependency versions.', remediation: 'Block access to requirements.txt.' } },
  { path: '/.npmrc', finding: { title: '.npmrc Exposed (Potential Auth Token)', severity: 'critical', cvss: 9.8, cve: null, description: '.npmrc may contain npm authentication tokens for private registries.', remediation: 'Block access to .npmrc files.' } },
  { path: '/.htaccess', finding: { title: '.htaccess File Exposed', severity: 'medium', cvss: 5.3, cve: null, description: '.htaccess reveals server configuration and potentially sensitive rewrite rules.', remediation: 'Block access to .htaccess files.' } },
  { path: '/nginx.conf', finding: { title: 'nginx.conf Exposed', severity: 'medium', cvss: 5.3, cve: null, description: 'Nginx configuration file reveals server structure.', remediation: 'Block access to .conf files.' } },
  { path: '/web.config', finding: { title: 'web.config Exposed', severity: 'high', cvss: 7.5, cve: null, description: 'IIS web.config may contain connection strings and application secrets.', remediation: 'Block access to web.config.' } },
  { path: '/info.php', finding: { title: 'PHP Info Page Exposed (info.php)', severity: 'high', cvss: 7.5, cve: null, description: 'PHP configuration details publicly exposed.', remediation: 'Delete info.php from production.' } },
  { path: '/test.php', finding: { title: 'Test PHP File Exposed', severity: 'medium', cvss: 5.3, cve: null, description: 'Test PHP file should not be on production server.', remediation: 'Remove test files from production.' } },
  { path: '/debug.php', finding: { title: 'Debug PHP File Exposed', severity: 'high', cvss: 7.5, cve: null, description: 'Debug PHP file may expose sensitive information.', remediation: 'Remove debug files from production.' } },
  { path: '/debug', finding: { title: 'Debug Endpoint Exposed', severity: 'high', cvss: 7.5, cve: null, description: 'Debug endpoint is publicly accessible.', remediation: 'Remove or restrict debug endpoints in production.' } },
  { path: '/console', finding: { title: 'Management Console Exposed', severity: 'high', cvss: 8.1, cve: null, description: 'Management console endpoint is publicly accessible.', remediation: 'Restrict console access to internal IPs.' } },
  { path: '/.well-known/openid-configuration', finding: { title: 'OpenID Connect Discovery Endpoint', severity: 'low', cvss: 0, cve: null, description: 'OpenID Connect discovery document revealed.', remediation: 'Informational — review OIDC configuration for misconfigurations.', verification: 'informational', confidence: 99 } },
  { path: '/oauth/.well-known/openid-configuration', finding: { title: 'OAuth/OIDC Configuration Exposed', severity: 'low', cvss: 0, cve: null, description: 'OAuth OIDC configuration document.', remediation: 'Review OIDC configuration.', verification: 'informational', confidence: 99 } },
  { path: '/.ssh/known_hosts', finding: { title: 'SSH known_hosts Exposed', severity: 'medium', cvss: 5.3, cve: null, description: 'SSH known_hosts reveals server fingerprints for network mapping.', remediation: 'Block access to .ssh directory.' } },
  { path: '/authorized_keys', finding: { title: 'SSH authorized_keys Exposed', severity: 'critical', cvss: 9.8, cve: null, description: 'SSH authorized_keys file is publicly accessible.', remediation: 'Remove from web root immediately.' } },
  { path: '/.bash_history', finding: { title: '.bash_history Exposed', severity: 'high', cvss: 7.5, cve: null, description: 'Bash command history may contain credentials and internal commands.', remediation: 'Remove from web root. Restrict shell history files.' } },
  { path: '/sitemap.xml', finding: { title: 'Sitemap.xml Present (Informational)', severity: 'low', cvss: 0, cve: null, description: 'Sitemap.xml found — reveals URL structure.', remediation: 'Review sitemap for unintended URL disclosure.', verification: 'informational', confidence: 99 } },
  { path: '/.gitlab-ci.yml', finding: { title: '.gitlab-ci.yml Exposed', severity: 'medium', cvss: 5.3, cve: null, description: 'CI/CD pipeline configuration reveals build and deploy process.', remediation: 'Block access to CI/CD configuration files.' } },
  { path: '/.travis.yml', finding: { title: '.travis.yml Exposed', severity: 'medium', cvss: 5.3, cve: null, description: 'Travis CI configuration may reveal secrets or build pipeline.', remediation: 'Block access to .travis.yml.' } },
  { path: '/Jenkinsfile', finding: { title: 'Jenkinsfile Exposed', severity: 'medium', cvss: 5.3, cve: null, description: 'Jenkins pipeline configuration reveals CI/CD process.', remediation: 'Block access to Jenkinsfile.' } },
  { path: '/aws.json', finding: { title: 'AWS Credentials JSON Exposed', severity: 'critical', cvss: 10.0, cve: null, description: 'AWS credentials JSON file publicly accessible.', remediation: 'Remove and revoke AWS credentials immediately.' } },
  { path: '/gcloud.json', finding: { title: 'GCP Service Account Key Exposed', severity: 'critical', cvss: 10.0, cve: null, description: 'Google Cloud service account key is publicly accessible.', remediation: 'Remove and revoke GCP service account key immediately.' } },
  { path: '/key.json', finding: { title: 'key.json Exposed (Potential Service Account)', severity: 'critical', cvss: 9.8, cve: null, description: 'JSON key file publicly accessible — may be a cloud service account key.', remediation: 'Remove immediately and audit cloud access.' } },
  { path: '/credentials.json', finding: { title: 'credentials.json Exposed', severity: 'critical', cvss: 9.8, cve: null, description: 'Credentials JSON file publicly accessible.', remediation: 'Remove and rotate credentials.' } },
  { path: '/.token', finding: { title: '.token File Exposed', severity: 'critical', cvss: 9.8, cve: null, description: 'Token file publicly accessible.', remediation: 'Remove token files from web root.' } },
  { path: '/token', finding: { title: 'Token Endpoint Accessible', severity: 'medium', cvss: 5.3, cve: null, description: 'Token endpoint is publicly accessible without authentication.', remediation: 'Require authentication for token endpoints.' } },
  { path: '/feed', finding: { title: 'RSS/Atom Feed (Informational)', severity: 'low', cvss: 0, cve: null, description: 'RSS/Atom feed found.', remediation: 'Review feed for unintended content disclosure.', verification: 'informational', confidence: 90 } },
  { path: '/_next/static/', finding: { title: 'Next.js Static Build Artifacts Accessible', severity: 'low', cvss: 2.1, cve: null, description: 'Next.js build artifacts are publicly accessible.', remediation: 'Review for source map exposure.', verification: 'informational', confidence: 85 } },
  { path: '/__webpack_hmr', finding: { title: 'Webpack HMR Endpoint Exposed (Development Mode)', severity: 'high', cvss: 7.5, cve: null, description: 'Webpack Hot Module Replacement endpoint is running — indicates development mode in production.', remediation: 'Disable HMR in production builds.' } },
  { path: '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', finding: { title: 'PHPUnit eval-stdin RCE Vector', severity: 'critical', cvss: 10.0, cve: 'CVE-2017-9841', description: 'CVE-2017-9841: PHPUnit eval-stdin.php allows remote code execution.', remediation: 'Remove vendor/phpunit from production. Update PHPUnit.' } },
  { path: '/vendor/autoload.php', finding: { title: 'Composer Vendor Directory Exposed', severity: 'high', cvss: 7.5, cve: null, description: 'PHP vendor directory is publicly accessible, potentially exposing vulnerable libraries.', remediation: 'Block web access to /vendor/ directory.' } },
  { path: '/api/swagger.json', finding: { title: 'Swagger API Spec Exposed (swagger.json)', severity: 'medium', cvss: 5.3, cve: null, description: 'Swagger API specification reveals all endpoints and parameters.', remediation: 'Restrict API spec access or require authentication.' } },
  { path: '/v2/api-docs', finding: { title: 'Swagger v2 API Docs Exposed', severity: 'medium', cvss: 5.3, cve: null, description: 'Spring Boot Swagger v2 API documentation is publicly accessible.', remediation: 'Restrict /v2/api-docs in production.' } },
  { path: '/openapi.json', finding: { title: 'OpenAPI Spec Exposed', severity: 'medium', cvss: 5.3, cve: null, description: 'OpenAPI specification reveals API structure and endpoints.', remediation: 'Require authentication for API documentation.' } },
];

const contentMarkers: Record<string, RegExp> = {
  '/.env': /(?:^|\n)\s*[A-Z][A-Z0-9_]{2,}\s*=/,
  '/.git/config': /^\s*(?:\[core\]|repositoryformatversion|ref:)/im,
  '/.git/HEAD': /^\s*ref:\s+refs\//im,
  '/backup.sql': /(create\s+table|insert\s+into|--\s*(?:mysql|postgres|sql))/i,
  '/phpinfo.php': /(php version|phpinfo\(\)|configuration file)/i,
  '/wp-login.php': /(wp-login|user_login|wordpress)/i,
  '/robots.txt': /(?:^|\n)\s*(?:user-agent|disallow|sitemap)\s*:/i,
};

export async function checkSensitivePaths(
  target: Target,
  deep: boolean,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const paths = SENSITIVE_PATHS.filter((p) => !p.deep || deep);
  await onLog(`[${ts()}] Probing ${paths.length} sensitive paths...`);
  const BATCH = 12;
  const findings: RealFinding[] = [];
  const notFoundUrl = `${target.url.replace(/\/$/, '')}/sentinelx-not-found-${Date.now()}`;
  const notFound = await probe(notFoundUrl, { timeoutMs: 8_000 });
  const compact = (value: string) => value.replace(/\s+/g, ' ').trim().slice(0, 4_000);

  for (let i = 0; i < paths.length; i += BATCH) {
    const batch = paths.slice(i, i + BATCH);
    const results = await Promise.allSettled(
      batch.map(async ({ path, finding }) => {
        const url = target.url.replace(/\/$/, '') + path;
        const result = await probe(url, { timeoutMs: 8_000 });
        if (!result || result.status !== 200) return null;
        const resultBody = compact(result.body);
        const baselineBody = notFound ? compact(notFound.body) : '';
        if (notFound && result.status === notFound.status && resultBody === baselineBody) return null;
        const marker = contentMarkers[path];
        if (marker && !marker.test(result.body)) return null;
        if (!marker && resultBody.toLowerCase().includes('404') && result.body.length < 2_000) return null;
        const snippet = result.body.slice(0, 300).replace(/\s+/g, ' ').trim();
        return {
          ...finding,
          evidence: `GET ${url} → HTTP ${result.status} (${result.durationMs}ms)\nContent-Type: ${result.headers['content-type'] ?? 'unknown'}\nBody preview: ${snippet || '(empty)'}`,
        } as RealFinding;
      }),
    );
    for (const r of results) {
      if (r.status === 'fulfilled' && r.value) {
        findings.push(r.value);
        await onLog(`[${ts()}] FOUND: ${r.value.title}`);
      }
    }
  }
  await onLog(`[${ts()}] Path discovery: ${findings.length} exposure(s) found`);
  return findings;
}
