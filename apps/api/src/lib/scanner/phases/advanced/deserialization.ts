import { ts } from '../../context';
import { probe } from '../../utils/http';
import type { RealFinding, Target, LogFn } from '../../context';

// Java serialisation magic bytes: 0xaced0005
const JAVA_MAGIC = Buffer.from([0xac, 0xed, 0x00, 0x05]);

export async function checkDeserialization(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Scanning for deserialization surface (Java, PHP, Python)...`);

  const endpoints = [
    target.url,
    `${target.url.replace(/\/$/, '')}/api`,
    `${target.url.replace(/\/$/, '')}/api/v1`,
    `${target.url.replace(/\/$/, '')}/rpc`,
    `${target.url.replace(/\/$/, '')}/invoke`,
    `${target.url.replace(/\/$/, '')}/service`,
    `${target.url.replace(/\/$/, '')}/ws`,
  ];

  // Check if any endpoint returns Java serialisation magic bytes
  for (const ep of endpoints) {
    const r = await probe(ep, { timeoutMs: 8_000 });
    if (!r) continue;
    const bodyBuffer = Buffer.from(r.body, 'binary');
    if (bodyBuffer.subarray(0, 4).equals(JAVA_MAGIC)) {
      findings.push({
        title: 'Java Serialized Object Returned in Response',
        severity: 'high',
        verification: 'verified',
        confidence: 92,
        cvss: 8.1,
        cve: null,
        description: `The endpoint ${ep} returned Java serialized object bytes (magic: 0xaced0005).`,
        evidence: `GET ${ep} → HTTP ${r.status}\nBody starts with: 0xaced0005`,
        remediation: 'Replace Java serialisation with JSON. If needed, use signed serialisation.',
      });
      await onLog(`[${ts()}] ⚠ Java serialisation surface detected at ${ep}`);
    }
    // PHP unserialise surface
    const ct = r.headers['content-type'] ?? '';
    if (ct.includes('application/x-php-serialized') || r.body.startsWith('O:') || /^a:\d+:\{/.test(r.body)) {
      findings.push({
        title: 'PHP Serialized Object Exposure',
        severity: 'high',
        verification: 'suspected',
        confidence: 75,
        cvss: 8.1,
        cve: null,
        description: `PHP serialized object detected in response from ${ep}.`,
        evidence: `GET ${ep} → HTTP ${r.status}\nContent-Type: ${ct}\nBody preview: ${r.body.slice(0, 100)}`,
        remediation: 'Use JSON for data exchange instead of PHP serialise().',
      });
      await onLog(`[${ts()}] ⚠ PHP serialisation surface at ${ep}`);
    }
    // Python pickle: always starts with 0x80 0x0x
    if (r.body.length > 0 && r.body.charCodeAt(0) === 0x80 && [0x02, 0x03, 0x04, 0x05].includes(r.body.charCodeAt(1))) {
      findings.push({
        title: 'Python Pickle Serialized Object Exposure',
        severity: 'critical',
        verification: 'suspected',
        confidence: 80,
        cvss: 9.8,
        cve: null,
        description: `Python pickle serialized data detected at ${ep}.`,
        evidence: `GET ${ep} → HTTP ${r.status}\nBody starts with pickle magic bytes`,
        remediation: 'Never use pickle for untrusted input. Use JSON.',
      });
      await onLog(`[${ts()}] ⚠ Python pickle surface at ${ep}`);
    }
  }

  // Send Java serialisation payload and check for errors that indicate processing
  const base64Aced = JAVA_MAGIC.toString('base64');
  const testPayload = `${base64Aced}AAAAAAAAAAAAAAAAAAA=`; // truncated — causes parse error
  for (const ep of endpoints.slice(0, 3)) {
    const r = await probe(ep, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-java-serialized-object' },
      body: testPayload,
      timeoutMs: 8_000,
    });
    if (!r) continue;
    const body = r.body.toLowerCase();
    if (body.includes('classnotfound') || body.includes('streamcorruptedexception') || body.includes('deserializ') || body.includes('readobject')) {
      findings.push({
        title: 'Java Deserialization Endpoint Detected (Error Response)',
        severity: 'high',
        verification: 'suspected',
        confidence: 70,
        cvss: 8.1,
        cve: null,
        description: `Posting a truncated Java serialized object to ${ep} returned a deserialization error, indicating the endpoint processes Java objects.`,
        evidence: `POST ${ep}\nContent-Type: application/x-java-serialized-object\nHTTP ${r.status}\nError keywords: ${body.slice(0, 300)}`,
        remediation: 'Use serialisation filters (ObjectInputFilter), update Apache Commons Collections.',
      });
      await onLog(`[${ts()}] ⚠ Java deserialization endpoint at ${ep}`);
      break;
    }
  }

  return findings;
}
