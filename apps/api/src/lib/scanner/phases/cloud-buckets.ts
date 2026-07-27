/**
 * Phase 11e — Cloud Bucket Enumeration (reconFTW-style)
 *
 * Generates permutations of bucket names from the target domain and checks
 * S3, GCS, and Azure Blob Storage for public read/list access.
 */

import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

function generateBucketNames(hostname: string): string[] {
  // Extract domain parts: example.com → ['example', 'com']
  const parts = hostname.replace(/^www\./, '').split('.');
  const base = parts[0];
  const rootDomain = parts.slice(0, -1).join('-'); // e.g. 'sub-example'
  const domainNoDot = parts.slice(0, -1).join(''); // e.g. 'example'

  const prefixes = [
    '', 'www-', 'dev-', 'staging-', 'prod-', 'test-', 'backup-', 'bak-', 'old-',
    'static-', 'assets-', 'cdn-', 'media-', 'uploads-', 'files-', 'data-',
    'logs-', 'log-', 'archive-', 'public-', 'private-', 'internal-',
    'api-', 'app-', 'web-', 'mail-', 'img-', 'images-', 'storage-',
  ];
  const suffixes = [
    '', '-dev', '-staging', '-prod', '-test', '-backup', '-bak', '-old',
    '-static', '-assets', '-cdn', '-media', '-uploads', '-files', '-data',
    '-logs', '-archive', '-public', '-private', '-internal', '-api', '-app',
    '-web', '-storage', '-bucket', '-store', '-s3',
  ];

  const candidates = new Set<string>();
  const bases = [base, rootDomain, domainNoDot, hostname.replace(/\./g, '-')].filter(Boolean);

  for (const b of bases) {
    for (const pre of prefixes) {
      for (const suf of suffixes) {
        const name = `${pre}${b}${suf}`.toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
        if (name.length >= 3 && name.length <= 63) candidates.add(name);
      }
    }
  }

  return [...candidates].slice(0, 100);
}

interface BucketFinding {
  provider: string;
  bucketName: string;
  url: string;
  isPublic: boolean;
  isList: boolean;
  evidence: string;
}

async function checkS3Bucket(
  bucketName: string,
  onLog: LogFn,
): Promise<BucketFinding | null> {
  const regions = ['', 'us-east-1.', 'us-west-2.', 'eu-west-1.'];
  for (const region of regions) {
    const url = `https://${bucketName}.s3.${region}amazonaws.com/`;
    const result = await probe(url, { timeoutMs: 8_000, skipAuth: true });
    if (!result) continue;

    if (result.status === 403) {
      // Bucket exists but is private — interesting finding
      return {
        provider: 'AWS S3',
        bucketName,
        url,
        isPublic: false,
        isList: false,
        evidence: `HTTP 403 — bucket "${bucketName}" exists but access is denied. Bucket enumeration confirmed.`,
      };
    }

    if (result.status === 200) {
      const isList = /<ListBucketResult/i.test(result.body);
      return {
        provider: 'AWS S3',
        bucketName,
        url,
        isPublic: true,
        isList,
        evidence: isList
          ? `HTTP 200 with ListBucketResult XML — bucket "${bucketName}" is publicly listable.\n${result.body.slice(0, 800)}`
          : `HTTP 200 — bucket "${bucketName}" is publicly accessible.\n${result.body.slice(0, 400)}`,
      };
    }
  }
  return null;
}

async function checkGCSBucket(bucketName: string): Promise<BucketFinding | null> {
  const url = `https://storage.googleapis.com/${bucketName}/`;
  const result = await probe(url, { timeoutMs: 8_000, skipAuth: true });
  if (!result) return null;

  if (result.status === 403) {
    return {
      provider: 'Google Cloud Storage',
      bucketName,
      url,
      isPublic: false,
      isList: false,
      evidence: `HTTP 403 — GCS bucket "${bucketName}" exists but is private.`,
    };
  }

  if (result.status === 200) {
    const isList = result.body.includes('"kind": "storage#objects"') || result.body.includes('<ListBucketResult');
    return {
      provider: 'Google Cloud Storage',
      bucketName,
      url,
      isPublic: true,
      isList,
      evidence: `HTTP 200 — GCS bucket "${bucketName}" is publicly accessible.\n${result.body.slice(0, 500)}`,
    };
  }
  return null;
}

async function checkAzureBlob(
  accountName: string,
  containerName: string,
): Promise<BucketFinding | null> {
  const url = `https://${accountName}.blob.core.windows.net/${containerName}?restype=container&comp=list`;
  const result = await probe(url, { timeoutMs: 8_000, skipAuth: true });
  if (!result) return null;

  if (result.status === 200 && result.body.includes('<EnumerationResults')) {
    return {
      provider: 'Azure Blob Storage',
      bucketName: `${accountName}/${containerName}`,
      url,
      isPublic: true,
      isList: true,
      evidence: `HTTP 200 — Azure Blob container "${accountName}/${containerName}" is publicly listable.\n${result.body.slice(0, 500)}`,
    };
  }
  return null;
}

export async function checkCloudBuckets(
  target: Target,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const bucketNames = generateBucketNames(target.hostname);

  await onLog(`[${ts()}] Cloud bucket enumeration: testing ${bucketNames.length} name permutations across S3/GCS/Azure...`);

  const publicBuckets: BucketFinding[] = [];
  const privateBuckets: BucketFinding[] = [];

  // Check S3 in batches
  const BATCH = 10;
  for (let i = 0; i < bucketNames.length; i += BATCH) {
    const batch = bucketNames.slice(i, i + BATCH);
    const results = await Promise.allSettled([
      ...batch.map((name) => checkS3Bucket(name, onLog)),
      // GCS for first 30 candidates
      ...(i < 30 ? batch.map((name) => checkGCSBucket(name)) : []),
      // Azure for first 20 (try as account+container)
      ...(i < 20 ? batch.map((name) => checkAzureBlob(name, name)) : []),
    ]);

    for (const r of results) {
      if (r.status === 'fulfilled' && r.value) {
        if (r.value.isPublic) publicBuckets.push(r.value);
        else privateBuckets.push(r.value);
      }
    }
  }

  await onLog(
    `[${ts()}] Cloud bucket scan: ${publicBuckets.length} public, ${privateBuckets.length} private/existing buckets found`,
  );

  // Public (listable/readable) — critical
  for (const bucket of publicBuckets.filter((b) => b.isList)) {
    findings.push({
      title: `Public Cloud Bucket (Listable): ${bucket.provider} — ${bucket.bucketName}`,
      severity: 'critical',
      cvss: 9.8,
      cve: null,
      verified: true,
      verification: 'verified',
      confidence: 97,
      affectedEndpoint: bucket.url,
      description:
        `A ${bucket.provider} bucket named "${bucket.bucketName}" is publicly listable. ` +
        'An attacker can enumerate all stored objects and potentially download sensitive files including backups, credentials, and source code.',
      evidence: bucket.evidence,
      remediation:
        'Immediately restrict bucket access. Apply a private ACL or bucket policy. ' +
        'Audit the bucket contents for sensitive data. Enable S3 Block Public Access settings.',
      compliance: {
        owasp: ['A01:2021 – Broken Access Control'],
        pci: ['PCI DSS 6.4.2', 'PCI DSS 7.2'],
        nist: ['NIST AC-3', 'NIST SC-28'],
      },
    });
    await onLog(`[${ts()}] ⚠ CRITICAL: ${bucket.provider} bucket ${bucket.bucketName} is publicly listable!`);
  }

  // Public (readable, not listed)
  for (const bucket of publicBuckets.filter((b) => !b.isList)) {
    findings.push({
      title: `Public Cloud Bucket (Readable): ${bucket.provider} — ${bucket.bucketName}`,
      severity: 'high',
      cvss: 7.5,
      cve: null,
      verified: true,
      verification: 'verified',
      confidence: 90,
      affectedEndpoint: bucket.url,
      description:
        `A ${bucket.provider} bucket named "${bucket.bucketName}" is publicly accessible. ` +
        'Objects may be downloadable without authentication.',
      evidence: bucket.evidence,
      remediation: 'Apply private ACL or bucket policy. Enable Block Public Access. Audit stored objects.',
      compliance: {
        owasp: ['A01:2021 – Broken Access Control'],
      },
    });
  }

  // Private (confirmed to exist via 403) — medium (bucket enumeration)
  if (privateBuckets.length > 0) {
    findings.push({
      title: `${privateBuckets.length} Cloud Bucket(s) Enumerated (Private)`,
      severity: 'medium',
      cvss: 5.3,
      cve: null,
      verification: 'verified',
      confidence: 88,
      description:
        `${privateBuckets.length} cloud storage bucket(s) associated with "${target.hostname}" were enumerated (HTTP 403). ` +
        'While currently private, the bucket names are predictable from the domain. Bucket enumeration enables targeted attacks.',
      evidence:
        `Confirmed private buckets:\n` +
        privateBuckets.slice(0, 15).map((b) => `  ${b.provider}: ${b.bucketName} — ${b.url}`).join('\n'),
      remediation:
        'Use random, unguessable bucket names. Enable S3 Block Public Access. ' +
        'Monitor for bucket policy changes. Consider enabling S3 Object Lock.',
    });
  }

  return findings;
}
