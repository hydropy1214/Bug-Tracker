import type { HttpProbeOptions } from '../utils/http';
import { probe } from '../utils/http';
import type { LogFn, ScanPolicy, Target } from '../context';
import { ts } from '../context';

export type SurfaceMethod = 'GET' | 'POST' | 'PUT' | 'PATCH';

export interface SurfaceParameter {
  endpoint: string;
  parameter: string;
  method: SurfaceMethod;
  source: 'query' | 'form' | 'script' | 'sitemap';
  sampleValue?: string;
  contentType?: string;
  fields?: Record<string, string>;
}

export interface SurfaceEndpoint {
  url: string;
  method: SurfaceMethod;
  source: SurfaceParameter['source'];
  parameters: string[];
}

export interface SurfaceInventory {
  endpoints: SurfaceEndpoint[];
  parameters: SurfaceParameter[];
  crawled: string[];
  forms: number;
  truncated: boolean;
}

const MAX_CRAWL_PAGES = 24;
const MAX_DISCOVERED_ENDPOINTS = 80;
const MAX_PARAMETERS = 160;
const SKIP_EXTENSIONS = /\.(?:css|gif|ico|jpe?g|png|svg|woff2?|ttf|map|mp[34]|pdf|zip)$/i;

function decodeHtml(value: string): string {
  return value
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#x27;|&#39;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>');
}

function sameOrigin(value: string, target: Target | string): URL | null {
  try {
    const base = typeof target === 'string' ? target : target.url;
    const url = new URL(value, base);
    const targetUrl = new URL(typeof target === 'string' ? target : target.url);
    if (url.origin !== targetUrl.origin || !/^https?:$/i.test(url.protocol)) return null;
    url.hash = '';
    return url;
  } catch {
    return null;
  }
}

function shouldCrawl(url: URL): boolean {
  return !SKIP_EXTENSIONS.test(url.pathname) && !/\/(?:logout|signout)(?:\/|$)/i.test(url.pathname);
}

function addQueryParameters(
  url: URL,
  source: SurfaceParameter['source'],
  inventory: SurfaceInventory,
): void {
  for (const [parameter, sampleValue] of url.searchParams.entries()) {
    if (!parameter || inventory.parameters.length >= MAX_PARAMETERS) break;
    inventory.parameters.push({
      endpoint: `${url.origin}${url.pathname}`,
      parameter,
      method: 'GET',
      source,
      sampleValue,
    });
  }
}

function addEndpoint(inventory: SurfaceInventory, endpoint: SurfaceEndpoint): void {
  if (inventory.endpoints.length >= MAX_DISCOVERED_ENDPOINTS) {
    inventory.truncated = true;
    return;
  }
  const key = `${endpoint.method}:${endpoint.url}`;
  if (inventory.endpoints.some((item) => `${item.method}:${item.url}` === key)) return;
  inventory.endpoints.push(endpoint);
}

function addParameter(inventory: SurfaceInventory, parameter: SurfaceParameter): void {
  if (inventory.parameters.length >= MAX_PARAMETERS) {
    inventory.truncated = true;
    return;
  }
  const key = `${parameter.method}:${parameter.endpoint}:${parameter.parameter}`;
  if (
    inventory.parameters.some(
      (item) => `${item.method}:${item.endpoint}:${item.parameter}` === key,
    )
  )
    return;
  inventory.parameters.push(parameter);
}

function parseAttributes(tag: string): Record<string, string> {
  const attributes: Record<string, string> = {};
  const attributeRe = /([:\w-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;
  let match: RegExpExecArray | null;
  while ((match = attributeRe.exec(tag)) !== null) {
    attributes[match[1]!.toLowerCase()] = decodeHtml(match[2] ?? match[3] ?? match[4] ?? '');
  }
  return attributes;
}

function parseForms(
  html: string,
  pageUrl: URL,
  inventory: SurfaceInventory,
): void {
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let formMatch: RegExpExecArray | null;
  while ((formMatch = formRe.exec(html)) !== null) {
    const formAttrs = parseAttributes(formMatch[1] ?? '');
    const action = sameOrigin(formAttrs.action || pageUrl.href, {
      url: pageUrl.href,
      hostname: pageUrl.hostname,
      port: Number(pageUrl.port) || (pageUrl.protocol === 'https:' ? 443 : 80),
      isHttps: pageUrl.protocol === 'https:',
      assetType: 'url',
    });
    if (!action) continue;

    const method = (formAttrs.method ?? 'GET').toUpperCase();
    if (!['GET', 'POST', 'PUT', 'PATCH'].includes(method)) continue;
    const fields: Record<string, string> = {};
    const inputRe = /<(?:input|textarea|select)\b[^>]*>/gi;
    let inputMatch: RegExpExecArray | null;
    while ((inputMatch = inputRe.exec(formMatch[2] ?? '')) !== null) {
      const attrs = parseAttributes(inputMatch[0]);
      const name = attrs.name?.trim();
      if (!name || attrs.disabled !== undefined) continue;
      fields[name] = attrs.value ?? '';
    }
    const parameters = Object.keys(fields);
    if (parameters.length === 0) continue;

    inventory.forms++;
    const endpoint = action.origin + action.pathname;
    addEndpoint(inventory, {
      url: endpoint,
      method: method as SurfaceMethod,
      source: 'form',
      parameters,
    });
    for (const parameter of parameters) {
      addParameter(inventory, {
        endpoint,
        parameter,
        method: method as SurfaceMethod,
        source: 'form',
        sampleValue: fields[parameter],
        contentType: 'application/x-www-form-urlencoded',
        fields,
      });
    }
  }
}

function parseLinks(
  html: string,
  pageUrl: URL,
  target: Target,
  inventory: SurfaceInventory,
  queue: Array<{ url: URL; depth: number }>,
): void {
  const referenceRe = /<(?:a|link|script|iframe|img|form)\b[^>]*(?:href|src|action)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;
  let match: RegExpExecArray | null;
  while ((match = referenceRe.exec(html)) !== null) {
    const reference = decodeHtml(match[1] ?? match[2] ?? match[3] ?? '').trim();
    if (!reference || /^(?:javascript:|mailto:|tel:|data:|#)/i.test(reference)) continue;
    const resolved = sameOrigin(reference, target);
    if (!resolved) continue;
    addQueryParameters(resolved, 'query', inventory);
    if (shouldCrawl(resolved) && queue.length < MAX_CRAWL_PAGES * 2) {
      queue.push({ url: resolved, depth: 1 });
    }
  }

  // Bundled frontends often contain API paths that are not present as links.
  const scriptPathRe = /["'`]((?:\/|\.\.?\/)(?:api|graphql|gql|v\d+)[^"'`\\\s<]{0,180})["'`]/gi;
  let scriptMatch: RegExpExecArray | null;
  while ((scriptMatch = scriptPathRe.exec(html)) !== null) {
    const resolved = sameOrigin(scriptMatch[1]!, pageUrl.href);
    if (!resolved) continue;
    addEndpoint(inventory, {
      url: resolved.origin + resolved.pathname,
      method: 'GET',
      source: 'script',
      parameters: [],
    });
    addQueryParameters(resolved, 'script', inventory);
    if (shouldCrawl(resolved)) queue.push({ url: resolved, depth: 1 });
  }
}

export async function discoverAttackSurface(
  target: Target,
  policy: ScanPolicy,
  onLog: LogFn,
): Promise<SurfaceInventory> {
  const inventory: SurfaceInventory = {
    endpoints: [],
    parameters: [],
    crawled: [],
    forms: 0,
    truncated: false,
  };
  const seed = new URL(target.url);
  const queue: Array<{ url: URL; depth: number }> = [{ url: seed, depth: 0 }];
  const queued = new Set<string>();

  await onLog(
    `[${ts()}] Attack-surface discovery — crawling same-origin pages, forms, scripts, and sitemaps (max ${MAX_CRAWL_PAGES} pages)...`,
  );

  // Robots and sitemap files frequently expose API and admin routes without
  // requiring a brute-force wordlist.
  for (const path of ['/robots.txt', '/sitemap.xml']) {
    if (!policy.allowDeepChecks && path === '/sitemap.xml') continue;
    const url = new URL(path, target.url);
    const response = await probe(url.href, { timeoutMs: Math.min(policy.timeoutMs, 8_000) });
    if (!response || response.status !== 200) continue;
    const references = path.endsWith('robots.txt')
      ? [...response.body.matchAll(/^(?:sitemap|disallow):\s*(\S+)/gim)].map((m) => m[1]!)
      : [...response.body.matchAll(/<loc[^>]*>\s*([^<\s]+)\s*<\/loc>/gi)].map((m) => m[1]!);
    for (const reference of references) {
      const resolved = sameOrigin(reference, target);
      if (!resolved) continue;
      addQueryParameters(resolved, 'sitemap', inventory);
      if (shouldCrawl(resolved)) queue.push({ url: resolved, depth: 1 });
    }
  }

  while (queue.length > 0 && inventory.crawled.length < MAX_CRAWL_PAGES) {
    const item = queue.shift()!;
    const key = item.url.href;
    if (queued.has(key) || !shouldCrawl(item.url)) continue;
    queued.add(key);
    const response = await probe(item.url.href, {
      timeoutMs: Math.min(policy.timeoutMs, 10_000),
    });
    if (!response) continue;
    inventory.crawled.push(item.url.href);
    addQueryParameters(item.url, 'query', inventory);
    addEndpoint(inventory, {
      url: item.url.origin + item.url.pathname,
      method: 'GET',
      source: item.depth === 0 ? 'query' : 'sitemap',
      parameters: [...item.url.searchParams.keys()],
    });

    const contentType = response.headers['content-type'] ?? '';
    if (!/html|xhtml|javascript|json/i.test(contentType)) continue;
    if (/html|xhtml/i.test(contentType)) {
      parseForms(response.body, item.url, inventory);
      parseLinks(response.body, item.url, target, inventory, queue);
    } else {
      const scriptPathRe = /["']((?:\/|\.\.?\/)(?:api|graphql|gql|v\d+)[^"'\\\s<]{0,180})["']/gi;
      let scriptMatch: RegExpExecArray | null;
      while ((scriptMatch = scriptPathRe.exec(response.body)) !== null) {
        const resolved = sameOrigin(scriptMatch[1]!, item.url.href);
        if (!resolved) continue;
        addEndpoint(inventory, {
          url: resolved.origin + resolved.pathname,
          method: 'GET',
          source: 'script',
          parameters: [...resolved.searchParams.keys()],
        });
        addQueryParameters(resolved, 'script', inventory);
      }
    }
  }

  await onLog(
    `[${ts()}] Attack surface discovered — ${inventory.crawled.length} page(s), ${inventory.endpoints.length} endpoint(s), ${inventory.parameters.length} parameter(s), ${inventory.forms} form(s)${inventory.truncated ? ' (limits reached)' : ''}.`,
  );
  return inventory;
}

export function getParameterCandidates(
  inventory: SurfaceInventory,
  target: Target,
  max = 32,
): SurfaceParameter[] {
  const fallbackNames = [
    'id',
    'q',
    'query',
    'search',
    'url',
    'uri',
    'next',
    'redirect',
    'return',
    'file',
    'path',
    'page',
    'name',
    'value',
  ];
  const candidates = [...inventory.parameters];
  const fallbackEndpoint = target.url.replace(/\/$/, '');
  for (const parameter of fallbackNames) {
    candidates.push({
      endpoint: fallbackEndpoint,
      parameter,
      method: 'GET',
      source: 'query',
    });
  }
  const score = (candidate: SurfaceParameter): number => {
    const name = candidate.parameter.toLowerCase();
    return (
      (/(?:id|q|query|search|url|uri|next|redirect|return|file|path|page|name|value|input|sort|filter)/i.test(name)
        ? 10
        : 0) +
      (candidate.source === 'form' ? 3 : 0) +
      (candidate.endpoint.includes('/api/') || /graphql|gql/i.test(candidate.endpoint) ? 2 : 0)
    );
  };
  const unique = new Map<string, SurfaceParameter>();
  for (const candidate of candidates) {
    const key = `${candidate.method}:${candidate.endpoint}:${candidate.parameter}`;
    if (!unique.has(key)) unique.set(key, candidate);
  }
  return [...unique.values()]
    .sort((a, b) => score(b) - score(a))
    .slice(0, max);
}

export function makeParameterRequest(
  candidate: SurfaceParameter,
  value: string,
): { url: string; options: HttpProbeOptions } {
  if (candidate.method === 'GET') {
    const url = new URL(candidate.endpoint);
    url.searchParams.set(candidate.parameter, value);
    return { url: url.href, options: { timeoutMs: 10_000 } };
  }
  const fields = { ...(candidate.fields ?? {}) };
  fields[candidate.parameter] = value;
  const body = new URLSearchParams(fields).toString();
  return {
    url: candidate.endpoint,
    options: {
      method: candidate.method,
      headers: { 'Content-Type': candidate.contentType ?? 'application/x-www-form-urlencoded' },
      body,
      timeoutMs: 10_000,
    },
  };
}