import { getActiveLabyrinthConfig, isTrainingOnlyUserAgent, normalizeBasePath, resolveConfig } from './config.js';
import { hashClientIp, hmacSha256Hex, normalizeClientIp, verifyTrapToken } from './crypto.js';
import { generateDecoyDocument } from './generator.js';
import { QuarantineStore } from './quarantine.js';
import type { EdgeLabyrinthOptions, TrapViolationEvent } from './types.js';

const DEFAULT_EXCLUDED_PREFIXES: readonly string[] = [
  '/_next',
  '/_astro',
  '/_assets',
  '/.well-known',
  '/robots.txt',
  '/sitemap',
  '/media',
  '/favicon',
  '/api',
];

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function safeDecodePath(rawPath: string): string {
  let current = rawPath;
  for (let i = 0; i < 2; i++) {
    try {
      const next = decodeURIComponent(current);
      if (next === current) {
        break;
      }
      current = next;
    } catch {
      break;
    }
  }
  return current.replace(/\/{2,}/g, '/') || '/';
}

function isExcludedPath(lowerPath: string, excludedPrefixes: readonly string[]): boolean {
  for (const excluded of excludedPrefixes) {
    const norm = excluded.trim().toLowerCase().replace(/\/+$/, '');
    if (!norm) {
      continue;
    }
    if (norm === '/sitemap') {
      if (lowerPath === '/sitemap' || lowerPath.startsWith('/sitemap/') || /^\/sitemap[^/]*\.xml$/i.test(lowerPath)) {
        return true;
      }
      continue;
    }
    if (norm === '/favicon') {
      if (lowerPath === '/favicon' || lowerPath.startsWith('/favicon/') || lowerPath.startsWith('/favicon.')) {
        return true;
      }
      continue;
    }
    if (lowerPath === norm || lowerPath.startsWith(`${norm}/`)) {
      return true;
    }
  }
  return false;
}

function buildSecurityHeaders(
  contentType: string,
  stateHeader: 'decoy' | 'quarantined' | 'observed' | 'burst-shed',
  retryAfterSeconds?: number,
): Headers {
  const headers = new Headers({
    'Content-Type': contentType,
    'X-Robots-Tag': 'noindex, nofollow, noarchive, nosnippet, noai, noimageai',
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    'X-Content-Type-Options': 'nosniff',
    'X-Crawler-Labyrinth': stateHeader,
  });
  if (typeof retryAfterSeconds === 'number' && retryAfterSeconds > 0) {
    headers.set('Retry-After', String(retryAfterSeconds));
  }
  return headers;
}

function buildBlockResponse(
  status: 429 | 403,
  retryAfterSeconds: number,
  isHead: boolean,
  stateHeader: 'quarantined' | 'burst-shed' = 'quarantined',
): Response {
  const message =
    status === 429
      ? 'HTTP 429 Too Many Requests: Automated traversal of disallowed robots.txt routes is rate-limited.'
      : 'HTTP 403 Forbidden: Automated traversal of disallowed robots.txt routes is prohibited.';

  return new Response(isHead ? null : `${message}\n`, {
    status,
    headers: buildSecurityHeaders('text/plain; charset=utf-8', stateHeader, status === 429 ? retryAfterSeconds : undefined),
  });
}

async function findActiveQuarantine(
  store: QuarantineStore,
  todayDigest: string,
  extractedIp: string,
  secret: string,
  blockTtlMs: number,
  nowMs: number,
): Promise<{ quarantined: boolean; retryAfterSeconds: number; strikes: number } | null> {
  const todayRec = store.isQuarantined(todayDigest, nowMs);
  if (todayRec.quarantined) {
    return todayRec;
  }

  const lookbackDays = Math.min(7, Math.max(1, Math.ceil(blockTtlMs / 86_400_000)));
  for (let d = 1; d <= lookbackDays; d++) {
    const pastDay = new Date(nowMs - d * 86_400_000).toISOString().slice(0, 10);
    const pastDigest = await hashClientIp(extractedIp, secret, pastDay);
    const pastRec = store.isQuarantined(pastDigest, nowMs);
    if (pastRec.quarantined) {
      return pastRec;
    }
  }
  return null;
}

function extractClientIp(
  request: Request,
  explicitIp: string | undefined,
  trustProxyHeaders: boolean,
  trustedProxyHeader?: string,
): string | null {
  if (explicitIp) {
    const normalized = normalizeClientIp(explicitIp);
    if (normalized.length > 0) {
      return normalized;
    }
  }
  if (!trustProxyHeaders) {
    return null;
  }
  if (trustedProxyHeader) {
    const raw = request.headers.get(trustedProxyHeader);
    if (!raw) {
      return null;
    }
    const candidate = trustedProxyHeader === 'x-forwarded-for' ? (raw.split(',')[0] ?? '') : raw;
    const normalized = normalizeClientIp(candidate);
    return normalized.length > 0 ? normalized : null;
  }
  const cfIp = request.headers.get('cf-connecting-ip');
  if (cfIp) {
    const normalized = normalizeClientIp(cfIp);
    if (normalized.length > 0) {
      return normalized;
    }
  }
  const nfIp = request.headers.get('x-nf-client-connection-ip');
  if (nfIp) {
    const normalized = normalizeClientIp(nfIp);
    if (normalized.length > 0) {
      return normalized;
    }
  }
  const realIp = request.headers.get('x-real-ip');
  if (realIp) {
    const normalized = normalizeClientIp(realIp);
    if (normalized.length > 0) {
      return normalized;
    }
  }
  const xff = request.headers.get('x-forwarded-for');
  if (xff) {
    const first = xff.split(',')[0];
    if (first) {
      const normalized = normalizeClientIp(first);
      if (normalized.length > 0) {
        return normalized;
      }
    }
  }
  return null;
}

function compileTrapRegex(basePrefix: string, routePrefix: string): RegExp {
  return new RegExp(
    `^${escapeRegex(basePrefix)}\\/${escapeRegex(routePrefix)}(?:\\/([\\s\\S]*))?$`,
    'i',
  );
}

export type LabyrinthHandler = (request: Request, clientIp?: string) => Promise<Response | null>;
export type EdgeLabyrinthHandler = LabyrinthHandler;

/**
 * Web-standard Request/Response handler for Next.js Middleware, SvelteKit Hooks, Hono,
 * Cloudflare Workers, Deno, and Node Fetch servers. Returns `null` on pass-through.
 */
export function createLabyrinthHandler(options?: EdgeLabyrinthOptions): LabyrinthHandler {
  const base = options ? resolveConfig(options) : (getActiveLabyrinthConfig() ?? resolveConfig());
  const excludedPrefixes = options?.excludedPrefixes ?? DEFAULT_EXCLUDED_PREFIXES;
  const store = options?.store ?? new QuarantineStore();
  const basePrefix = normalizeBasePath(base.basePath);
  const trapRegex = compileTrapRegex(basePrefix, base.routePrefix);
  let warnedDefaultSecret = false;

  return async (request: Request, clientIp?: string): Promise<Response | null> => {
    if (base.usesDefaultSecret && !warnedDefaultSecret) {
      warnedDefaultSecret = true;
      console.warn(
        '[crawler-labyrinth] Default fallback secret is active; set a unique >=16-char `secret` before production deployment.',
      );
    }

    let url: URL;
    try {
      url = new URL(request.url, 'http://localhost');
    } catch {
      return null;
    }

    const pathname = safeDecodePath(url.pathname || '/');
    const lowerPath = pathname.toLowerCase();
    const isHead = (request.method ?? 'GET').toUpperCase() === 'HEAD';

    // Match explicit trap route before prefix exclusions so valid prefixes like `apis` or `sitemaps` are never shadowed.
    const trapMatch = trapRegex.exec(pathname);
    if (!trapMatch) {
      const relLower =
        basePrefix && (lowerPath === basePrefix.toLowerCase() || lowerPath.startsWith(`${basePrefix.toLowerCase()}/`))
          ? lowerPath.slice(basePrefix.length) || '/'
          : lowerPath;
      if (isExcludedPath(lowerPath, excludedPrefixes) || isExcludedPath(relLower, excludedPrefixes)) {
        return null;
      }
    }

    const userAgent = request.headers.get('user-agent') ?? '';
    const uaMatched = !trapMatch && base.interceptTrainingBots && isTrainingOnlyUserAgent(userAgent);
    const nowMs = Date.now();
    const shouldCheckQuarantine = base.mode !== 'observe' && store.hasActiveQuarantines(nowMs);

    if (!trapMatch && !uaMatched && !shouldCheckQuarantine) {
      return null;
    }

    const extractedIp = extractClientIp(request, clientIp, base.trustProxyHeaders, base.trustedProxyHeader);
    const hasIdentifiableIp = extractedIp !== null;
    if (!trapMatch && !uaMatched && !hasIdentifiableIp) {
      return null;
    }

    const todayUtcDay = new Date(nowMs).toISOString().slice(0, 10);
    const ipDigest = await hashClientIp(extractedIp ?? '0.0.0.0', base.secret, todayUtcDay);

    if (hasIdentifiableIp && shouldCheckQuarantine && extractedIp !== null) {
      const existing = await findActiveQuarantine(store, ipDigest, extractedIp, base.secret, base.blockTtlMs, nowMs);
      if (existing) {
        return buildBlockResponse(base.blockStatus, existing.retryAfterSeconds, isHead);
      }
    }

    if (!trapMatch && !uaMatched) {
      return null;
    }

    const trimmedTail = trapMatch ? (trapMatch[1] ?? '').replace(/^\/+|\/+$/g, '') : '';
    const tokenCandidate = /^[a-zA-Z0-9_-]{1,96}$/.test(trimmedTail) ? trimmedTail : '';
    const cleanTail = trimmedTail.replace(/[\x00-\x1F\x7F]+/g, '');
    const rawToken = trapMatch ? (trimmedTail === '' ? '' : cleanTail.slice(0, 96) || 'control-probe') : 'ua-guard';
    const verified = trapMatch && tokenCandidate ? await verifyTrapToken(tokenCandidate, base.secret) : null;
    const parsed = verified && verified.depth <= base.maxDepth ? verified : null;
    const entryVector = !trapMatch ? 'ua_guard' : parsed ? 'signed_bait' : 'robots_probe';

    const notify = async (event: TrapViolationEvent): Promise<void> => {
      if (!base.onViolation) {
        return;
      }
      try {
        await base.onViolation(event);
      } catch {
        // Telemetry hooks must never abort request handling.
      }
    };

    if (base.mode !== 'observe') {
      if (base.burstLimitPerMinute > 0 && store.isBurstExceeded(base.burstLimitPerMinute)) {
        await notify({
          timestamp: new Date().toISOString(),
          ipDigest,
          userAgentExcerpt: userAgent.slice(0, 120),
          routeToken: rawToken || 'root',
          actionTaken: 'burst_shed',
          entryVector,
          strikes: 0,
          status: 429,
        });
        return buildBlockResponse(429, 60, isHead, 'burst-shed');
      }
    }

    const outcome = hasIdentifiableIp
      ? store.recordHit(ipDigest, base.mode, base.strikeThreshold, base.blockTtlMs, nowMs)
      : {
          quarantined: base.mode === 'block',
          retryAfterSeconds: Math.max(60, Math.ceil(base.blockTtlMs / 1000)),
          strikes: 1,
        };

    if (outcome.quarantined) {
      await notify({
        timestamp: new Date().toISOString(),
        ipDigest,
        userAgentExcerpt: userAgent.slice(0, 120),
        routeToken: rawToken || 'root',
        actionTaken: 'quarantined',
        entryVector,
        strikes: outcome.strikes,
        status: base.blockStatus,
      });
      return buildBlockResponse(base.blockStatus, outcome.retryAfterSeconds, isHead);
    }

    const depth = parsed ? parsed.depth : 1;
    const seed = parsed
      ? parsed.seed
      : (await hmacSha256Hex(`entry|${pathname}`, base.secret)).slice(0, 12);

    const decoy = await generateDecoyDocument({
      depth,
      seed,
      secret: base.secret,
      routePrefix: base.routePrefix,
      basePath: base.basePath,
      trailingSlash: base.trailingSlash,
      format: base.format,
      maxDepth: base.maxDepth,
      linksPerPage: 3,
    });

    const isObserve = base.mode === 'observe';
    const actionTaken = isObserve ? 'observed' : 'decoy_served';
    const stateHeader = isObserve ? 'observed' : 'decoy';

    await notify({
      timestamp: new Date().toISOString(),
      ipDigest,
      userAgentExcerpt: userAgent.slice(0, 120),
      routeToken: rawToken || 'root',
      actionTaken,
      entryVector,
      strikes: outcome.strikes,
      status: 200,
    });

    return new Response(isHead ? null : decoy.body, {
      status: 200,
      headers: buildSecurityHeaders(decoy.contentType, stateHeader),
    });
  };
}

export const createEdgeLabyrinthHandler = createLabyrinthHandler;
