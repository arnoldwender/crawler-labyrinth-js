import type {
  LabyrinthOptions,
  ResolvedLabyrinthConfig,
  ResponseFormat,
  TrailingSlashMode,
  TrapMode,
} from './types.js';

export const DEFAULT_ROUTE_PREFIX = 'crawler-trap';
export const DEFAULT_SECRET = 'crawler-labyrinth-default-seed-v1';

const RESERVED_PREFIXES: readonly string[] = [
  '_next',
  '_astro',
  '_assets',
  'api',
  'media',
  'well-known',
  'robots',
  'sitemap',
  'favicon',
  'admin',
];

const ALLOWED_SEARCH_UA_TOKENS: readonly string[] = [
  'Googlebot',
  'Bingbot',
  'Applebot',
  'OAI-SearchBot',
  'ChatGPT-User',
  'Claude-SearchBot',
  'Claude-User',
  'PerplexityBot',
  'Perplexity-User',
  'MistralAI-User',
  'Slackbot',
  'Storebot-Google',
  'DuckDuckBot',
];

const TRAINING_ONLY_UA_TOKENS: readonly string[] = [
  'GPTBot',
  'CCBot',
  'ClaudeBot',
  'anthropic-ai',
  'Bytespider',
  'PetalBot',
  'Diffbot',
  'Omgilibot',
  'ImagesiftBot',
  'DataForSeoBot',
  'Scrapy',
];

const GLOBAL_CONFIG_SYMBOL = Symbol.for('crawler-labyrinth.config');

type GlobalWithConfig = typeof globalThis & {
  [GLOBAL_CONFIG_SYMBOL]?: ResolvedLabyrinthConfig;
};

export function setActiveLabyrinthConfig(config: ResolvedLabyrinthConfig): void {
  (globalThis as GlobalWithConfig)[GLOBAL_CONFIG_SYMBOL] = config;
}

export function getActiveLabyrinthConfig(): ResolvedLabyrinthConfig | null {
  return (globalThis as GlobalWithConfig)[GLOBAL_CONFIG_SYMBOL] ?? null;
}

export function normalizeBasePath(raw: string | undefined): string {
  if (!raw) {
    return '';
  }
  const trimmed = raw.trim().replace(/\/{2,}/g, '/').replace(/^\/+|\/+$/g, '');
  if (trimmed === '') {
    return '';
  }
  return `/${trimmed}`;
}

export function sanitizeTrailingSlash(raw: TrailingSlashMode | undefined): TrailingSlashMode {
  return raw === 'never' || raw === 'ignore' ? raw : 'always';
}

export function formatTrapPath(
  basePath: string,
  routePrefix: string,
  token?: string,
  trailingSlash: TrailingSlashMode = 'always',
): string {
  const base = normalizeBasePath(basePath);
  const prefix = sanitizeRoutePrefix(routePrefix);
  const suffix = trailingSlash === 'never' ? '' : '/';
  if (token && token.length > 0) {
    return `${base}/${prefix}/${encodeURIComponent(token)}${suffix}`;
  }
  return `${base}/${prefix}${suffix}`;
}

export function sanitizeRoutePrefix(raw: string | undefined): string {
  if (!raw) {
    return DEFAULT_ROUTE_PREFIX;
  }
  const stripped = raw.trim().replace(/^\/+|\/+$/g, '').toLowerCase();
  if (stripped.includes('.') || stripped.includes('/')) {
    return DEFAULT_ROUTE_PREFIX;
  }
  const baseClean = stripped.replace(/[^a-z0-9_-]/g, '').replace(/^-+|-+$/g, '');
  const clean = baseClean.replace(/^[-_]+|[-_]+$/g, '');
  if (clean.length < 3 || clean.length > 32) {
    return DEFAULT_ROUTE_PREFIX;
  }
  for (const reserved of RESERVED_PREFIXES) {
    if (
      baseClean === reserved ||
      baseClean.startsWith(`${reserved}-`) ||
      baseClean.startsWith(`${reserved}_`) ||
      clean === reserved ||
      clean.startsWith(`${reserved}-`) ||
      clean.startsWith(`${reserved}_`)
    ) {
      return DEFAULT_ROUTE_PREFIX;
    }
  }
  return clean;
}

function sanitizeMode(raw: TrapMode | undefined): TrapMode {
  return raw === 'labyrinth' || raw === 'block' || raw === 'hybrid' || raw === 'observe' ? raw : 'hybrid';
}

function sanitizeFormat(raw: ResponseFormat | undefined): ResponseFormat {
  return raw === 'plain' ? 'plain' : 'html';
}

export function sanitizeTrustedProxyHeader(raw: string | undefined): string | undefined {
  if (typeof raw !== 'string') {
    return undefined;
  }
  const clean = raw.trim().toLowerCase();
  if (!/^[a-z0-9-]{1,64}$/.test(clean)) {
    return undefined;
  }
  return clean;
}

function clampInt(val: number | undefined, min: number, max: number, fallback: number): number {
  if (typeof val !== 'number' || !Number.isFinite(val)) {
    return fallback;
  }
  const n = Math.trunc(val);
  if (n < min) return min;
  if (n > max) return max;
  return n;
}

export function sanitizeBurstLimit(val: number | undefined, fallback = 300): number {
  if (typeof val !== 'number' || !Number.isFinite(val)) {
    return fallback;
  }
  const n = Math.trunc(val);
  if (n <= 0) return 0;
  if (n < 5) return 5;
  if (n > 10_000) return 10_000;
  return n;
}

export function sanitizeSeed(raw: string | undefined, fallback = 'archroot0001'): string {
  if (!raw) return fallback;
  const clean = raw.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (clean.length === 0) return fallback;
  if (clean.length < 4) {
    return `${clean}arch0001`.slice(0, 12);
  }
  return clean.slice(0, 24);
}

export function resolveConfig(options: LabyrinthOptions = {}): ResolvedLabyrinthConfig {
  const hasStrongSecret = typeof options.secret === 'string' && options.secret.length >= 16;
  const secret = hasStrongSecret ? options.secret! : DEFAULT_SECRET;
  return {
    routePrefix: sanitizeRoutePrefix(options.routePrefix),
    basePath: normalizeBasePath(options.basePath),
    trailingSlash: sanitizeTrailingSlash(options.trailingSlash),
    mode: sanitizeMode(options.mode),
    format: sanitizeFormat(options.format),
    secret,
    usesDefaultSecret: !hasStrongSecret || secret === DEFAULT_SECRET,
    maxDepth: clampInt(options.maxDepth, 1, 16, 8),
    linkCount: clampInt(options.linkCount, 1, 5, 1),
    strikeThreshold: clampInt(options.strikeThreshold, 1, 100, 5),
    blockTtlMs: clampInt(options.blockTtlMs, 60_000, 7 * 24 * 60 * 60 * 1000, 6 * 60 * 60 * 1000),
    blockStatus: options.blockStatus === 403 ? 403 : 429,
    burstLimitPerMinute: sanitizeBurstLimit(options.burstLimitPerMinute),
    interceptTrainingBots: options.interceptTrainingBots ?? false,
    trustProxyHeaders: options.trustProxyHeaders ?? false,
    trustedProxyHeader: sanitizeTrustedProxyHeader(options.trustedProxyHeader),
    entrySeed: sanitizeSeed(options.entrySeed),
    onViolation: options.onViolation,
  };
}

/**
 * Matches verified AI training or bulk scraper User-Agents while explicitly
 * sparing search, citation, and link-preview crawlers.
 */
export function isTrainingOnlyUserAgent(userAgent: string): boolean {
  const normalized = userAgent.trim().toLowerCase();
  if (normalized.length === 0) {
    return false;
  }
  for (const allowed of ALLOWED_SEARCH_UA_TOKENS) {
    if (normalized.includes(allowed.toLowerCase())) {
      return false;
    }
  }
  for (const token of TRAINING_ONLY_UA_TOKENS) {
    if (normalized.includes(token.toLowerCase())) {
      return true;
    }
  }
  return false;
}
