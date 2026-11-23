import {
  DEFAULT_SECRET,
  formatTrapPath,
  getActiveLabyrinthConfig,
  normalizeBasePath,
  sanitizeRoutePrefix,
  sanitizeSeed,
  sanitizeTrailingSlash,
} from './config.js';
import { hmacSha256Hex, signTrapToken } from './crypto.js';
import type { BaitLink, BaitOptions } from './types.js';

/**
 * Generates deterministic depth-1 trap entry links.
 */
export async function buildBaitLinks(props: BaitOptions = {}): Promise<readonly BaitLink[]> {
  const active = getActiveLabyrinthConfig();
  const routePrefix = sanitizeRoutePrefix(props.routePrefix ?? active?.routePrefix);
  const basePath = normalizeBasePath(props.basePath ?? active?.basePath);
  const trailingSlash = sanitizeTrailingSlash(props.trailingSlash ?? active?.trailingSlash);

  const rawCount = props.count ?? active?.linkCount ?? 1;
  const finiteCount = typeof rawCount === 'number' && Number.isFinite(rawCount) ? Math.trunc(rawCount) : 1;
  const count = Math.max(1, Math.min(5, finiteCount));

  const seedBase = sanitizeSeed(props.seed ?? active?.entrySeed);
  const secret = props.secret && props.secret.length >= 16 ? props.secret : (active?.secret ?? DEFAULT_SECRET);
  const baseLabel = props.label && props.label.trim().length > 0 ? props.label.trim() : 'Archival Reference Index';

  const links: BaitLink[] = [];
  for (let i = 0; i < count; i++) {
    const subHash = await hmacSha256Hex(`entry|${seedBase}|${i}`, secret);
    const token = await signTrapToken(1, subHash.slice(0, 12), secret);
    links.push({
      href: formatTrapPath(basePath, routePrefix, token, trailingSlash),
      label: count === 1 ? baseLabel : `${baseLabel} ${i + 1}`,
      token,
    });
  }

  return links;
}

function escapeHtmlAttr(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Renders the accessible-inert honeypot container as a standalone HTML string
 * using native `hidden` + `inert` + `aria-hidden="true"` attributes.
 */
export async function renderCrawlerBaitHtml(props: BaitOptions = {}): Promise<string> {
  const links = await buildBaitLinks(props);
  const anchors = links
    .map(
      (link) =>
        `<a href="${escapeHtmlAttr(link.href)}" rel="nofollow noopener" tabindex="-1" aria-hidden="true">${escapeHtmlAttr(link.label)}</a>`,
    )
    .join('');
  return `<div hidden inert aria-hidden="true" data-crawler-labyrinth="1">${anchors}</div>`;
}
