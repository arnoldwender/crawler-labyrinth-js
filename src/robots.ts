import { normalizeBasePath, sanitizeRoutePrefix } from './config.js';

export interface PatchRobotsOptions {
  readonly contentSignal?: boolean;
  readonly basePath?: string;
}

function insertBeforeTrailingBlanks(lines: string[], additions: readonly string[]): string[] {
  const trailing: string[] = [];
  while (lines.length > 0) {
    const last = lines[lines.length - 1] ?? '';
    const trimmed = last.trim();
    const isMeta = trimmed === '' || trimmed.startsWith('#') || /^sitemap\s*:/i.test(stripInlineComment(last));
    if (!isMeta) {
      break;
    }
    trailing.unshift(lines.pop() ?? '');
  }
  lines.push(...additions, ...trailing);
  return lines;
}

function stripInlineComment(line: string): string {
  const hashIdx = line.indexOf('#');
  return (hashIdx === -1 ? line : line.slice(0, hashIdx)).trim();
}

function normalizeRuleCompare(directive: string): string {
  const colonIdx = directive.indexOf(':');
  if (colonIdx === -1) {
    return directive.trim().toLowerCase();
  }
  const field = directive.slice(0, colonIdx).trim().toLowerCase();
  const value = directive.slice(colonIdx + 1).trim();
  return `${field}:${value}`;
}

/**
 * Injects `Disallow: /<prefix>/` into every RFC 9309 User-agent group so named
 * Allow: / blocks (such as OAI-SearchBot or PerplexityBot) cannot shadow the rule.
 */
export function patchRobotsTxt(
  existingContent: string,
  routePrefix: string,
  options: PatchRobotsOptions = {},
): string {
  const cleanPrefix = sanitizeRoutePrefix(routePrefix);
  const basePath = normalizeBasePath(options.basePath);
  const rule = `Disallow: ${basePath}/${cleanPrefix}/`;
  const ruleNormalized = normalizeRuleCompare(rule);
  const signalLine = 'Content-Signal: search=yes, ai-train=no';
  const eol = existingContent.includes('\r\n') ? '\r\n' : '\n';
  const normalized = existingContent.replace(/\r\n?/g, '\n');
  const trimmedAll = normalized.trim();

  if (trimmedAll === '') {
    const starter = ['User-agent: *', rule];
    if (options.contentSignal) {
      starter.push(signalLine);
    }
    return `${starter.join(eol)}${eol}`;
  }

  const lines = normalized.replace(/\n+$/, '').split('\n');
  let result: string[] = [];
  let inGroup = false;
  let hasNonUaDirective = false;
  let groupHasDisallow = false;
  let groupIsStar = false;
  let groupHasSignal = false;
  let sawBlank = false;
  let foundAnyUa = false;

  const flushGroup = (): void => {
    const additions: string[] = [];
    if (!groupHasDisallow) {
      additions.push(rule);
    }
    if (options.contentSignal && groupIsStar && !groupHasSignal) {
      additions.push(signalLine);
    }
    if (additions.length > 0) {
      result = insertBeforeTrailingBlanks(result, additions);
    }
    inGroup = false;
    hasNonUaDirective = false;
    groupHasDisallow = false;
    groupIsStar = false;
    groupHasSignal = false;
    sawBlank = false;
  };

  for (const line of lines) {
    const trimmed = line.trim();
    const directive = stripInlineComment(line);
    const uaMatch = /^user-agent\s*:\s*(.+)$/i.exec(directive);
    const isSitemap = /^sitemap\s*:/i.test(directive);

    if (uaMatch) {
      foundAnyUa = true;
      if (inGroup && (hasNonUaDirective || sawBlank)) {
        flushGroup();
      }
      if (!inGroup) {
        inGroup = true;
        hasNonUaDirective = false;
        groupHasDisallow = false;
        groupIsStar = false;
        groupHasSignal = false;
        sawBlank = false;
      }
      if ((uaMatch[1] ?? '').trim() === '*') {
        groupIsStar = true;
      }
      result.push(line);
      continue;
    }

    // RFC 9309 ends a group only at the next user-agent line or end of file (§2.1); blank lines
    // and out-of-group Sitemap declarations may sit between directives (§2.2) without splitting.
    if (inGroup && (trimmed === '' || isSitemap)) {
      sawBlank = true;
      result.push(line);
      continue;
    }

    if (inGroup && directive !== '') {
      hasNonUaDirective = true;
      sawBlank = false;
      if (normalizeRuleCompare(directive) === ruleNormalized) {
        groupHasDisallow = true;
      }
      if (/^content-signal\s*:/i.test(directive)) {
        groupHasSignal = true;
      }
    }

    result.push(line);
  }

  if (inGroup) {
    flushGroup();
  }

  if (!foundAnyUa) {
    result.push('User-agent: *', rule);
    if (options.contentSignal) {
      result.push(signalLine);
    }
  }

  return `${result.join(eol)}${eol}`;
}

/**
 * Strips any `<url>...</url>` entry whose `<loc>` pathname targets `<basePath>/<prefix>(/...)`
 * from sitemap XML files so disallowed honeypot routes never appear in search sitemaps.
 */
export function stripTrapFromSitemapXml(xml: string, routePrefix: string, basePath = ''): string {
  const cleanPrefix = sanitizeRoutePrefix(routePrefix);
  const cleanBase = normalizeBasePath(basePath);
  const trapPath = `${cleanBase}/${cleanPrefix}`.toLowerCase();

  return xml.replace(/[ \t]*<url\b[^>]*>[\s\S]*?<\/url>[ \t]*\r?\n?/gi, (block) => {
    const locMatch = /<loc(?:\s+[^>]*)?>\s*(?:<!\[CDATA\[)?\s*([^\s<\]]+)/i.exec(block);
    if (!locMatch || !locMatch[1]) {
      return block;
    }
    let pathname = locMatch[1].trim();
    try {
      pathname = new URL(pathname, 'https://sitemap.invalid').pathname;
    } catch {
      const schemeIdx = pathname.indexOf('://');
      if (schemeIdx !== -1) {
        const pathStart = pathname.indexOf('/', schemeIdx + 3);
        pathname = pathStart === -1 ? '/' : pathname.slice(pathStart);
      }
    }
    try {
      pathname = decodeURIComponent(pathname);
    } catch {
      // Keep raw pathname when malformed percent sequences appear.
    }
    const lowerPath = pathname.toLowerCase();
    if (lowerPath === trapPath || lowerPath.startsWith(`${trapPath}/`)) {
      return '';
    }
    return block;
  });
}
