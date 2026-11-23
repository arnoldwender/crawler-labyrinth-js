import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  buildBaitLinks,
  createEdgeLabyrinthHandler,
  createLabyrinthHandler,
  generateDecoyDocument,
  hashClientIp,
  isTrainingOnlyUserAgent,
  normalizeClientIp,
  patchRobotsTxt,
  QuarantineStore,
  renderCrawlerBaitHtml,
  resolveConfig,
  sanitizeBurstLimit,
  sanitizeRoutePrefix,
  signTrapToken,
  stripTrapFromSitemapXml,
  timingSafeEqualHex,
  verifyTrapToken,
} from '../src/index.js';
import { createLabyrinthHandler as createHandlerFromEdge } from '../src/edge.js';
import type { TrapViolationEvent } from '../src/types.js';

describe('Config & User-Agent Separation', () => {
  it('sanitizes reserved framework prefixes (_next, _astro, api, robots.txt) and preserves valid stems', () => {
    expect(sanitizeRoutePrefix('_next')).toBe('crawler-trap');
    expect(sanitizeRoutePrefix('_astro')).toBe('crawler-trap');
    expect(sanitizeRoutePrefix('robots.txt')).toBe('crawler-trap');
    expect(sanitizeRoutePrefix('___')).toBe('crawler-trap');
    expect(sanitizeRoutePrefix('api-v2')).toBe('crawler-trap');
    expect(sanitizeRoutePrefix('apis')).toBe('apis');
    expect(sanitizeRoutePrefix('/Decoy_Vault-01/')).toBe('decoy_vault-01');
    expect(sanitizeRoutePrefix('a')).toBe('crawler-trap');
  });

  it('matches training-only scrapers while explicitly sparing search, citation, and preview bots', () => {
    expect(isTrainingOnlyUserAgent('Mozilla/5.0 AppleWebKit/537.36 (compatible; GPTBot/1.2)')).toBe(true);
    expect(isTrainingOnlyUserAgent('CCBot/2.0 (https://commoncrawl.org/faq/)')).toBe(true);
    expect(isTrainingOnlyUserAgent('ClaudeBot/1.0')).toBe(true);
    expect(isTrainingOnlyUserAgent('Bytespider')).toBe(true);

    expect(isTrainingOnlyUserAgent('OAI-SearchBot/1.0')).toBe(false);
    expect(isTrainingOnlyUserAgent('OAI-SearchBot/1.0 (compatible; GPTBot-test)')).toBe(false);
    expect(isTrainingOnlyUserAgent('Claude-SearchBot/1.0')).toBe(false);
    expect(isTrainingOnlyUserAgent('PerplexityBot/1.0')).toBe(false);
    expect(isTrainingOnlyUserAgent('Googlebot/2.1')).toBe(false);
    expect(isTrainingOnlyUserAgent('Applebot/0.1')).toBe(false);
    expect(isTrainingOnlyUserAgent('Slackbot-LinkExpanding 1.0')).toBe(false);
  });
});

describe('WebCrypto Token Signing, Privacy IP Hashing & Bait HTML', () => {
  it('signs and verifies trap tokens in constant time and rejects forged signatures', async () => {
    const secret = 'unit-fixture-core-secret-key-1234';
    const token = await signTrapToken(3, 'SeedAlpha9', secret);
    expect(token.startsWith('3-seedalpha9-')).toBe(true);
    expect(await verifyTrapToken(token, secret)).toEqual({ depth: 3, seed: 'seedalpha9' });

    const flipped = `${token.slice(0, -1)}${token.endsWith('0') ? '1' : '0'}`;
    expect(await verifyTrapToken(flipped, secret)).toBeNull();
    expect(timingSafeEqualHex('abcd', 'abcd')).toBe(true);
    expect(timingSafeEqualHex('abcd', 'abcde')).toBe(false);
    expect(timingSafeEqualHex('abcd', 'abc')).toBe(false);
    expect(timingSafeEqualHex('', '')).toBe(false);

    const cryptoSource = await readFile(resolve(process.cwd(), 'src/crypto.ts'), 'utf8');
    expect(cryptoSource).toMatch(/charCodeAt\(/);
    expect(cryptoSource).toMatch(/diff\s*\|=\s*a\.charCodeAt/);
  });

  it('normalizes IPv6/IPv4-mapped addresses and produces secret-keyed daily digests', async () => {
    const s1 = 'unit-fixture-digest-secret-alpha1';
    const s2 = 'unit-fixture-digest-secret-bravo2';
    const d1 = await hashClientIp('203.0.113.42', s1, '2026-11-23');
    const d2 = await hashClientIp('203.0.113.42', s1, '2026-11-24');
    const dKey2 = await hashClientIp('203.0.113.42', s2, '2026-11-23');

    expect(d1).toHaveLength(64);
    expect(d1).not.toContain('203.0.113');
    expect(d1).not.toBe(d2);
    expect(d1).not.toBe(dKey2);
    expect(normalizeClientIp('::ffff:198.51.100.7')).toBe('198.51.100.7');
    expect(normalizeClientIp('[2001:0db8:0000:0000::1]:443')).toBe('2001:db8::1');
  });

  it('renders accessible-inert HTML bait string with hidden, inert, aria-hidden, and escaping', async () => {
    const html = await renderCrawlerBaitHtml({
      routePrefix: 'crawler-trap',
      basePath: '/docs',
      count: 2,
      label: 'Archive <Ref> & "Index"',
      secret: 'unit-fixture-bait-html-secret-12',
    });
    expect(html).toContain('<div hidden inert aria-hidden="true" data-crawler-labyrinth="1">');
    expect(html).toContain('rel="nofollow noopener" tabindex="-1" aria-hidden="true"');
    expect(html).toContain('Archive &lt;Ref&gt; &amp; &quot;Index&quot; 1');
    expect(html).toContain('href="/docs/crawler-trap/');
  });
});

describe('Decoy Generator, Robots.txt & Sitemap Cleaner', () => {
  it('generates deterministic archival HTML with noindex/noai and rel=nofollow links', async () => {
    const secret = 'unit-fixture-decoy-secret-key-12';
    const a = await generateDecoyDocument({ depth: 2, seed: 'folio1', secret, basePath: '/app', trailingSlash: 'never' });
    const b = await generateDecoyDocument({ depth: 2, seed: 'folio1', secret, basePath: '/app', trailingSlash: 'never' });
    expect(a.body).toBe(b.body);
    expect(a.body).toContain('<meta name="robots" content="noindex, nofollow, noarchive, nosnippet, noai, noimageai" />');
    expect(a.body).toContain('rel="nofollow noopener"');
    expect(a.body).not.toContain('<script');
  });

  it('injects Disallow into every RFC 9309 User-agent group idempotently and strips trap sitemap entries', () => {
    const input = 'User-agent: OAI-SearchBot\nAllow: /\nUser-agent: GPTBot\nDisallow: /\n\nUser-agent: *\nAllow: /\n';
    const patched = patchRobotsTxt(input, 'crawler-trap');
    expect(patched.match(/Disallow: \/crawler-trap\//g)).toHaveLength(3);
    expect(patchRobotsTxt(patched, 'crawler-trap')).toBe(patched);

    const xml =
      '<urlset><url><loc>https://example.test/crawler-trap/1-abc/</loc></url><url><loc>https://example.test/about/</loc></url></urlset>';
    const cleaned = stripTrapFromSitemapXml(xml, 'crawler-trap');
    expect(cleaned).not.toContain('/crawler-trap/');
    expect(cleaned).toContain('https://example.test/about/');
  });
});

describe('QuarantineStore & Web-Standard Handler (Next.js / SvelteKit / Hono / Workers)', () => {
  it('enforces TTL expiration, LRU protection, trap modes, and burst window bounds', () => {
    const store = new QuarantineStore(64);
    const ban = store.recordHit('banned-attacker', 'block', 5, 60_000, 1_000);
    expect(ban.quarantined).toBe(true);

    for (let i = 0; i < 120; i++) {
      store.recordHit(`flood-${i}`, 'hybrid', 5, 60_000, 2_000 + i);
    }
    expect(store.size()).toBe(64);
    expect(store.isQuarantined('banned-attacker', 5_000).quarantined).toBe(true);
    expect(store.isQuarantined('banned-attacker', 70_000).quarantined).toBe(false);

    const labStore = new QuarantineStore(64);
    for (let s = 1; s <= 10; s++) {
      expect(labStore.recordHit('bot-lab', 'labyrinth', 2, 60_000, 1_000 + s).quarantined).toBe(false);
    }

    const expStore = new QuarantineStore(64);
    for (let i = 0; i < 64; i++) {
      expStore.recordHit(`stale-${i}`, 'hybrid', 5, 1_000, 1_000);
    }
    expStore.recordHit('fresh', 'hybrid', 5, 60_000, 5_000);
    expect(expStore.size()).toBe(1);

    const lruStore = new QuarantineStore(64);
    lruStore.recordHit('ban-0', 'block', 5, 60_000, 1_000);
    for (let i = 1; i <= 63; i++) {
      lruStore.recordHit(`ban-${i}`, 'block', 5, 60_000, 1_000 + i);
    }
    expect(lruStore.isQuarantined('ban-0', 2_000).quarantined).toBe(true);
    lruStore.recordHit('ban-64', 'block', 5, 60_000, 2_100);
    expect(lruStore.isQuarantined('ban-0', 2_200).quarantined).toBe(true);
    expect(lruStore.isQuarantined('ban-1', 2_200).quarantined).toBe(false);

    expect(sanitizeBurstLimit(0)).toBe(0);
    expect(sanitizeBurstLimit(2)).toBe(5);
    expect(sanitizeBurstLimit(99_999)).toBe(10_000);
    expect(resolveConfig().usesDefaultSecret).toBe(true);
  });

  it('handles Next.js/Hono/Workers requests: quarantine, 403, exclusions, HEAD, observe, and burst shedding', async () => {
    expect(createHandlerFromEdge).toBe(createLabyrinthHandler);
    expect(createEdgeLabyrinthHandler).toBe(createLabyrinthHandler);

    const events: TrapViolationEvent[] = [];
    const handler = createLabyrinthHandler({
      routePrefix: 'apis',
      basePath: '/docs',
      trailingSlash: 'never',
      mode: 'hybrid',
      maxDepth: 4,
      strikeThreshold: 2,
      blockStatus: 429,
      blockTtlMs: 120_000,
      secret: 'unit-fixture-core-handler-key-12',
      interceptTrainingBots: true,
      onViolation: (ev) => {
        events.push(ev);
      },
    });

    expect(await handler(new Request('https://example.test/_next/static/chunk.js'), '192.0.2.50')).toBeNull();
    expect(await handler(new Request('https://example.test/api/health'), '192.0.2.50')).toBeNull();
    expect(
      await handler(
        new Request('https://example.test/docs/blog/', { headers: { 'user-agent': 'OAI-SearchBot/1.0' } }),
        '192.0.2.50',
      ),
    ).toBeNull();

    const r1 = await handler(new Request('https://example.test/docs/%61pis/1-seed0001-0000'), '192.0.2.88');
    expect(r1?.status).toBe(200);
    expect(r1?.headers.get('X-Crawler-Labyrinth')).toBe('decoy');

    const headRes = await handler(new Request('https://example.test/docs/apis/2-seed0002-0000', { method: 'HEAD' }), '192.0.2.88');
    expect(headRes?.status).toBe(200);
    expect(await headRes?.text()).toBe('');

    const r3 = await handler(new Request('https://example.test/docs/apis/3-seed0003-0000'), '192.0.2.88');
    expect(r3?.status).toBe(429);
    expect(r3?.headers.get('Retry-After')).toBe('120');
    expect(r3?.headers.get('X-Crawler-Labyrinth')).toBe('quarantined');

    expect((await handler(new Request('https://example.test/docs/pricing/'), '192.0.2.88'))?.status).toBe(429);

    const botRes = await handler(
      new Request('https://example.test/docs/pricing/', { headers: { 'user-agent': 'GPTBot/1.2' } }),
      '198.51.100.10',
    );
    expect(botRes?.status).toBe(200);
    expect(events[2]?.actionTaken).toBe('quarantined');
    for (const ev of events) {
      expect(ev.ipDigest).toHaveLength(64);
      expect(ev.ipDigest).not.toContain('192.0.2');
      expect(ev.ipDigest).not.toContain('198.51.100');
    }

    // 403 block mode + HEAD empty body + maxDepth bound enforcement
    const blockMode = createLabyrinthHandler({
      mode: 'block',
      blockStatus: 403,
      maxDepth: 4,
      secret: 'unit-fixture-block-core-key-1234',
    });
    const tokenDepth16 = await signTrapToken(16, 'forged99', 'unit-fixture-block-core-key-1234');
    const head403 = await blockMode(new Request('https://example.test/crawler-trap/1-seed-0000/', { method: 'HEAD' }));
    expect(head403?.status).toBe(403);
    expect(await head403?.text()).toBe('');

    const depthBound = createLabyrinthHandler({
      mode: 'labyrinth',
      maxDepth: 4,
      secret: 'unit-fixture-block-core-key-1234',
    });
    const clampedRes = await depthBound(new Request(`https://example.test/crawler-trap/${tokenDepth16}/`));
    expect(await clampedRes?.text()).toContain('(Section 1)');

    // Observe dry-run mode + entryVector
    const obsEvents: TrapViolationEvent[] = [];
    const obsSecret = 'unit-fixture-observe-core-key-12';
    const baitToken = (await buildBaitLinks({ secret: obsSecret }))[0]!.token;
    const obsHandler = createLabyrinthHandler({
      mode: 'observe',
      strikeThreshold: 1,
      interceptTrainingBots: true,
      secret: obsSecret,
      onViolation: (ev) => {
        obsEvents.push(ev);
      },
    });
    const obsBait = await obsHandler(new Request(`https://example.test/crawler-trap/${baitToken}/`), '198.51.100.71');
    const obsProbe = await obsHandler(new Request('https://example.test/crawler-trap/probe/'), '198.51.100.71');
    const obsUa = await obsHandler(
      new Request('https://example.test/about/', { headers: { 'user-agent': 'GPTBot/1.2' } }),
      '198.51.100.71',
    );
    expect(obsBait?.headers.get('X-Crawler-Labyrinth')).toBe('observed');
    expect(obsProbe?.status).toBe(200);
    expect(obsUa?.status).toBe(200);
    expect(await obsHandler(new Request('https://example.test/about/'), '198.51.100.71')).toBeNull();
    expect(obsEvents.map((e) => [e.actionTaken, e.entryVector])).toEqual([
      ['observed', 'signed_bait'],
      ['observed', 'robots_probe'],
      ['observed', 'ua_guard'],
    ]);

    // Global burst circuit breaker
    const burstEvents: TrapViolationEvent[] = [];
    const burstHandler = createLabyrinthHandler({
      mode: 'labyrinth',
      burstLimitPerMinute: 5,
      secret: 'unit-fixture-burst-core-key-1234',
      onViolation: (ev) => {
        burstEvents.push(ev);
      },
    });
    for (let i = 0; i < 5; i++) {
      expect((await burstHandler(new Request('https://example.test/crawler-trap/p/'), `198.51.100.${i}`))?.status).toBe(200);
    }
    const shed = await burstHandler(new Request('https://example.test/crawler-trap/p/'), '198.51.100.99');
    expect(shed?.status).toBe(429);
    expect(shed?.headers.get('Retry-After')).toBe('60');
    expect(shed?.headers.get('X-Crawler-Labyrinth')).toBe('burst-shed');
    expect(burstEvents[5]?.actionTaken).toBe('burst_shed');
    for (const ev of burstEvents) {
      expect(ev.ipDigest).toHaveLength(64);
      expect(ev.ipDigest).not.toContain('198.51.100');
    }
  });
});
