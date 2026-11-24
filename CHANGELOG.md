# Changelog

All notable changes to `crawler-labyrinth` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-11-24

### Fixed
- **O(1) Hot-Path Short-Circuit & Bounded UTC Midnight Rollover (`QuarantineStore`, `edge.ts`):** Added `hasActiveQuarantines()` for `0` WebCrypto calls on normal traffic with no active bans (or in `observe` mode), optional shared `options.store`, and bounded `1..7`-day UTC lookback across midnight rollover.
- **`observe` Dry-Run Parity (`edge.ts`):** Skips `HTTP 429 burst-shed` responses in `mode: 'observe'`.
- **Extended Trap Probe Matching (`edge.ts`):** Captures multi-segment paths, `.html` suffixes, newline tails, and `>96`-char probes under `/<routePrefix>/...` as `robots_probe` while preserving sibling-prefix exclusions.
- **RFC 9309 `robots.txt` Continuity (`robots.ts`):** Maintains active `User-agent:` group state across blank lines and mid-group `Sitemap:` declarations without duplicating `Disallow: /<prefix>/`.
- **Strict IP Validation & Single-Header Proxy Pinning (`crypto.ts`, `config.ts`, `edge.ts`):** Rejects non-IP strings in `normalizeClientIp()` (`""`) and adds `trustedProxyHeader` to prevent multi-CDN spoofing.

### Added
- Expanded Vitest coverage (`12 passed (12)`) for `trustProxyHeaders`, `trustedProxyHeader`, throwing `onViolation` hooks, UTC rollover, and extended trap probes (`32/32` killed mutants).

## [1.0.0] - 2026-11-23

### Added
- Initial public release of the zero-dependency Web-standard (`Request` / `Response` + WebCrypto) core package extracted from `astro-crawler-labyrinth`.
- Exports `createLabyrinthHandler` (and `createEdgeLabyrinthHandler` alias) supporting `hybrid`, `labyrinth`, `block`, and dry-run `observe` modes, global `burstLimitPerMinute` shedding, `entryVector` telemetry (`signed_bait`, `robots_probe`, `ua_guard`), and `X-Crawler-Labyrinth` state headers.
- Exports accessible-inert bait helpers (`buildBaitLinks`, `renderCrawlerBaitHtml`), deterministic archival decoy generator (`generateDecoyDocument`), RFC 9309 multi-group `robots.txt` patcher (`patchRobotsTxt`), sitemap cleaner (`stripTrapFromSitemapXml`), bounded LRU `QuarantineStore`, and WebCrypto HMAC helpers (`signTrapToken`, `verifyTrapToken`, `hashClientIp`, `normalizeClientIp`).
- Built with an agentic workflow; review and test thoroughly before production deployment. Provided "AS IS" under MIT with zero support (`SUPPORT.md`).
