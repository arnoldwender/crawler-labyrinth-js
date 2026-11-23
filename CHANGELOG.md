# Changelog

All notable changes to `crawler-labyrinth` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-23

### Added
- Initial public release of the zero-dependency Web-standard (`Request` / `Response` + WebCrypto) core package extracted from `astro-crawler-labyrinth`.
- Exports `createLabyrinthHandler` (and `createEdgeLabyrinthHandler` alias) supporting `hybrid`, `labyrinth`, `block`, and dry-run `observe` modes, global `burstLimitPerMinute` shedding, `entryVector` telemetry (`signed_bait`, `robots_probe`, `ua_guard`), and `X-Crawler-Labyrinth` state headers.
- Exports accessible-inert bait helpers (`buildBaitLinks`, `renderCrawlerBaitHtml`), deterministic archival decoy generator (`generateDecoyDocument`), RFC 9309 multi-group `robots.txt` patcher (`patchRobotsTxt`), sitemap cleaner (`stripTrapFromSitemapXml`), bounded LRU `QuarantineStore`, and WebCrypto HMAC helpers (`signTrapToken`, `verifyTrapToken`, `hashClientIp`, `normalizeClientIp`).
- Built with an agentic workflow; review and test thoroughly before production deployment. Provided "AS IS" under MIT with zero support (`SUPPORT.md`).
