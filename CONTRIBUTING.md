# Contributing to Crawler Labyrinth

Contributions that improve correctness, runtime compatibility, accessibility, or test coverage are welcome.

## Support & Issue Scope

**Zero technical, setup, or private support is provided.** See [SUPPORT.md](SUPPORT.md):

- Report reproducible code defects **exclusively** via public [GitHub Issues](https://github.com/arnoldwender/crawler-labyrinth-js/issues).
- **Do not** contact the author privately via email, `arnoldwender.com`, or direct messages — private inquiries are never answered.
- Issues and pull requests carry no guaranteed response or maintenance SLA, and the software is provided strictly **"AS IS"** without warranty or liability.

---

## Development Setup

1. Fork the repository and create a branch from `main`.
2. Install dependencies with Node.js `>= 20.0.0`:
   ```bash
   npm install
   npm run typecheck
   npm run build
   npm test
   npm run test:mutations
   ```
3. Add or update unit/integration tests in `test/labyrinth.test.ts` covering your change.

---

## Pull Request Guidelines

- Keep PRs focused on a single bug fix or enhancement.
- Ensure `npm run typecheck`, `npm run build`, `npm test`, `npm run test:mutations`, and `npm pack --dry-run` succeed without warnings or skipped tests.
- Keep all modules strictly runtime-agnostic (Web Standards `Request` / `Response`, `URL`, `Headers`, `TextEncoder`, and `globalThis.crypto.subtle` only — zero Node built-ins in `src/`).
- Do **not** store raw client IP addresses, commit secrets/API keys, or block search/citation crawlers in default configurations.
- Update `README.md` or `CHANGELOG.md` whenever behavior, options, or exported types change.

---

## Licensing of Contributions

By submitting a pull request or patch to this repository, you agree that your contributions will be licensed under the [MIT License](LICENSE).
