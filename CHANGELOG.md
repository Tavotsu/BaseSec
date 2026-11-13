# Changelog

All notable changes to BaseSec are documented in this file.

## [Unreleased]

### Added
- Optional IAST agent that confirms injections by observing canaries reaching real sinks, raising confidence to high with the sink location. Use `basesec dast <url> --start "<cmd>" --agent` (or `--agent` with a manually started app, and `scan --verify --dast-agent`).
- scan --verify --target: confirms static findings at runtime and reports them as verified, with request/response evidence.
- **DAST-008 (unauthenticated sensitive endpoint)**: a sensitive `GET`/`HEAD` route that the route artifact marks `hasAuth: false` and that answers 2xx without credentials is reported (medium, confidence low). Full mode only. New `dast.publicRoutes` config option excludes routes that are public on purpose (`*` matches one path segment).
- **DAST-010 (missing rate limiting)**, opt-in with `--probe-rate-limit` or `dast.probeRateLimit`: a burst of 30 requests to a login or healthcheck target, sent outside `--rps` but counted in the request budget, reports when no response is 429 and none carries rate-limit headers.
- **`DAST-009` is deferred**: detection of verbose errors on malformed input (plan §4.3) needs the mutation tests and arrives with them. It is not implemented and does not appear in `basesec rules`.
- Active black-box injection checks (DAST-101–105, DAST-011) over GET parameters, non-destructive payloads only.
- **`basesec dast <url>`**: runtime testing of a running application, in no-source mode. It checks `/` and the healthcheck with `GET` only and never sends injection payloads. Options cover allowlisted targets (`--allow-remote` with typed host confirmation), rate and request budgets, per-finding redacted `.http` evidence, and `$env:` header secrets.
- **`basesec dast --routes <file>` and `--scan <path>`**: full mode. Each route of the artifact (GET, HEAD and OPTIONS only; mutating endpoints are skipped) is requested, and cookie and stack-trace findings point to the handler's file and lines.
- **DAST rules `DAST-001` to `DAST-007`** (headers, HSTS, CSP, CORS, cookie flags, stack traces, server banner). They are listed by `basesec rules --dast` and are not part of `scan`.
- **`dast` section in the config file** (`basesec.config.*`, `.basesecrc`, `package.json`) with the same options as the CLI flags.
- **`stats.dast` in reports**: JSON, SARIF (`runs[0].properties.dast`), HTML and Markdown show the DAST mode and whether the analysis was incomplete.

### Changed
- SAST: server-side taint sources for Next.js route handlers; Next.js projects may report new findings.
- **BREAKING: `engines.node` now requires patched versions**: `^22.23.4 || ^24.22.1 || >=26.12.1`. Node 18 and 20 are no longer supported (npm warns on install, and `pnpm`/`npm` with `engine-strict` refuse it). Node 22 and 24 releases before these versions are affected by Node2Shell (CVE-2026-111497) and by other CVEs fixed on 2026-10-21.
- Build target raised to `node22`.
- `basesec rules` lists the DAST rules after the SAST rules from a catalog of every implemented DAST rule (DAST-001 to DAST-008, DAST-010, DAST-011, DAST-101 to DAST-105). The title counts the SAST rules only; `--dast` shows the DAST count.

## [0.1.9] - 2026-11-03

### Security
- **Removed `fast-glob`** (replaced by `tinyglobby`) to eliminate its vulnerable transitive chain, which had no upstream remediation path:
  - **CVE-2026-112366** (picomatch 2.3.2, high) — ReDoS via `analyzeRepeatedExtglob`
  - **CVE-2026-93687** (braces 3.0.3, high) — uncontrolled recursion

## [0.1.8] - 2026-10-29

### Security

- **Resolved all open Dependabot alerts (#11–#18)**, all in dev/transitive dependencies:
  - **GHSA-68fv-2mgg-jv7q** (source-map-js, high) — event-loop DoS via indexed source-map section offsets
  - **GHSA-9jrq-w75r-8gcw** (vite, high) — cross-origin script execution through custom middleware
  - **GHSA-rq7h-c2jc-7f22** (vite, medium) — files outside `server.fs.allow` served when project paths match system paths
  - **GHSA-qxg6-89mg-rqv8** (vitest/@vitest/mocker, medium) — code injection via unauthenticated manual mock registration
  - **GHSA-xp26-3454-mjgp** (@vitest/mocker, medium) — Windows backslash traversal bypasses redirect allowlist
  - **GHSA-587h-7wmj-h5pm**, **GHSA-698v-4r3x-3vcv**, **GHSA-r825-w8mm-5pxw** (launch-editor, vite chain) — Windows existence-check bypass, missing `%` escaping, editor CLI flag misinterpretation

### Changed

- `vite` override bumped to `8.1.6`; added overrides for `source-map-js` (`1.2.2`) and `@vitest/mocker` (`4.1.12`)
- `vitest` and `@vitest/coverage-v8` bumped to `^4.1.12`

## [0.1.7] - 2026-07-17

### Added

- **Frontend framework support** — detection for React, Next.js, Vue, Nuxt, Angular, and Svelte (imports + `package.json`); `nextjs` implies `react`. `--framework` accepts the new values.
- **Single-file components** — `.vue` and `.svelte` files are scanned by default; the `<script>` block is parsed as TS/TSX and the template is scanned, with no extra dependency (string-based extraction, real line numbers).
- **23 new rules (42 → 65)**:
  - **DOM (`DOM-001`…`DOM-008`)** — `innerHTML`/`insertAdjacentHTML`, `document.write`, `location`/`window.open` open redirect, wildcard `postMessage`, `message` listener without origin check, tokens in `localStorage`/`sessionStorage`, `eval`/`Function` with network data, prototype pollution via URL params.
  - **React/Next (`REACT-001`…`003`, `NEXT-001`…`002`)** — `dangerouslySetInnerHTML`, JSX `href`/`src`, ref `innerHTML`, `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` secret exposure, `redirect()` open redirect.
  - **Vue (`VUE-001`…`003`)** — `v-html`, `:href`/`:src`, render-function `innerHTML`.
  - **Angular (`NG-001`…`006`)** — `bypassSecurityTrust*`, `nativeElement.innerHTML`, `[innerHTML]`, `HttpClient.jsonp`, router open redirect, unguarded sensitive routes.
  - **Svelte (`SVELTE-001`)** — `{@html}`.
- **Frontend taint sources & sinks** — browser globals (`location`, `document.URL/cookie/referrer`, `localStorage`/`sessionStorage`) and framework hooks/routes (`useSearchParams`, `$route`, `ActivatedRoute.snapshot`, `$page`) as taint sources; DOM navigation/HTML sinks.

### Fixed

- `.tsx` files were parsed as `ts.ScriptKind.TS` instead of `TSX`, so JSX was not parsed as JSX.
- Version string was hardcoded and out of sync across the CLI banner, `--version`, and report formatters; now sourced from a single `VERSION` constant.
- Silent `catch {}` when loading a malformed config file — now surfaced via `logger.warn`.

## [0.1.6] - 2026-06-15

### Security

- **Resolved all open Dependabot alerts** by pinning patched versions via `pnpm.overrides` in `pnpm-workspace.yaml`:
  - **#1 GHSA-g7r4-m6w7-qqqr** (esbuild, low) — CWE-22 path traversal on Windows dev server
  - **#2 GHSA-gv7w-rqvm-qjhr** (esbuild, high) — CWE-426 untrusted search path + CWE-494 download of code without integrity check (Deno binary)
  - **#3 GHSA-fx2h-pf6j-xcff** (vite, high) — CWE-22 + CWE-200 `server.fs.deny` bypass on Windows
  - **#4 GHSA-v6wh-96g9-6wx3** (vite, medium) — CWE-73 + CWE-522 NTLMv2 hash disclosure via `launch-editor`

### Changed

- `esbuild` pinned to `0.28.1` across the whole dependency tree (was still being pulled transitively at `0.27.7` through `vitest` → `vite` chain)
- `vite` pinned to `8.0.16` (transitive, via vitest)
- `pnpm-workspace.yaml` is now tracked in git (no longer gitignored) so overrides are reproducible across clones
- Removed obsolete `pnpm.onlyBuiltDependencies` from `package.json` (pnpm 11 reads it from `pnpm-workspace.yaml > allowBuilds`)

## [0.1.5] - 2026-06-15

### Security

- **esbuild upgraded to `0.28.1`** to address CWE-426 (Untrusted Search Path) and CWE-494 (Download of Code Without Integrity Check) reported in `0.27.x`
- `tsconfig.json`: added `ignoreDeprecations: "6.0"` to silence the `baseUrl` deprecation warning under TypeScript 6.0

### Changed

- `package.json` description rewritten with richer SEO keywords and 158 keywords added across security, framework, vulnerability, AI, and CI/CD categories for improved discoverability on npm and GitHub

## [0.1.4] - 2026-06-04

### Added

- **AI-powered analysis enhancement** — enriches findings with AI-generated explanations and detects suspicious taint flows that may bypass existing rules
  - `--ai` flag to enable AI analysis
  - `--ai-provider` for Ollama (local) or OpenAI
  - `--ai-model` to specify model
  - `--ai-context` for context level: `minimal`, `context`, or `file`
  - `--ai-dry-run` to preview what would be sent to the LLM without sending
  - Privacy consent prompt before any data is sent
  - Stores consent in `~/.basesec/ai-consent`
- **Auto-save reports to `~/.basesec/`** — when using `--format` with a non-terminal format (`json`, `sarif`, `html`, `markdown`) without an explicit `--output` path, reports are automatically saved to `~/.basesec/scan-<timestamp>.<format>`
- **`--output` accepts optional argument** — `-o` without a path saves to `~/.basesec/`; `-o <path>` saves to the specified location

### Changed

- **Default behavior for non-terminal formats** — no longer requires `-o` flag to save reports; using `--format sarif` alone will save the report

## [0.1.3] - 2026-06-01

### Fixed

- **Windows didn't recognize flags** — added `hasArg()` and `getArgValue()` helpers to detect both kebab-case (`--read-env`) and camelCase (`--readEnv`) CLI arguments
- **Flag: --help was outdated** — added `0.1.1` and `0.1.2` flags to `--help`

## [0.1.2] — 2026-05-23

### Added

- **Fastify support** — detection logic, taint sources (`request.body`, etc.), and 3 new rules:
  - `FASTIFY-001`: Missing Fastify Rate Limiting
  - `FASTIFY-002`: Missing Fastify Helmet
  - `FASTIFY-003`: Missing Fastify CORS
- **Koa support** — detection logic, taint sources (`ctx.request.body`, etc.), and 3 new rules:
  - `KOA-001`: Missing Koa Helmet
  - `KOA-002`: Missing Koa CORS
  - `KOA-003`: Unsafe ctx.body with User Input
- **Prisma support** — detection logic, dangerous sinks (`$queryRaw`, `$executeRaw`, etc.), and 2 new rules:
  - `PRISMA-001`: Prisma Raw Query Injection
  - `PRISMA-002`: Unsafe Prisma Raw Query
- **Dependency checking** — 4 new rules (DEP-001 to DEP-004) in new `dependency-check` category
  - `DEP-001`: Outdated dependencies with known CVEs (bundled CVE database for top npm packages)
  - `DEP-002`: Vulnerable dependencies via `pnpm audit` / `npm audit` integration
  - `DEP-003`: Unused dependencies detection (declared but never imported)
  - `DEP-004`: Lockfile mismatch detection (package.json out of sync with lockfile)
- **`--no-deps` CLI flag** — skip dependency checking during scan
- **`--read-env` CLI flag** — allows scanning of `.env` files (which are skipped by default) to detect hardcoded secrets
- **`--verbose` CLI flag** — added detailed logging and robust error reporting
- **Config exposure** — hardcoded settings are now configurable via `.basesecrc` (`maxFileSize`, `maxFiles`, `cache.maxAge`, `cache.dir`, `workers.threshold`, `workers.max`)
- **CLI input validation** — explicit validation and clear error messages for `--framework` and `--workers` inputs

### Fixed

- **Error handling improvements** — removed silent `catch {}` blocks across the codebase, replacing them with proper warning logs when `--verbose` is enabled
- **Test coverage** — added missing tests for CLI init, worker pool, pipeline, rule registry, taint sources, taint sinks, and TypeORM patterns (coverage increased to 342 tests)
- **Sensitive file protection** — `.env`, `.pem`, `.key`, credentials files are now skipped entirely during scanning (hard skip in file collector) unless `--read-env` is passed
- **Config override warning** — warns when user config removes sensitive file ignore patterns

### Security

- Sensitive files (`.env`, `.pem`, `.key`, `.p12`, `.pfx`, `secrets.*`, `credentials.*`) are never scanned, even if removed from ignore patterns, unless explicitly opted-in via `--read-env` this is 

## [0.1.1] — 2026-05-10

### Fixed

- **`typescript` moved to `dependencies`** — fixes `ERR_MODULE_NOT_FOUND: Cannot find package 'typescript'` when installing globally via `npm i -g basesec`
- **NestJS taint propagation** — `@Body()`, `@Param()`, `@Query()`, `@Headers()`, `@Req()` decorator parameters now correctly registered as taint sources; enables detection of SQLI-002, CMDI-001 on NestJS code
- **ERR-001 (Exposed Stack Trace)** — broadened detection to catch any `.stack` or `.message` access inside response arguments (e.g., `res.json({ error: new Error().stack })`)
- **NOSQL-002 over-reporting** — Mongoose `detectMongoosePatterns()` now separates line numbers by pattern type (`leanLineNumbers`, `directQueryLineNumbers`, `whereLineNumbers`) to avoid false positives on `.lean()` calls
- **`isExpressionTainted()` substring matching** — tainted variables embedded in larger expressions (e.g., `'rm -rf ' + body.path`) are now detected via `matchesExpression()` substring checks
- **`package.json` entry points** — corrected `main`, `bin`, `exports` to point to `dist/index.js` (was `dist/cli.js`)
- **`package.json` metadata** — added `repository`, `bugs`, `homepage` fields

## [0.1.0] — 2025-05-07

### Added

- **30 security rules** across 9 categories (SQL Injection, XSS, NoSQL Injection, Command Injection, Path Traversal, Authentication, Secrets, Error Handling, Misconfiguration)
- **Taint analysis engine** — tracks data flow from user input to dangerous sinks
- **Framework detection** — auto-detects Express, NestJS, Mongoose, TypeORM
- **5 output formats** — Terminal, JSON, SARIF, HTML, Markdown
- **Analysis cache** — SHA-256 hash-based per-file caching for incremental scans
- **Worker threads** — multi-core parallel analysis via `node:worker_threads`
- **Custom rules** — load external MJS/CJS rule modules via `.basesecrc`
- **CLI flags** — `--workers`, `--no-cache`, `--strict`, `--no-taint`, `--framework`, `--severity`
- **Configuration system** — `.basesecrc` (ESM/CJS/JSON), `package.json` field
- **Init command** — `basesec init` generates `.basesecrc` template
- **Comprehensive test suite** — 312 tests, ~88.75% statement coverage
- **Performance benchmarks** — documented 12x speedup with cache + workers
- **Full documentation** — README, INSTALLATION, USAGE, CONFIGURATION, RULES, CONTRIBUTING, CI_CD, TROUBLESHOOTING, FAQ, EXAMPLES, CHANGELOG, SECURITY, PERFORMANCE

### Security

- 34 bugs fixed during security audit (4 critical, 14 high, 10 medium, 6 low)
- Taint argument extraction fixed in 11 rules
- Framework import false positives resolved via exact matching
- XSS receiver validation added
- TypeORM framework detection fixed

## 0.0.9 — 2025-04-01

### Added

- Initial project scaffold
- CLI with `scan` and `init` commands
- Core pipeline: FileCollector → Parser → Analyzer → ResultStore
- TypeScript Compiler API parser
- Basic rule registry and loader
- Terminal and JSON formatters

[0.1.0]: https://github.com/tavotsu/basesec/releases/tag/v0.1.0