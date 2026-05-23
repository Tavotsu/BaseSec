# Changelog

All notable changes to BaseSec are documented in this file.

## [0.1.2] — Unreleased

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