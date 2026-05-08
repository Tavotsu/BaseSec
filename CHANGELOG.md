# Changelog

All notable changes to BaseSec are documented in this file.

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