
<p align="center">
  <img src="https://github.com/Tavotsu/BaseSec/blob/gh-pages/website/public/logo.png?raw=true" alt="logo" width=300px height=300px>
</p>
Static Application Security Testing (SAST) CLI tool for Node.js backends.  
Scans JavaScript and TypeScript source files, detects vulnerabilities via AST analysis and taint tracking, and reports findings in terminal, JSON, SARIF, HTML, or Markdown.

## Features

- **42 Security Rules** across 10 categories (SQL Injection, XSS, NoSQL Injection, Command Injection, Path Traversal, Authentication, Secrets, Error Handling, Misconfiguration, Dependency Checking)
- **Taint Analysis** — tracks data flow from user input (`req.query`, `req.body`, etc.) to dangerous sinks
- **Framework Detection** — auto-detects Express, NestJS, Mongoose, TypeORM, Fastify, Koa, and Prisma
- **Dependency Checking** — detects outdated packages with known CVEs, vulnerable dependencies (via `pnpm/npm audit`), unused dependencies, and lockfile mismatches
- **Sensitive File Protection** — `.env` and credential files are completely ignored by default unless explicitly allowed with `--read-env`
- **Multiple Output Formats** — Terminal (colored tables), JSON, SARIF, HTML, Markdown
- **Analysis Cache** — hash-based per-file caching for 10x speedup on incremental scans
- **Worker Threads** — multi-core parallel analysis for large codebases
- **Custom Rules** — load external rule files (MJS/CJS) via `.basesecrc`
- **Zero Configuration** — works out of the box with sensible defaults

## Quick Start

### Install

```bash
npm install -g basesec
# or
pnpm add -g basesec
# or
yarn global add basesec
```

### Scan

```bash
# Scan current directory
basesec scan

# Scan specific directory
basesec scan ./src

# JSON output
basesec scan ./src --format json --output report.json

# Only critical/high findings, strict exit code
basesec scan ./src --severity high --strict
```

## Framework Support

| Framework | Auto-Detection | Notes |
|---|---|---|
| Express | Yes | Route handlers, middleware, `res.send()`, `res.set()` |
| NestJS | Yes | Decorators (`@Controller`, `@Get`, etc.), guards |
| Fastify | Yes | Route handlers, rate limit, helmet, CORS |
| Koa | Yes | Context assignments (`ctx.body`), middleware |
| Mongoose | Yes | Query chains, `$where`, `lean()` |
| TypeORM | Yes | Query builder, raw queries |
| Prisma | Yes | Raw queries (`$queryRaw`, `$executeRaw`) |

## Configuration

Create a `.basesecrc` file in your project root:

```js
export default {
  severity: 'low',
  framework: 'auto',
  ignore: ['node_modules', 'dist', 'coverage'],
  taintAnalysis: true,
  rules: [],
  rulesConfig: {},
  maxFileSize: 512000,
  maxFiles: 10000,
};
```

See [CONFIGURATION.md](docs/CONFIGURATION.md) for full options.

## Performance

BaseSec uses two core optimizations:

1. **Analysis Cache** (enabled by default) — SHA-256 file + config hashing, skips unchanged files
2. **Worker Threads** (auto-enabled for >50 files) — parallel analysis across CPU cores

Combined, these deliver **~12x speedup** on rescans. See [PERFORMANCE.md](PERFORMANCE.md) for benchmark data.

## Documentation

- [INSTALLATION.md](docs/INSTALLATION.md) — Detailed installation options
- [USAGE.md](docs/USAGE.md) — CLI commands and flags
- [CONFIGURATION.md](docs/CONFIGURATION.md) — Configuration file reference
- [RULES.md](docs/RULES.md) — Complete rule catalog
- [PERFORMANCE.md](PERFORMANCE.md) — Benchmarks and optimization guide
- [CI_CD.md](docs/CI_CD.md) — CI/CD integration examples
- [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) — Common issues and fixes
- [FAQ.md](docs/FAQ.md) — Frequently asked questions
- [EXAMPLES.md](docs/EXAMPLES.md) — Vulnerable vs. secure code examples
- [CONTRIBUTING.md](CONTRIBUTING.md) — How to contribute
- [CHANGELOG.md](CHANGELOG.md) — Version history
- [SECURITY.md](SECURITY.md) — Security policy

## License

MIT © tavotsu
