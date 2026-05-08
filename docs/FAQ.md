# FAQ

## General

### What is BaseSec?

BaseSec is a Static Application Security Testing (SAST) CLI tool for Node.js backends. It scans JavaScript and TypeScript code for security vulnerabilities using AST analysis and taint tracking.

### What frameworks are supported?

Express, NestJS, Mongoose, and TypeORM. Auto-detection is enabled by default.

### Does BaseSec modify my code?

No. BaseSec is read-only. It parses and analyzes your code but never writes to source files.

## Performance

### How fast is BaseSec?

On a typical codebase (~50 files), BaseSec scans in under 2 seconds. With caching enabled, rescans take ~400ms. With workers + cache, large codebases scan in ~130ms. See [PERFORMANCE.md](PERFORMANCE.md).

### Should I use worker threads?

- **< 50 files**: No, worker startup overhead (~200ms) exceeds benefit
- **50-200 files**: Auto-scaling handles this
- **> 200 files**: Explicitly set `--workers <cores>` for best throughput

### Can I disable taint analysis?

Yes:

```bash
basesec scan ./src --no-taint
```

This disables data-flow tracking. Rules that rely on taint analysis will produce fewer findings (only direct pattern matches).

## Configuration

### Can I use TypeScript for `.basesecrc`?

Yes. BaseSec supports `.basesecrc.ts`, `.basesecrc.mjs`, `.basesecrc.cjs`, and `.basesecrc.json`.

### Can I extend or override rules?

Yes. Load custom rule files via the `rules` array in `.basesecrc`:

```js
export default {
  rules: ['./custom-rules/my-rule.mjs'],
};
```

### How do I ignore specific files?

Use `--ignore` (repeatable) or the `ignore` config array:

```bash
basesec scan ./src -i "**/*.test.ts" -i "generated/**"
```

## Output

### Can I output multiple formats at once?

No. Run BaseSec multiple times:

```bash
basesec scan ./src -f json -o report.json
basesec scan ./src -f html -o report.html
```

### Does SARIF output work with GitHub Code Scanning?

Yes. BaseSec generates SARIF 2.1.0 compatible output. Use `github/codeql-action/upload-sarif` to upload.

## Rules

### How many rules are there?

30 rules across 9 categories.

### Can I disable specific rules?

Not directly via CLI. Use `rulesConfig` in `.basesecrc`:

```js
export default {
  rulesConfig: {
    'XSS-001': { enabled: false },
  },
};
```

Or run only specific rules:

```bash
basesec scan ./src -r SQLI-001,SQLI-002
```

### What is taint analysis?

Taint analysis tracks data flow from untrusted sources (user input) to dangerous sinks (database queries, command execution). BaseSec marks variables as "tainted" when they originate from `req.query`, `req.body`, `req.params`, etc., and propagates taint through assignments, concatenation, and template literals.

## CI/CD

### Should I use `--strict` in CI?

Yes, if you want builds to fail on any finding:

```bash
basesec scan ./src --strict
```

Combine with `--severity high` to only fail on serious issues.

### Should I use `--no-cache` in CI?

Yes. CI environments are ephemeral — caching provides no benefit and may cause stale results.

## Development

### How do I run tests?

```bash
pnpm test
pnpm test:coverage
```

### How do I add a new rule?

See [CONTRIBUTING.md](./CONTRIBUTING.md).

### What parser does BaseSec use?

TypeScript Compiler API (`ts.createSourceFile`). Not ts-morph.