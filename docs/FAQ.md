# FAQ

## General

### What is BaseSec?

BaseSec is a Static Application Security Testing (SAST) CLI tool for Node.js backends. It scans JavaScript and TypeScript code for security vulnerabilities using AST analysis and taint tracking.

### What frameworks are supported?

Express, NestJS, Mongoose, TypeORM, Fastify, Koa, and Prisma. Auto-detection is enabled by default.

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

### Where are reports saved?

Non-terminal formats (JSON, SARIF, HTML, Markdown) auto-save to `~/.basesec/scan-<timestamp>.<format>` by default. Use `-o <path>` to specify a custom location:

```bash
# Auto-save to ~/.basesec/scan-2026-06-03T12-00-00.sarif
basesec scan ./src --format sarif

# Save to custom path
basesec scan ./src -f sarif -o ./results.sarif
```

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

42 rules across 10 categories, plus AI-001 for AI-enhanced detection.

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

## AI Enhancement

### Does BaseSec require AI?

No. BaseSec is fully functional without AI. All 42 security rules work offline with no external dependencies. AI enhancement is entirely opt-in.

### What does AI enhancement do?

When enabled, AI can:
- Provide detailed explanations for findings
- Detect suspicious taint flows that may bypass existing rules (AI-001)

### How do I enable AI?

1. Add AI config to `.basesecrc`:
   ```js
   export default {
     ai: {
       enabled: true,
       provider: 'ollama', // or 'openai'
       model: 'llama3.2',
     },
   };
   ```
2. Run with `--ai` flag:
   ```bash
   basesec scan ./src --ai
   ```

### Which AI providers are supported?

**Ollama (local, recommended):**
- Privacy-preserving: data never leaves your machine
- Requires `ollama serve` running locally
- Free and open source

**OpenAI:**
- Requires `OPENAI_API_KEY` environment variable
- Data is sent to OpenAI's servers — see responsibility notice below

### Who is responsible for data sent to AI providers?

**You are.** BaseSec does not store, log, or retain any code sent to AI providers. However:

- When using OpenAI (or any cloud-based LLM), your code snippets are transmitted to the provider's servers
- Review the provider's privacy policy before use
- For maximum privacy, use Ollama (local) — no data leaves your machine
- BaseSec is not responsible for the privacy practices or data handling of third-party AI providers

### Can I preview what would be sent without actually sending?

Yes:
```bash
basesec scan ./src --ai --ai-dry-run
```

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