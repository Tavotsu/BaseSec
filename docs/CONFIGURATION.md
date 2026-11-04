# Configuration

BaseSec supports three configuration methods (in order of precedence):

1. CLI flags (highest priority)
2. `.basesecrc` file
3. `package.json` `"basesec"` field

## `.basesecrc` File

Create `.basesecrc` in your project root.

### ESM (`.basesecrc` or `.basesecrc.mjs`)

```js
export default {
  severity: 'low',
  framework: 'auto',
  ignore: ['node_modules', 'dist', 'build', 'coverage', '*.test.ts'],
  taintAnalysis: true,
  rules: [],
  rulesConfig: {
    'SQLI-001': { enabled: true },
    'XSS-001': { enabled: false },
  },
  sanitizers: ['escapeHtml', 'sanitizeInput'],
};
```

### CommonJS (`.basesecrc.cjs`)

```js
module.exports = {
  severity: 'low',
  framework: 'auto',
  ignore: ['node_modules', 'dist', 'build', 'coverage'],
  taintAnalysis: true,
};
```

### JSON (`.basesecrc.json`)

```json
{
  "severity": "low",
  "framework": "auto",
  "ignore": ["node_modules", "dist"],
  "taintAnalysis": true
}
```

## `package.json` Configuration

```json
{
  "name": "my-app",
  "basesec": {
    "severity": "medium",
    "framework": "express",
    "ignore": ["node_modules", "dist"]
  }
}
```

## Configuration Options

| Option | Type | Default | Description |
|---|---|---|---|
| `severity` | `string` | `'low'` | Minimum severity to report |
| `framework` | `string` | `'auto'` | Framework detection mode |
| `ignore` | `string[]` | `['node_modules','dist','coverage']` | Glob patterns to exclude |
| `taintAnalysis` | `boolean` | `true` | Enable taint tracking |
| `rules` | `string[]` | `[]` | Paths to custom rule files |
| `rulesConfig` | `object` | `{}` | Per-rule configuration |
| `sanitizers` | `string[]` | `[]` | Recognized sanitizer function names |

## Framework Option

- `'auto'` — Detect framework from imports and `package.json`
- `'express'` — Force Express detection
- `'nestjs'` — Force NestJS detection
- `'mongoose'` — Force Mongoose detection
- `'typeorm'` — Force TypeORM detection
- `'fastify'`, `'koa'`, `'prisma'` — Force the respective backend framework
- `'react'` — Force React detection (also enabled automatically for `'nextjs'`)
- `'nextjs'` — Force Next.js detection (implies `react`)
- `'vue'` — Force Vue/Nuxt detection
- `'angular'` — Force Angular detection
- `'svelte'` — Force Svelte/SvelteKit detection
- `'*'` — Enable all framework-specific rules

`.vue` and `.svelte` single-file components are scanned by default (script + template); no extra dependency is required.

## Custom Rules

Load external rule modules:

```js
export default {
  rules: ['./custom-rules/my-rule.mjs', './rules/company-policy.cjs'],
};
```

Custom rules must export a rule object compatible with `defineRule()`. See [CONTRIBUTING.md](CONTRIBUTING.md) for rule authoring guide.

## Ignoring Files

Glob patterns use `fast-glob` syntax:

```js
ignore: [
  'node_modules',
  'dist',
  'coverage',
  '**/*.test.ts',
  '**/*.spec.js',
  'migrations/**',
];
```

## Runtime Testing (`dast`)

The `dast` block configures `basesec dast`. Every field is optional. CLI flags take precedence over
the block, and the block takes precedence over built-in defaults.

```ts
// basesec.config.ts
export default defineConfig({
  dast: {
    target: 'http://localhost:3000',
    health: '/healthz',
    headers: { Authorization: 'Bearer $env:API_TOKEN' },
    rps: 20,
    concurrency: 5,
    maxRequests: 5000,
    timeout: 300,            // seconds
    requestTimeout: 10000,   // milliseconds
    evidence: true,
    evidenceDir: '/var/tmp/basesec-evidence',   // absolute path; "~" is not expanded
    rules: ['DAST-001', 'DAST-005'],
    allowRemote: false,
  },
});
```

| Field | Type | Default | Description |
|---|---|---|---|
| `target` | `string` | — | URL used when `basesec dast` is run without an argument |
| `health` | `string` | `'/'` | Healthcheck path |
| `headers` | `Record<string, string>` | `{}` | Request headers. Values may use `$env:NAME` |
| `rps` | `number` | `20` | Requests per second (positive integer) |
| `concurrency` | `number` | `5` | Parallel requests (positive integer) |
| `maxRequests` | `number` | `5000` | Hard request budget (positive integer) |
| `timeout` | `number` | `300` | Global timeout in seconds (positive integer) |
| `requestTimeout` | `number` | `10000` | Per-request timeout in milliseconds (positive integer) |
| `evidence` | `boolean` | `true` | Write `.http` evidence files |
| `evidenceDir` | `string` | `~/.basesec` | Directory for evidence files. Use an absolute path; `~` is not expanded |
| `rules` | `string[]` | all | DAST rule IDs to run |
| `allowRemote` | `boolean` | `false` | Allow non-local targets. **Not enough on its own**: each run still needs the typed host confirmation, or `BASESEC_ALLOW_REMOTE=1` without a terminal |

### Secrets in headers: `$env:NAME`

Do not commit tokens to the config file. Write `$env:NAME` and BaseSec replaces it with the value of
that environment variable when it loads the config. `Bearer $env:API_TOKEN` also works. If the
variable is missing or empty, BaseSec stops with exit code 3 and names only the variable. It never
sends the literal `$env:NAME`. Header names must be HTTP tokens, and values may not contain CR or LF.

Values from `dast.headers` are redacted in evidence files, like values passed with `--header`.

## AI Enhancement

Enable AI-powered analysis to get detailed explanations and detect suspicious taint flows that may bypass existing rules.

```js
export default {
  ai: {
    enabled: true,
    provider: 'ollama',       // 'ollama' or 'openai'
    model: 'llama3.2',        // model name (optional for Ollama)
    contextLevel: 'minimal',   // 'minimal', 'context', or 'file'
    maxFindings: 50,           // max findings to enrich (default: 50)
    timeout: 30000,           // timeout in ms (default: 30000)
  },
};
```

### AI Providers

**Ollama (local):**
```js
ai: {
  enabled: true,
  provider: 'ollama',
  model: 'llama3.2',  // must be running: `ollama serve`
}
```

**OpenAI:**
```js
ai: {
  enabled: true,
  provider: 'openai',
  model: 'gpt-4o-mini',
  // Requires OPENAI_API_KEY environment variable
}
```

### Context Levels

| Level | Description |
|-------|-------------|
| `minimal` | Only the specific tainted expression (default) |
| `context` | Surrounding function/block for context |
| `file` | Full file content for complete context |

### Privacy

On first use, BaseSec displays a privacy notice and prompts for consent. Consent is stored in `~/.basesec/ai-consent`. Use `basesec init --revoke-ai-consent` to revoke.