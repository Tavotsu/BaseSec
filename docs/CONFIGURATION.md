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

- `'auto'` — Detect framework from imports
- `'express'` — Force Express detection
- `'nestjs'` — Force NestJS detection
- `'mongoose'` — Force Mongoose detection
- `'typeorm'` — Force TypeORM detection
- `'*'` — Enable all framework-specific rules

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