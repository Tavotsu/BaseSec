# Usage

## Commands

### `basesec scan [path]`

Scan a directory for vulnerabilities.

```bash
basesec scan
basesec scan ./src
basesec scan ./src --format json --output report.json
```

#### Options

| Flag | Short | Description | Default |
|---|---|---|---|
| `--format <format>` | `-f` | Output format: `terminal`, `json`, `sarif`, `html`, `markdown` | `terminal` |
| `--output [file]` | `-o` | Write report to file. Without argument, saves to `~/.basesec/scan-<timestamp>.<format>` | stdout (terminal) or auto-save (other formats) |
| `--severity <level>` | `-s` | Minimum severity: `critical`, `high`, `medium`, `low`, `info` | `low` |
| `--rules <ids>` | `-r` | Comma-separated rule IDs to run | all |
| `--ignore <pattern>` | `-i` | Glob patterns to ignore (repeatable) | `['node_modules','dist','coverage']` |
| `--config <path>` | `-c` | Path to config file | `.basesecrc` |
| `--no-taint` | | Disable taint analysis | enabled |
| `--quiet` | `-q` | Only show summary | disabled |
| `--strict` | | Exit with code 1 if any finding | disabled |
| `--framework <fw>` | | Force framework: `express`, `nestjs`, `mongoose`, `typeorm`, `fastify`, `koa`, `prisma`, `auto` | `auto` |
| `--no-color` | | Disable colored output | enabled |
| `--no-banner` | | Disable banner | enabled |
| `--workers <num>` | | Worker threads (0=disabled, auto=auto-scale) | auto |
| `--no-cache` | | Disable result caching | enabled |
| `--read-env` | | Allow scanning of `.env` files | disabled |
| `--verbose` | `-V` | Show verbose output | disabled |
| `--ai` | | Enable AI-powered analysis enhancement | disabled |
| `--ai-provider <provider>` | | AI provider: `ollama` or `openai` | config |
| `--ai-model <model>` | | AI model to use | config |
| `--ai-context <level>` | | Context level: `minimal`, `context`, `file` | `minimal` |
| `--ai-dry-run` | | Show what would be sent to LLM without sending | disabled |
| `--help` | `-h` | Show help | |

#### Examples

```bash
# Terminal output with colors (stdout only)
basesec scan ./src

# JSON auto-saved to ~/.basesec/scan-<timestamp>.json
basesec scan ./src --format json

# SARIF auto-saved to ~/.basesec/scan-<timestamp>.sarif
basesec scan ./src -f sarif

# Explicit output path (overrides auto-save)
basesec scan ./src -f sarif -o ./results.sarif

# Only critical findings, fail CI
basesec scan ./src -s critical --strict

# Scan with 4 worker threads, no cache
basesec scan ./src --workers 4 --no-cache

# Ignore test files
basesec scan ./src -i "**/*.test.ts" -i "**/*.spec.ts"

# Run only SQL injection rules
basesec scan ./src -r SQLI-001,SQLI-002,SQLI-003,SQLI-004

# Scan including .env files (for secret detection)
basesec scan ./src --read-env

# AI-enhanced scan with local Ollama
basesec scan ./src --ai --ai-provider ollama --ai-model llama3.2

# AI scan with OpenAI (requires OPENAI_API_KEY env var)
basesec scan ./src --ai --ai-provider openai --ai-model gpt-4o-mini

# Preview what AI would send without actually sending
basesec scan ./src --ai --ai-dry-run
```

### `basesec init`

Create a `.basesecrc` configuration file in the current directory.

```bash
basesec init
basesec init --revoke-ai-consent
```

The `--revoke-ai-consent` flag revokes AI consent stored in `~/.basesec/ai-consent`.

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success, no findings (or findings below severity threshold) |
| 1 | Findings detected (with `--strict`) |
| 2 | Invalid arguments or configuration error |

## Output Formats

### Terminal

Colored table output. Default. Always prints to stdout. No auto-save.

### JSON / SARIF / HTML / Markdown

When using these formats, reports are **automatically saved** to `~/.basesec/scan-<timestamp>.<format>` unless you specify an explicit path with `--output`.

```bash
# Auto-saves to ~/.basesec/scan-2026-06-03T12-00-00.json
basesec scan ./src --format json

# Saves to custom location
basesec scan ./src --format sarif --output ./results.sarif
```