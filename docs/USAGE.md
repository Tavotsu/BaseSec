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
| `--framework <fw>` | | Force framework: `express`, `nestjs`, `mongoose`, `typeorm`, `fastify`, `koa`, `prisma`, `react`, `nextjs`, `vue`, `angular`, `svelte`, `auto` | `auto` |
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

## Runtime testing (`basesec dast`)

> **Legal warning.** Run `basesec dast` only against systems you own or for which you have
> **written authorization** from the owner. It sends real HTTP requests to the target. By default
> it accepts only loopback (`127.0.0.1`, `::1`, `localhost`) and private networks
> (`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`). Link-local addresses, including cloud metadata
> at `169.254.169.254`, are always blocked. Testing a system without authorization is a crime in
> most jurisdictions.

`basesec dast <url>` tests a **running** application at runtime. This first version runs in
**no-source mode**: it does not read your code, so it has no routes to attack. It sends `GET` to
`/` and to the healthcheck, then checks headers, cookies, CORS and error pages (`DAST-001` to
`DAST-007`). It never sends injection payloads.

```bash
# Local app, default checks
basesec dast http://localhost:3000

# Healthcheck on another path, JSON report saved to a file
basesec dast http://localhost:3000 --health /healthz -f json -o ./dast.json

# Authenticated check; the token is read from the environment, not from the command line
basesec dast http://localhost:3000 --header 'Authorization: Bearer $env:API_TOKEN' --strict

# Non-local target: requires --allow-remote and typing the host to confirm
basesec dast https://staging.example.com --allow-remote
```

When the run is non-interactive (CI), a remote host also needs `BASESEC_ALLOW_REMOTE=1`.
`allowRemote` in the config file is not enough on its own.

| Flag | Default | Description |
|---|---|---|
| `--health <path>` | `/` | Healthcheck path, observed in addition to `/` |
| `--header <header>` | — | Request header `"Name: value"`, repeatable. Overrides the same header from the config (case-insensitive) |
| `--allow-remote` | off | Allow non-local targets. Requires typing the host, or `BASESEC_ALLOW_REMOTE=1` without a terminal |
| `--rps <n>` | 20 | Requests per second |
| `--concurrency <n>` | 5 | Parallel requests |
| `--max-requests <n>` | 5000 | Hard request budget |
| `--timeout <s>` | 300 | Global timeout in seconds |
| `--request-timeout <ms>` | 10000 | Per-request timeout |
| `--evidence-dir <dir>` | `~/.basesec` | Directory for evidence files (created with the first finding) |
| `--no-evidence` | off | Do not write evidence files |
| `--rules <ids>` | all | Comma-separated DAST rule IDs, e.g. `DAST-001,DAST-005` |
| `--config`, `-c` | — | Path to config file |
| `--allow-vulnerable-node` | off | Run even if Node lacks the mandatory security patches |
| `--format`, `-f` / `--output`, `-o` | `terminal` | Same as `scan` |
| `--severity`, `-s` | `low` | Minimum severity to report, same as `scan` |
| `--strict` | off | Exit 1 if there are findings |
| `--quiet`, `-q` / `--verbose`, `-V` / `--no-color` / `--no-banner` | — | Same as `scan` |

Progress is printed to stderr, so `basesec dast <url> -f json > out.json` stays valid JSON.

### No-source mode

The output starts with a warning. Findings are reported as "no confirmed at runtime", not as
"secure". With `--format json`, `stats.dast.mode` is `"no-source"`, so integrations can tell a
shallow check apart from a full one. Incomplete runs (request budget or timeout) say so in
`stats.dast.incomplete` and in the summary. They do not change the exit code.

### Evidence

Each finding gets a redacted `.http` file in `~/.basesec/dast-<timestamp>/`, for example
`DAST-005-7143753f.http`. It opens in VS Code (REST Client) or IntelliJ. Cookie values, values of
`--header` and `$env:` secrets are replaced with `[REDACTED]`. The body is truncated to 8 KB. The
directory has mode `0700` and files have mode `0600`. Existing files are never overwritten.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | No findings (or findings below the severity threshold, without `--strict`) |
| 1 | Findings with `--strict` |
| 2 | Target unreachable or unexpected error |
| 3 | Configuration error, invalid flag, blocked host (no request was sent), missing `$env:` variable, or Node below the patched floor |

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