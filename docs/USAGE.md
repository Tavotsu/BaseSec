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
| `--output <file>` | `-o` | Write report to file | stdout |
| `--severity <level>` | `-s` | Minimum severity: `critical`, `high`, `medium`, `low`, `info` | `low` |
| `--rules <ids>` | `-r` | Comma-separated rule IDs to run | all |
| `--ignore <pattern>` | `-i` | Glob patterns to ignore (repeatable) | `['node_modules','dist','coverage']` |
| `--config <path>` | `-c` | Path to config file | `.basesecrc` |
| `--no-taint` | | Disable taint analysis | enabled |
| `--quiet` | `-q` | Only show summary | disabled |
| `--strict` | | Exit with code 1 if any finding | disabled |
| `--framework <fw>` | | Force framework: `express`, `nestjs`, `mongoose`, `typeorm`, `auto` | `auto` |
| `--no-color` | | Disable colored output | enabled |
| `--no-banner` | | Disable banner | enabled |
| `--workers <num>` | | Worker threads (0=disabled, auto=auto-scale) | auto |
| `--no-cache` | | Disable result caching | enabled |
| `--help` | `-h` | Show help | |

#### Examples

```bash
# Terminal output with colors
basesec scan ./src

# JSON report to file
basesec scan ./src -f json -o report.json

# SARIF for GitHub Advanced Security
basesec scan ./src -f sarif -o results.sarif

# Only critical findings, fail CI
basesec scan ./src -s critical --strict

# Scan with 4 worker threads, no cache
basesec scan ./src --workers 4 --no-cache

# Ignore test files
basesec scan ./src -i "**/*.test.ts" -i "**/*.spec.ts"

# Run only SQL injection rules
basesec scan ./src -r SQLI-001,SQLI-002,SQLI-003,SQLI-004
```

### `basesec init`

Create a `.basesecrc` configuration file in the current directory.

```bash
basesec init
```

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success, no findings (or findings below severity threshold) |
| 1 | Findings detected (with `--strict`) |
| 2 | Invalid arguments or configuration error |

## Output Formats

### Terminal

Colored table output. Default. Best for local development.

### JSON

Machine-readable array of findings.

### SARIF

Standard format for security tools. Compatible with GitHub Code Scanning, Azure DevOps, and other SARIF consumers.

### HTML

Self-contained HTML report with severity statistics and code snippets.

### Markdown

GitHub-flavored Markdown suitable for PR comments or documentation.