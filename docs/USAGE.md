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

`basesec dast <url>` tests a **running** application at runtime. It sends `GET` to `/` and to the
healthcheck, then checks headers, cookies, CORS and error pages (`DAST-001` to `DAST-007`). These passive
checks never send payloads. In full mode, the active injection checks described below also run.

With no route surface it runs in **no-source mode**. When a route surface is available (from
`--routes`, `--scan`, or the saved artifact described below) it runs in **full mode**: it also sends
`GET`, `HEAD` and `OPTIONS` to every endpoint, and checks cookies (`DAST-005`) and stack traces
(`DAST-006`) on each response. Such findings point to the handler's file and lines.

```bash
# Local app, default checks
basesec dast http://localhost:3000

# Healthcheck on another path, JSON report saved to a file
basesec dast http://localhost:3000 --health /healthz -f json -o ./dast.json

# Authenticated check; the token is read from the environment, not from the command line
basesec dast http://localhost:3000 --header 'Authorization: Bearer $env:API_TOKEN' --strict

# Non-local target: requires --allow-remote and typing the host to confirm
basesec dast https://staging.example.com --allow-remote

# Full mode: routes derived from the code in memory, nothing written to disk
basesec dast http://localhost:3000 --scan ./src

# Full mode with an explicit route artifact
basesec dast http://localhost:3000 --routes ./routes.json
```

**Where the route surface comes from.** `--routes <file>` uses that artifact; it is an error if the
file is missing or invalid, and nothing is sent. `--scan <path>` analyzes the code with the normal
project configuration and keeps the routes in memory; it writes nothing to disk. `--routes` and
`--scan` cannot be used together. Without either flag, BaseSec looks for the artifact saved by
`basesec scan <path> --emit-routes` for the project root: the nearest directory with `package.json`,
starting from the current directory. It is stored in `~/.basesec/routes/<hash>.json`. An invalid saved
artifact is ignored with a warning. Use `--routes` or `--scan` when the directory where you run
`dast` is not the project root, for example in a monorepo.

Endpoints with a mutating method (`POST`, `PUT`, `PATCH`, `DELETE`) are never requested: they are
counted and skipped. Mutation testing is not available yet.

When the run is non-interactive (CI), a remote host also needs `BASESEC_ALLOW_REMOTE=1`.
`allowRemote` in the config file is not enough on its own.

| Flag | Default | Description |
|---|---|---|
| `--routes <file>` | saved artifact | Route artifact to test in full mode. Invalid or missing file: exit 3, no request is sent |
| `--scan <path>` | — | Derive the routes from this code path in memory (full mode). Cannot be combined with `--routes` |
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
| `--rules <ids>` | all | Comma-separated DAST rule IDs, e.g. `DAST-001,DAST-005`. Active and injection IDs (`DAST-008`, `DAST-010`, `DAST-011`, `DAST-101` to `DAST-105`) select their checks |
| `--probe-rate-limit` | off | Enables `DAST-010`: 30 rapid requests to a login or to the healthcheck. Also `dast.probeRateLimit: true` in the config |
| `--agent` | off | Confirms injections with the IAST agent: a canary that reaches a real sink raises the finding to `high`. Needs routes. See [IAST agent](#iast-agent---agent---start) |
| `--start <cmd>` | — | Starts the app with the agent injected, waits for `--health`, and stops it (whole process group) when done. Implies `--agent`. Not read from the config |
| `--start-timeout <s>` | 60 | Seconds to wait for the app to answer with `--start` |
| `--agent-dir <dir>` | `$BASESEC_AGENT_DIR` or the tmp dir | Directory with the agent sockets, for an app started by hand. Needs `--agent` |
| `--config`, `-c` | — | Path to config file |
| `--allow-vulnerable-node` | off | Run even if Node lacks the mandatory security patches |
| `--format`, `-f` / `--output`, `-o` | `terminal` | Same as `scan` |
| `--severity`, `-s` | `low` | Minimum severity to report, same as `scan` |
| `--strict` | off | Exit 1 if there are findings |
| `--quiet`, `-q` / `--verbose`, `-V` / `--no-color` / `--no-banner` | — | Same as `scan` |

Progress is printed to stderr, so `basesec dast <url> -f json > out.json` stays valid JSON.

### No-source mode and full mode

Without a route surface the output starts with a warning, and findings are reported as "no confirmed
at runtime", not as "secure". With `--format json`, `stats.dast.mode` is `"no-source"` or `"full"`, so
integrations can tell a shallow check apart from a full one. Incomplete runs (request budget or timeout) say so in
`stats.dast.incomplete` and in the summary. They do not change the exit code.

### Active checks (injection)

Active checks run only in **full mode** (`--routes`, `--scan`, or a saved artifact). Read this first:

- **Only `GET`, `HEAD` and `OPTIONS` endpoints are attacked, and only their path and query parameters.**
  Request bodies are never touched, and mutating endpoints (`POST`, `PUT`, `PATCH`, `DELETE`) are never
  requested. Without a route surface there are no parameters, so nothing is injected.
- **The payloads are non-destructive.** They are read-only queries, always-true conditions, delays of at
  most 2 seconds, reads of well-known read-only files (`/etc/passwd`, `win.ini`) and unique canary strings.
  No payload writes, deletes, creates or redirects output to a file. A test checks every payload in the
  catalog against that rule.
- Each finding is confirmed by an oracle (reflection, SQL error signature, timing with a control request,
  response difference, or redirect to another host). Oracles with weak evidence report low confidence.

| Class | Rule | Severity | Oracle |
|---|---|---|---|
| SQL injection | `DAST-101` | critical | SQL error signature, or timing with a control |
| NoSQL injection (`param[$ne]=…`) | `DAST-102` | high | Stable response difference, low confidence |
| Command injection | `DAST-103` | critical | Canary echoed in the output, or timing with a control |
| Path traversal | `DAST-104` | critical | `/etc/passwd` or `win.ini` contents |
| Reflected XSS | `DAST-105` | high | Unescaped canary in an HTML response |
| Open redirect | `DAST-011` | medium | `Location` to another host that carries the canary |

Each class reports at most once per endpoint. A finding names the parameter and the oracle, and lists any
static finding of the same class at that handler as a possible origin. Select classes with
`--rules DAST-105`, for example. The run budget (`--max-requests`) also covers the injection requests.
At most 40 requests go to each endpoint, so an endpoint with many parameters may leave some untested. NoSQL
operators are sent only in query parameters. A timing finding needs the delayed response twice and a zero-delay
control that stays fast.

### Authentication and rate limit checks (DAST-008, DAST-010)

Both checks run only in **full mode**, except `DAST-010` with `--probe-rate-limit`, which also works without routes.

**`DAST-008` Unauthenticated sensitive endpoint** (medium, confidence low). For each `GET` or `HEAD` route whose
artifact says `hasAuth: false` (not `'unknown'`, not `true`) and whose path looks sensitive, BaseSec sends one
request without credentials and without following redirects. A `2xx` answer is a finding. A `401`, `403`, `3xx`,
`4xx` or `5xx` is not. `OPTIONS` routes are not checked: servers answer preflight requests with `2xx` by design.

- Sensitive means the path contains one of these as a whole word: `admin`, `internal`, `debug`, `config`,
  `metrics`, `account`, `settings`, `dashboard`, `private`, `secret` (so `/international` and `/accounting` do
  not match). It is also sensitive with an owner parameter (`:userId`, `:uid`, `:accountId`, `:customerId`) or an
  identifier after a user-owned resource (`/users/:id`, `/orders/:id`, `/accounts/:id`, `/customers/:id`,
  `/invoices/:id`, `/messages/:id`…). A public catalog such as `/products/:id` is not sensitive. A collection
  without a parameter (`/users`, `/profile`) is not sensitive by itself: a conservative choice that avoids
  reporting public listings. A non-sensitive route without auth is not reported, because most APIs have many.
- These paths are never reported: `/`, `/login`, `/logout`, `/register`, `/signup`, `/health`, `/healthz`,
  `/healthcheck` (and anything below them), `/status`, `/ready`, `/live`, `/ping`, `/favicon.ico`, and any path
  whose last segment is a login or sign-up page (`/admin/login`).
- `dast.publicRoutes` in the config lists routes that are public on purpose. Each pattern is a route path
  split by `/`. `*` matches exactly one segment, and the other segments match literally, ignoring case:
  `"/api/*/status"` covers `/api/v1/status`, but not `/api/v1/v2/status`.
- If the run sent a credential (for example `--header Authorization: …`), the observation of that route is not
  reused, because it carried the credential. The check repeats the request without every credential header
  (any header whose name contains `auth`, `cookie`, `token`, `session`, `api-key`, `secret`, `credential` or
  `jwt`). Cookies that the server set earlier in the run are not sent either, and the cookies this request
  receives are not kept for the rest of the run.
- Known limitation: a `2xx` that is a login page is skipped only when it is HTML with a password field, or carries
  `WWW-Authenticate`. A login screen rendered by a SPA, or a JSON body such as `{"error":"login required"}` with a
  `200`, still counts as reachable. This is why the confidence is `low`.

**`DAST-010` Missing rate limiting** (low, confidence low, opt-in). It is off unless you pass
`--probe-rate-limit` or set `dast.probeRateLimit: true`. It sends **30 `GET` requests in a burst** to one target:
the first surface `GET` route with `login`, `signin`, `auth`, `oauth`, `token` or `session` as a word of its path
(`/authors` does not count); otherwise the
healthcheck; otherwise `/`. A target that already answers `4xx`/`5xx` is not probed.

- The burst ignores `--rps`, otherwise it would test the rate of the probe and not the server. It still counts
  toward `--max-requests`, uses the concurrency limit, and goes through the same host guard and timeout.
- It reports only when all 30 answers arrive, none is `429` or any other `4xx`/`5xx`, and none carries `Retry-After`,
  `RateLimit`, `RateLimit-*`, `X-RateLimit-*` or `X-Rate-Limit-*`. An error in the middle of the burst (a WAF `403`,
  a `503`) is inconclusive, not "no limit". If the budget runs out in the middle, nothing is reported and the run is marked incomplete.
- Use it against a test environment: 30 quick requests can trip a lockout or an alert on a real login endpoint.

Not implemented yet: **`DAST-009`** (verbose error on malformed input). The plan ties it to endpoints with a body
and to `--allow-mutations`, so it arrives with the mutation tests. Until then, `basesec rules --dast` does not list it.

### Evidence

Each finding gets a redacted `.http` file in `~/.basesec/dast-<timestamp>/`, for example
`DAST-005-7143753f.http`. It opens in VS Code (REST Client) or IntelliJ. Cookie values, values of
`--header` and `$env:` secrets are replaced with `[REDACTED]`. The body is truncated to 8 KB. The
directory has mode `0700` and files have mode `0600`. Existing files are never overwritten.

### IAST agent (`--agent`, `--start`)

The agent confirms an injection when a payload's canary reaches a real sink in the app. The
black-box oracle still decides what is reported; the agent adds the sink location (`file:line`) and
raises the finding to `high`. Without the agent, injections stay at the confidence of their oracle.

```bash
# Recommended: BaseSec starts the app with the agent and stops it afterwards
basesec dast http://localhost:3000 --start "pnpm dev" --health /healthz --agent

# Manual: the app is started by hand with the agent loaded, then BaseSec attaches to it
export BASESEC_AGENT_DIR=$(mktemp -d)
NODE_OPTIONS='--require /absolute/path/to/basesec/dist/agent.cjs' pnpm dev
basesec dast http://localhost:3000 --agent --agent-dir "$BASESEC_AGENT_DIR"

# scan --verify: correlates static findings with the sink (same manual mode)
basesec scan ./src --verify --target http://localhost:3000 --dast-agent
```

- **How it loads.** `--start` injects `--require <absolute path to dist/agent.cjs>` into `NODE_OPTIONS`
  of the command, plus `BASESEC_AGENT_DIR` (a new directory per run) and `BASESEC_AGENT_ROOT` (the
  working directory). The agent is a standalone CommonJS bundle with no dependencies. The app's
  `node_modules` are not needed for it, but drivers are resolved from `BASESEC_AGENT_ROOT`.
- **Teardown.** The app runs in its own process group. On success, error, Ctrl-C, SIGTERM or SIGHUP, BaseSec
  kills the whole group, so a `pnpm dev` that starts the server as a grandchild does not leave it behind.
  A SIGKILL of BaseSec itself cannot be intercepted; then, kill the group by hand.
- **What it can confirm.** A canary only counts when it reaches a sink of the same family as the class:
  `child_process` for command injection, `mongodb` for NoSQL injection, `pg`/`mysql2` for SQL injection and
  `fs` for path traversal. A canary that lands in another family (an XSS payload inside a SQL string, for
  example) is ignored, so the agent never relabels a finding. Payloads of the timing and SQL-error classes
  carry no canary in the current catalog (adding one would change what every `dast` run sends, and the payload
  policy is reviewed byte by byte), and reflected XSS and open redirect have no instrumented sink. In practice
  the agent links command injection (echo payloads) and NoSQL operators.
- **Limits.** Drivers that are ESM-only are not instrumented. In a monorepo where the driver lives
  outside the working directory, set `BASESEC_AGENT_ROOT` to the package root. `eval`, the `Function`
  constructor and `vm.runInThisContext` are not instrumented (replacing them would change scoping and
  identity), so code injection through them is not confirmed. A sink called synchronously from inside another
  instrumented sink is reported once, by the outer one. Windows is not supported yet: the agent stays off there.
  The agent enables Node source maps in the app process so locations map to the TypeScript source; this changes
  how `error.stack` is formatted in the app (and costs some time when errors are thrown), nothing else.
- **Manual mode.** The directory must be yours and `0700` (`mktemp -d` creates one); otherwise the agent stays
  off and BaseSec ignores it. Example: `export BASESEC_AGENT_DIR=$(mktemp -d)`, start the app, then pass the
  same value to `--agent-dir`.
- **Never alters the app.** Every hook calls the original function with the original arguments and
  returns its result unchanged. An error in the agent is reported on stderr and the app keeps running
  without instrumentation. The agent only reports an argument that contains a canary, and nothing
  reaches the socket otherwise. It reads arguments without running application code (no getters or
  `toJSON`). It writes nothing to disk except its socket.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | No findings (or findings below the severity threshold, without `--strict`) |
| 1 | Findings with `--strict` |
| 2 | Target unreachable or unexpected error |
| 3 | Configuration error, invalid flag, blocked host (no request was sent), missing `$env:` variable, or Node below the patched floor |

### Verify static findings at runtime (`scan --verify`)

> **Legal warning.** `--verify` sends real HTTP requests to `--target`, with the same guards as
> `basesec dast`: only loopback and private networks by default, and `--dast-allow-remote` plus a typed
> host confirmation for anything else. Use the same target you are authorized to test. Without `--target`
> it is an error.

`basesec scan <path> --verify --target <url>` runs the static analysis and then attacks the running app
with the routes extracted from that same code. A static finding that the runtime confirms is reported as
`verified`, with the request and response that proved it, and it is **not** repeated as a separate runtime
finding. Runtime-only findings (for example, a missing header set by the proxy) are added at the end.

```bash
# Start the app, then confirm what the static analysis reports
basesec scan ./src --verify --target http://localhost:3000

# Only the high-severity results, and fail CI when any remains
basesec scan ./src --verify --target http://localhost:3000 --severity high --strict

# Limit the runtime checks and send no evidence files
basesec scan ./src --verify --target http://localhost:3000 --dast-rules DAST-101,DAST-105 --no-dast-evidence
```

The static finding is linked to the runtime confirmation in one of three ways, shown in the output as
`Link:`:

| Link | Meaning | Confidence |
|---|---|---|
| `handler` | The confirmed route's handler contains the static finding. | high |
| `import-graph` | The static finding is in a file the handler imports. Its confidence is at least medium. | max(original, medium) |
| `runtime-property` | A header or cookie rule (for example, a missing CSP) matches a static rule about the same thing. | high |

When two static findings compete for the same confirmed injection and sit on different lines, BaseSec does
not guess: the runtime finding stays, and its message lists the possible origins. Findings on the same line
(for example, two rules describing one SQL query) are all verified.

A runtime finding only verifies static findings it can actually explain: a confirmed reflected XSS
(`DAST-105`) is linked to `XSS-001` and an open redirect (`DAST-011`) to `XSS-004`, never to other `xss`
rules such as a missing `helmet` (`XSS-002`) that happen to live in a file the route imports.

`verified` absent does not mean "false positive". It means "not confirmed at runtime". The terminal report
says so on every verify run, and it never says a finding is safe.

| Flag | Meaning |
|---|---|
| `--verify` | Enables the runtime check. Requires `--target`. Not combined with `--emit-routes` or `--ai`. |
| `--target <url>` | The running app to attack. |
| `--dast-allow-remote` | Allows a non-local target (asks for the host to be typed when there is a terminal). |
| `--dast-header <h>` | Request header `"Name: value"`, repeatable. Overrides `dast.headers` with the same name. |
| `--dast-rules <ids>` | Comma-separated DAST rule IDs. |
| `--dast-probe-rate-limit` | Enables `DAST-010`. |
| `--dast-timeout <s>` | Global timeout (default 300). |
| `--dast-request-timeout <ms>` | Per-request timeout (default 10000). |
| `--dast-rps <n>` | Requests per second (default 20). |
| `--dast-max-requests <n>` | Request budget (default 5000). |
| `--dast-evidence-dir <dir>` | Where the `.http` evidence is written. |
| `--no-dast-evidence` | Does not write evidence files. |
| `--dast-allow-vulnerable-node` | Runs even if Node is below the patched floor. |

Other `dast` settings (`health`, `publicRoutes`, `concurrency`, `headers`, `probeRateLimit`) are read from
the `dast` section of the config file. The `--dast-*` flags are rejected without `--verify`.

Exit codes are the same as `scan` and `dast`: 0 clean (or findings without `--strict`), 1 findings with
`--strict`, 2 target unreachable or unexpected error, 3 configuration, invalid flag value, blocked host or Node
below the patched floor. Invalid flag combinations (`--verify` without `--target`, with `--emit-routes` or
`--ai`, or `--target` / `--dast-*` without `--verify`) exit 2, as the other `scan` flag errors do. If no routes are extracted from the code, nothing is attacked: BaseSec reports the
static findings and warns on stderr.

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