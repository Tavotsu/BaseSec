# Rules Catalog

BaseSec ships with **30 security rules** across **9 categories**. All rules support taint analysis where applicable.

## Authentication (AUTH)

| ID | Name | Severity | Description |
|---|---|---|---|
| `AUTH-001` | Missing Authentication Guard | high | NestJS route lacks `@UseGuards()` or Express route has no auth middleware |
| `AUTH-002` | Hardcoded JWT Secret | critical | JWT secret found as string literal in config/code |
| `AUTH-003` | Permissive CORS Configuration | high | CORS allows all origins (`*`) or lacks credentials restriction |
| `AUTH-004` | Missing Rate Limiting on Auth Endpoints | medium | Login/register endpoints lack rate limiter middleware |

## Command Injection (CMDI)

| ID | Name | Severity | Description |
|---|---|---|---|
| `CMDI-001` | Command Injection via child_process | critical | `exec()`, `execSync()`, `spawn()` with user input |
| `CMDI-002` | Use of eval() | critical | `eval()` called with user-controlled data |
| `CMDI-003` | setTimeout/setInterval with String Argument | medium | `setTimeout("code", delay)` — implicit eval |

## Error Handling (ERR)

| ID | Name | Severity | Description |
|---|---|---|---|
| `ERR-001` | Exposed Stack Trace | medium | Error responses include stack traces in production |
| `ERR-002` | Missing Global Error Handler | low | Express app has no centralized error handler |
| `ERR-003` | Unhandled Promise Rejection | low | Promises without `.catch()` or `try/catch` |

## Misconfiguration (CONF)

| ID | Name | Severity | Description |
|---|---|---|---|
| `CONF-001` | Missing Content-Security-Policy | medium | Helmet CSP not configured or disabled |
| `CONF-002` | Debug Mode in Production | high | `DEBUG=true`, `NODE_ENV=development` in prod config |
| `CONF-003` | Insecure Cookie Configuration | medium | Cookies without `httpOnly`, `secure`, or `sameSite` |
| `CONF-004` | Unlimited Body Parser | medium | Express body parser without size limits |

## NoSQL Injection (NOSQL)

| ID | Name | Severity | Description |
|---|---|---|---|
| `NOSQL-001` | MongoDB $where with User Input | critical | `Model.find({ $where: userInput })` |
| `NOSQL-002` | Mongoose Query Object Injection | high | Unsanitized query object from user input |
| `NOSQL-003` | Mongoose Lean Data Leak | medium | `lean()` exposes internal fields without projection |

## Path Traversal (PATH)

| ID | Name | Severity | Description |
|---|---|---|---|
| `PATH-001` | Path Traversal via User Input | critical | `fs.readFile(req.query.file)` without sanitization |
| `PATH-002` | Insecure Express Static Configuration | medium | `express.static` serves root directory or lacks dotfiles restriction |

## Secrets (SEC)

| ID | Name | Severity | Description |
|---|---|---|---|
| `SEC-001` | Hardcoded API Key | critical | API keys, tokens, or secrets as string literals |
| `SEC-002` | Hardcoded Password | critical | Passwords or credentials in source code |
| `SEC-003` | Hardcoded Cryptographic Key | critical | Private keys, AES keys in code |

## SQL Injection (SQLI)

| ID | Name | Severity | Description |
|---|---|---|---|
| `SQLI-001` | SQL String Concatenation | critical | `"SELECT ..." + userInput` in DB queries |
| `SQLI-002` | SQL Template Literal Injection | critical | `` `SELECT ... ${userInput}` `` in queries |
| `SQLI-003` | Raw SQL Query Without Parameters | critical | `query()` called with concatenated string |
| `SQLI-004` | SQL Injection via Knex Raw Query | high | `knex.raw(userInput)` or `.whereRaw(userInput)` |

## Cross-Site Scripting (XSS)

| ID | Name | Severity | Description |
|---|---|---|---|
| `XSS-001` | Unsafe res.send() with User Input | high | `res.send(req.query.x)` without escaping |
| `XSS-002` | Missing Helmet Middleware | medium | Express app missing Helmet security headers |
| `XSS-003` | Unsafe Response Header with User Input | medium | `res.setHeader()` with user-controlled value |
| `XSS-004` | Open Redirect | medium | `res.redirect(req.query.url)` without allowlist |

## Severity Scale

- **Critical** — Exploitable remotely, data breach or RCE likely
- **High** — Serious vulnerability, authentication bypass or significant data exposure
- **Medium** — Moderate risk, partial information disclosure or limited impact
- **Low** — Minor issue, best practice violation
- **Info** — Informational, no direct security impact

## Running Specific Rules

```bash
basesec scan ./src -r SQLI-001,SQLI-002
basesec scan ./src -r AUTH-001,AUTH-002,AUTH-003
```