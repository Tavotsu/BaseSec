# Rules Catalog

BaseSec ships with **65 security rules** across **10 categories**, covering both Node.js backends and frontend frameworks (React/Next, Vue/Nuxt, Angular, Svelte). All rules support taint analysis where applicable.

## AI Enhancement (AI)

| ID | Name | Severity | Description |
|---|---|---|---|
| `AI-001` | AI-detected Vulnerability | varies | Suspicious taint flows detected by AI analysis that may bypass existing rules |

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

## Dependency Check (DEP)

| ID | Name | Severity | Description |
|---|---|---|---|
| `DEP-001` | Outdated Dependency with Known CVE | critical | Package version has known vulnerabilities |
| `DEP-002` | Vulnerable Dependency | critical | Vulnerable package detected via audit |
| `DEP-003` | Unused Dependency | low | Package declared but never imported |
| `DEP-004` | Lockfile Mismatch | medium | package.json out of sync with lockfile |

## Error Handling (ERR)

| ID | Name | Severity | Description |
|---|---|---|---|
| `ERR-001` | Exposed Stack Trace | medium | Error responses include stack traces in production |
| `ERR-002` | Missing Global Error Handler | low | Express app has no centralized error handler |
| `ERR-003` | Unhandled Promise Rejection | low | Promises without `.catch()` or `try/catch` |

## Fastify (FASTIFY)

| ID | Name | Severity | Description |
|---|---|---|---|
| `FASTIFY-001` | Missing Fastify Rate Limiting | high | Fastify app lacks rate limiting middleware |
| `FASTIFY-002` | Missing Fastify Helmet | medium | Fastify app missing security headers |
| `FASTIFY-003` | Missing Fastify CORS | medium | Fastify app missing CORS configuration |

## Koa (KOA)

| ID | Name | Severity | Description |
|---|---|---|---|
| `KOA-001` | Missing Koa Helmet | medium | Koa app missing security headers |
| `KOA-002` | Missing Koa CORS | medium | Koa app missing CORS configuration |
| `KOA-003` | Unsafe ctx.body with User Input | high | `ctx.body` assigned directly from user input |

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

## Prisma (PRISMA)

| ID | Name | Severity | Description |
|---|---|---|---|
| `PRISMA-001` | Prisma Raw Query Injection | critical | `$queryRaw` with string concatenation |
| `PRISMA-002` | Unsafe Prisma Raw Query | high | `$executeRaw` with unsafe input |

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

## DOM / Client-Side (DOM)

Framework-agnostic browser rules. Run on any JS/TS; the DOM-specific ones (`window`, `document`, `localStorage`) are inert on backend code.

| ID | Name | Severity | Description |
|---|---|---|---|
| `DOM-001` | Unsafe innerHTML/outerHTML/insertAdjacentHTML | high | Dynamic value assigned to `innerHTML`/`outerHTML` or `insertAdjacentHTML()` |
| `DOM-002` | Unsafe document.write() | medium | `document.write()`/`writeln()` with dynamic input |
| `DOM-003` | Open Redirect via location/window.open | high | Dynamic `location.href =` or `window.open()` (open redirect / `javascript:` URI) |
| `DOM-004` | postMessage with Wildcard Target Origin | medium | `postMessage(data, "*")` sends data to any origin |
| `DOM-005` | message Listener Without Origin Check | high | `message` event handler that never validates `event.origin` |
| `DOM-006` | Sensitive Data in localStorage/sessionStorage | medium | Tokens/JWTs/credentials stored in Web Storage |
| `DOM-007` | Dynamic Code Execution with Network/URL Data | critical | `eval`/`new Function`/`setTimeout(string)` fed network/URL data (frontend files) |
| `DOM-008` | Prototype Pollution via URL Parameters | high | Recursive merge/assign of URL-derived data into objects (frontend files) |

## React / Next.js (REACT / NEXT)

| ID | Name | Severity | Description |
|---|---|---|---|
| `REACT-001` | dangerouslySetInnerHTML with Dynamic Value | critical | `dangerouslySetInnerHTML={{ __html: nonLiteral }}` |
| `REACT-002` | Unvalidated URL in JSX href/src | high | JSX `href`/`src` bound to a dynamic expression (`javascript:` URI) |
| `REACT-003` | innerHTML via React ref | high | `ref.current.innerHTML =` bypasses JSX escaping |
| `NEXT-001` | Secret Exposed via Public Env Prefix | critical | `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` env var that looks like a secret (inlined into the bundle) |
| `NEXT-002` | Open Redirect via Next redirect() | high | `redirect()` destination derived from `searchParams`/query without validation |

## Vue / Nuxt (VUE)

| ID | Name | Severity | Description |
|---|---|---|---|
| `VUE-001` | v-html with Dynamic Binding | critical | `v-html` renders raw HTML, bypassing escaping (`.vue` template) |
| `VUE-002` | Unvalidated URL in Vue :href/:src | high | `:href`/`:src` bound to route/props/URL data without validation |
| `VUE-003` | innerHTML in Vue Render Function | high | `innerHTML` passed via props to `h()`/`createElement()` |

## Angular (NG)

| ID | Name | Severity | Description |
|---|---|---|---|
| `NG-001` | DomSanitizer bypassSecurityTrust with Dynamic Value | critical | `bypassSecurityTrustHtml/Script/Style/Url/ResourceUrl()` with a non-literal |
| `NG-002` | innerHTML via ElementRef.nativeElement | high | `nativeElement.innerHTML =` bypasses the sanitizer |
| `NG-003` | Tainted [innerHTML] Binding | medium | `[innerHTML]` template binding (sanitized by default; risky with a bypass) |
| `NG-004` | HttpClient.jsonp with Dynamic URL | high | `HttpClient.jsonp()` with a dynamic URL/callback (JSONP script injection) |
| `NG-005` | Open Redirect via Router.navigate | high | `navigateByUrl()`/`navigate()` destination from route/query params |
| `NG-006` | Sensitive Route Without Guard | medium | Route for `admin`/`dashboard`/`settings`… with no `canActivate`/`canMatch` |

## Svelte (SVELTE)

| ID | Name | Severity | Description |
|---|---|---|---|
| `SVELTE-001` | {@html} with Dynamic Expression | critical | `{@html expr}` renders raw HTML, bypassing escaping (`.svelte` template) |

## Runtime / DAST (DAST)

These rules run against a **running** application with `basesec dast <url>`. They are not part of
`basesec scan` and do not appear in ALL_RULES. In no-source mode, they inspect only the responses to
`GET /` and to the healthcheck. A finding is *verified* because the runtime response shows it. The
absence of a finding means "not confirmed at runtime", not "secure".

| ID | Name | Severity | Description |
|---|---|---|---|
| `DAST-001` | Missing security headers | medium | HTML responses lack X-Content-Type-Options, X-Frame-Options (or CSP `frame-ancestors`) or Referrer-Policy. Scope: target |
| `DAST-002` | Missing HSTS | medium | HTTPS responses lack a `Strict-Transport-Security` header with a positive `max-age`. Scope: target |
| `DAST-003` | Missing or weak Content-Security-Policy | medium | HTML responses have no CSP, or the CSP `script-src` allows `'unsafe-inline'`, `'unsafe-eval'` or `*` without nonce, hash or `'strict-dynamic'`. Scope: target |
| `DAST-004` | Permissive CORS at runtime | high (medium for `*`) | The runtime reflects an arbitrary Origin, `null` or `*` in `Access-Control-Allow-Origin` while `Access-Control-Allow-Credentials` is true. Scope: target |
| `DAST-005` | Insecure cookie flags | high | `Set-Cookie` lacks `HttpOnly` or `SameSite`, or lacks `Secure` over HTTPS. Scope: endpoint |
| `DAST-006` | Stack trace exposed | high | A 5xx response body contains a Node.js stack trace with internal file paths. Scope: endpoint |
| `DAST-007` | Server banner leakage | low | Responses disclose the framework (`X-Powered-By`) or the server version (`Server`). Scope: target |
| `DAST-008` | Unauthenticated sensitive endpoint | medium | A sensitive `GET`/`HEAD` route with `hasAuth: false` in the route artifact answers 2xx without credentials (confidence low). Full mode only. Scope: endpoint |
| `DAST-010` | Missing rate limiting | low | Opt-in (`--probe-rate-limit`): 30 rapid requests to a login or healthcheck target get no 429 and no rate-limit headers. Scope: target |

Run a subset with `basesec dast <url> --rules DAST-001,DAST-005`. List the rules with
`basesec rules --dast`. `DAST-009` is not implemented yet (see the USAGE guide).

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