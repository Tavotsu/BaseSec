# PRODUCT.md — BaseSec Product Context

## Product Overview
BaseSec is a fast, offline CLI Static Application Security Testing (SAST) tool specifically built for JavaScript and TypeScript codebases.

## Core Capabilities
- **Direct AST Parsing**: Uses the official TypeScript Compiler API (`ts.createSourceFile`) to parse `.js`, `.ts`, `.jsx`, `.tsx`, and single-file components (`.vue`, `.svelte`) with exact line numbers and zero regex guesswork.
- **Deep Taint Tracking**: Follows untrusted data from sources (`req.query`, `req.body`, `location.search`, `localStorage`) across assignments and function calls directly into dangerous execution sinks (`db.query`, `exec()`, `dangerouslySetInnerHTML`, `v-html`).
- **65 Security Rules**: Across 11 CVE categories (SQLI, NOSQL, XSS, CMDI, PATH, AUTH, SEC, DEP, DOM, ERR, CONF).
- **12 Frameworks Supported**: Express, NestJS, Fastify, Koa, React, Next.js, Vue, Nuxt, Angular, Svelte, Prisma, Mongoose, TypeORM.
- **Privacy & Speed**: 100% offline, zero telemetry, scans at 78+ files per second on multi-threaded worker pools.
- **CI/CD Integration**: Emits SARIF (for native GitHub Code Scanning alerts), JSON, Markdown, HTML, and terminal reports with exit codes.

## Primary User Personas
- **Fullstack / Backend JS/TS Developers**: Want to catch security flaws before push or merge.
- **DevOps & Platform Engineers**: Want lightweight, zero-config SAST for GitHub Actions / GitLab CI without 10-minute container spin-ups.
- **Security Auditors**: Need reliable taint tracking with actionable remediation snippets for developers.
