# Contributing

Thank you for contributing to BaseSec.

## Development Setup

```bash
git clone https://github.com/Tavotsu/BaseSec.git
cd BaseSec
pnpm install
```

## Commands

```bash
pnpm dev scan <path>      # Run the CLI via tsx, no build needed
pnpm build                # Build with tsup → dist/
pnpm test                 # Run all tests (vitest)
pnpm test tests/rules/sql-injection.test.ts   # Run a single test file
pnpm test:coverage        # Tests with v8 coverage
pnpm typecheck            # TypeScript check (tsc --noEmit)
```

Do **not** insert `--` before the arguments. pnpm forwards it literally, so
`pnpm test -- <file>` runs the whole suite unfiltered and `pnpm dev -- scan .` never
reaches the `scan` command at all.

## Adding a New Rule

1. Create the file at `src/rules/categories/<dir>/<kebab-case>.ts`
2. Define it with `defineRule()` from `src/rules/define-rule.ts`
3. Register it in `src/rules/index.ts` — **three edits in that one file** (see below)
4. Add tests to the matching file in `tests/rules/`
5. Update `docs/RULES.md`

### Directories are named after the trigger, not the category

`src/rules/categories/<dir>/` is organized by *what makes the rule fire*, not by the rule's
`category` field. `fastify/`, `koa/`, `prisma/`, `react/`, `vue/`, `angular/` and `svelte/`
hold framework-specific detectors; `dom/` holds framework-agnostic browser rules.

A rule living in `categories/fastify/missing-helmet.ts` can perfectly well have
`category: 'misconfiguration'`. Do not assume directory name == category.

### Registering the rule

`src/rules/index.ts` is the only thing that makes a rule run. It needs all three:

```ts
export { SQLI005 } from './categories/sql-injection/my-new-rule';   // 1. re-export
import { SQLI005 } from './categories/sql-injection/my-new-rule';   // 2. import
export const ALL_RULES: Rule[] = [ /* ... */ SQLI005 ];             // 3. add to the array
```

A rule missing from `ALL_RULES` compiles, passes typecheck and never executes.

> The `index.ts` files inside some `categories/*/` folders are vestigial — nothing imports
> them, and the newer categories (`react`, `vue`, `angular`, `svelte`, `dom`) do not have
> them. Ignore them; only `src/rules/index.ts` matters.

### Rule Template

```ts
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isTaintSource } from '../../../utils/patterns';
import { resolveConfidence, isExpressionTainted } from '../../../taint/integration';
import type { Finding } from '../../types';

export const SQLI005 = defineRule({
  id: 'SQLI-005',
  name: 'Rule Name',
  description: 'What this detects and why it is dangerous.',
  category: 'sql-injection',
  severity: 'high',
  frameworks: ['*'],
  tags: ['cwe:89', 'sql-injection'],
  detect(ctx): Finding[] {
    const findings: Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      // narrow to the node you care about, then gate on taint
      const argText = /* text of the ARGUMENT, not the whole call */ '';

      if (isTaintSource(argText) || isExpressionTainted(ctx.taintGraph, argText)) {
        const { line, column } = getLineAndColumn(ctx.sourceFile, node);

        findings.push({
          ruleId: 'SQLI-005',
          ruleName: 'Rule Name',
          category: 'sql-injection',
          severity: 'high',
          filePath: ctx.filePath,
          line,
          column,
          endLine: line,
          endColumn: column + argText.length,
          message: 'What is wrong at this location.',
          codeSnippet: getCodeSnippet(ctx.content, line),
          remediation: 'What the developer should do instead.',
          references: ['https://cwe.mitre.org/data/definitions/89.html'],
          confidence: resolveConfidence(ctx.taintGraph, argText, 'high'),
        });
      }

      return 'continue';
    });

    return findings;
  },
});
```

`detect()` **returns** a `Finding[]`. There is no `ctx.addFinding()`.

`RuleContext` is `{ sourceFile, filePath, content, config, taintGraph? }`. Note that
`frameworks` is an array (`Framework[]`), not a single string.

### Rule ID Convention

Format: `CATEGORY-NNN` with a hyphen (e.g. `SQLI-001`, `NOSQL-002`).

Three things must agree:

- the `id` passed to `defineRule()`
- the `ruleId` on every `Finding` the rule emits
- the export name in `src/rules/index.ts`, which mirrors the ID without the hyphen (`SQLI001`)

### Taint Integration

Pass the **argument text**, never the full call expression:

```ts
// correct
isTaintSource(argText) || isExpressionTainted(ctx.taintGraph, argText)

// wrong — matches almost nothing
isExpressionTainted(ctx.taintGraph, node.getText(ctx.sourceFile))
```

`ctx.taintGraph` is per-file and may be `undefined` (taint analysis is off, or the file was
served from cache). `resolveConfidence()` and `isExpressionTainted()` both handle
`undefined` internally, so pass it straight through — but never reach into
`ctx.taintGraph.sources` without a guard.

## Testing

Tests mirror `src/` under `tests/`, but rule tests are **flat**: one file per area, e.g.
`tests/rules/sql-injection.test.ts`, `tests/rules/react.test.ts`. Add to the existing file
rather than creating a nested path.

Helpers live in `tests/helpers.ts`: `runRule()`, `createRuleContext()`, `expectFinding()`,
`expectNoFindings()`.

```ts
import { describe, it, expect } from 'vitest';
import { SQLI001 } from '../../src/rules/categories/sql-injection/string-concat';
import { runRule } from '../helpers';

describe('SQLI-001', () => {
  it('detects string concatenation in a query', () => {
    const code = `db.query("SELECT * FROM users WHERE id = " + req.query.id)`;
    const findings = runRule(SQLI001, code);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('SQLI-001');
  });

  it('ignores a fully static query', () => {
    const code = `db.query("SELECT * FROM users WHERE id = 1")`;
    expect(runRule(SQLI001, code)).toHaveLength(0);
  });
});
```

Every rule needs a **negative** case. Rules are judged on precision — a rule that fires on
safe code is worse than no rule.

`runRule(rule, code, fileName)` accepts a filename, which is how you get `.tsx`, `.vue` or
`.svelte` parsing. To supply a taint graph, use `createRuleContext(code, fileName, { taintGraph })`.

## Code Style

- ESM only (`"type": "module"`)
- No comments unless necessary; when one is warranted it explains *why*, not *what*
- Follow existing patterns in `src/rules/`
- `import * as ts from 'typescript'` for the TS Compiler API — the project uses it directly,
  not ts-morph
- `node:` prefix for built-ins (`node:fs`, `node:path`)
- **No new runtime dependencies.** BaseSec ships with 6 on purpose. Open an issue first.
- **Never write an empty `catch {}`** — use `logger.warn('msg', e)` from `src/utils/logger.ts`
  so `--verbose` surfaces it
- Any rule that can emit sensitive data in `codeSnippet` must run it through
  `redactSecret()` from `src/utils/redact.ts`
- `src/config/schema.ts` and `src/rules/types.ts` must stay in sync

## Reporting Bugs

Open an issue with:
- BaseSec version (`basesec --version`)
- Node.js version
- Minimal code that triggers the false positive or bug
- Expected vs actual behavior

## License

CC BY-NC 4.0 © Tavotsu
