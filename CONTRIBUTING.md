# Contributing

Thank you for contributing to BaseSec.

## Development Setup

```bash
git clone https://github.com/tavotsu/basesec.git
cd basesec
pnpm install
```

## Commands

```bash
pnpm dev          # Run CLI via tsx
pnpm build        # Build with tsup → dist/
pnpm test         # Run all tests (vitest)
pnpm test:coverage # Tests with v8 coverage
pnpm typecheck    # TypeScript check (tsc --noEmit)
```

## Adding a New Rule

1. Create file at `src/rules/categories/<category>/<kebab-case>.ts`
2. Use `defineRule()` from `src/rules/define-rule.ts`
3. Export rule from `src/rules/categories/<category>/index.ts`
4. Add test at `tests/rules/categories/<category>/<kebab-case>.test.ts`
5. Update `docs/RULES.md`

### Rule Template

```ts
import { defineRule } from '../../define-rule';

export default defineRule({
  id: 'CATEGORY-NNN',
  name: 'Rule Name',
  category: 'category-name',
  severity: 'high',
  framework: '*',
  detect(ctx) {
    // AST analysis logic
    // Use ctx.sourceFile, ctx.filePath, ctx.taintGraph
    // Call ctx.addFinding({ ... }) when vulnerability detected
  },
});
```

### Rule ID Convention

Format: `CATEGORY-NNN` with hyphen (e.g., `SQLI-001`, `NOSQL-002`).

### Taint Integration

Rules must check taint before flagging:

```ts
if (isTaintSource(argText) || isExpressionTainted(ctx.taintGraph, argText)) {
  ctx.addFinding({
    ruleId: 'SQLI-001',
    // ...
    confidence: resolveConfidence(ctx.taintGraph, argText, 'medium'),
  });
}
```

Pass **argument text** (not full call expression) to `isExpressionTainted()` and `resolveConfidence()`.

## Testing

Tests mirror `src/` structure in `tests/`. Use `runRule()` helper to create `RuleContext`.

```ts
import { describe, it, expect } from 'vitest';
import rule from '../../../src/rules/categories/sql-injection/string-concat';
import { runRule } from '../../helpers';

describe('SQLI-001', () => {
  it('detects string concatenation in query', () => {
    const code = `db.query("SELECT * FROM users WHERE id = " + req.query.id)`;
    const findings = runRule(rule, code);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('SQLI-001');
  });
});
```

## Pull Request Checklist

- [ ] Tests pass (`pnpm test`)
- [ ] TypeScript clean (`pnpm typecheck`)
- [ ] Build succeeds (`pnpm build`)
- [ ] New rules have tests
- [ ] Documentation updated (`docs/RULES.md`, `CHANGELOG.md`)

## Code Style

- ESM only (`"type": "module"`)
- No comments unless necessary
- Follow existing patterns in `src/rules/`
- Use `import * as ts from 'typescript'` for TS Compiler API
- Use `node:` prefix for built-in modules (`node:fs`, `node:path`)

## Reporting Bugs

Open an issue with:
- BaseSec version (`basesec --version`)
- Node.js version
- Minimal code that triggers the false positive or bug
- Expected vs actual behavior

## License

MIT © Tavotsu