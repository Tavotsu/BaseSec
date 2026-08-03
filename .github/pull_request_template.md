## Summary

<!-- What changes and why. One or two sentences. -->

## Type of change

- [ ] New security rule
- [ ] Rule fix (false positive / false negative)
- [ ] Bug fix
- [ ] Feature
- [ ] Performance
- [ ] Docs / chore
- [ ] Dependency update

## Related issue

<!-- Closes #___ -->

## Checklist

- [ ] `pnpm test` passes
- [ ] `pnpm typecheck` is clean
- [ ] `pnpm build` succeeds
- [ ] `CHANGELOG.md` updated
- [ ] No new **runtime** dependency — BaseSec ships with 6 on purpose. Open an issue first if you need another.
- [ ] No empty `catch {}` — failures go through `logger.warn('msg', e)` so `--verbose` surfaces them

## New or changed rule

<!-- Delete this section if the PR does not touch src/rules/ -->

- [ ] ID follows `CATEGORY-NNN` and matches the `ruleId` on every emitted finding
- [ ] Exported from `src/rules/index.ts` — rules are re-exported individually into `ALL_RULES`, a rule that is not listed there never runs
- [ ] Test added under `tests/rules/`, with a positive **and** a negative case
- [ ] `detect()` handles `ctx.taintGraph === undefined`
- [ ] Taint gating passes the **argument text**, not the full call expression:
      `isTaintSource(argText) || isExpressionTainted(ctx.taintGraph, argText)`
- [ ] `docs/RULES.md` updated
- [ ] Any sensitive value reaching `codeSnippet` runs through `redactSecret()`

## False positives

<!--
Rules are judged on precision, not on how much they find.
Paste the code you confirmed does NOT trigger this rule.
-->

```ts

```

## Verification

<!-- Scan output before and after, or the failing test that now passes. -->

```
```
