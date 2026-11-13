import { describe, it, expect } from 'vitest';
import { ResultStore } from '../../src/core/result-store';
import type { Finding } from '../../src/rules/types';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'DAST-005',
    ruleName: 'Insecure cookie flags',
    category: 'misconfiguration',
    severity: 'high',
    filePath: '',
    line: 0,
    column: 0,
    endLine: 0,
    endColumn: 0,
    message: 'Cookies set without security flags: sid (missing HttpOnly).',
    codeSnippet: 'set-cookie: sid=[REDACTED]; Path=/',
    remediation: 'Set HttpOnly.',
    references: [],
    confidence: 'high',
    ...overrides,
  };
}

describe('ResultStore endpoint-aware deduplication', () => {
  it('does not deduplicate identical findings that differ only by endpoint', () => {
    const store = new ResultStore();
    store.add(makeFinding({ endpoint: 'GET /a' }));
    store.add(makeFinding({ endpoint: 'GET /b' }));
    expect(store.count()).toBe(2);
  });

  it('still deduplicates identical findings without endpoint', () => {
    const store = new ResultStore();
    store.add(makeFinding());
    expect(store.add(makeFinding())).toBe(false);
    expect(store.count()).toBe(1);
  });
});
