import { describe, it, expect } from 'vitest';
import { ResultStore } from '../../src/core/result-store';
import type { Finding } from '../../src/rules/types';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'TEST-001',
    ruleName: 'Test Rule',
    category: 'sql-injection',
    severity: 'high',
    filePath: 'test.ts',
    line: 1,
    column: 1,
    endLine: 1,
    endColumn: 10,
    message: 'Test finding',
    codeSnippet: 'const x = 1;',
    remediation: 'Fix it',
    references: [],
    confidence: 'high',
    ...overrides,
  };
}

describe('ResultStore', () => {
  it('adds findings and retrieves them', () => {
    const store = new ResultStore();
    const finding = makeFinding();
    const result = store.add(finding);

    expect(result).toBe(true);
    expect(store.count()).toBe(1);
    expect(store.getFindings()).toHaveLength(1);
  });

  it('deduplicates identical findings', () => {
    const store = new ResultStore();
    const finding = makeFinding({ line: 5, codeSnippet: '  db.query(sql);  ' });

    store.add(finding);
    const result = store.add(finding);

    expect(result).toBe(false);
    expect(store.count()).toBe(1);
  });

  it('allows different findings for same rule at different lines', () => {
    const store = new ResultStore();
    const f1 = makeFinding({ line: 5 });
    const f2 = makeFinding({ line: 10 });

    store.add(f1);
    store.add(f2);

    expect(store.count()).toBe(2);
  });

  it('groups findings by category', () => {
    const store = new ResultStore();
    store.add(makeFinding({ category: 'sql-injection' }));
    store.add(makeFinding({ category: 'sql-injection', line: 10 }));
    store.add(makeFinding({ category: 'xss', line: 15 }));

    const byCategory = store.getFindingsByCategory();
    expect(byCategory.get('sql-injection')!.length).toBe(2);
    expect(byCategory.get('xss')!.length).toBe(1);
  });

  it('groups findings by severity', () => {
    const store = new ResultStore();
    const f1 = makeFinding({ severity: 'critical', line: 1, codeSnippet: 'a' });
    const f2 = makeFinding({ severity: 'high', line: 2, codeSnippet: 'b' });
    const f3 = makeFinding({ severity: 'high', line: 3, codeSnippet: 'c' });
    store.add(f1);
    store.add(f2);
    store.add(f3);
    const bySeverity = store.getFindingsBySeverity();
    expect(bySeverity.get('critical')!.length).toBe(1);
    expect(bySeverity.get('high')!.length).toBe(2);
  });

  it('clears all findings', () => {
    const store = new ResultStore();
    store.add(makeFinding());
    store.add(makeFinding({ line: 10 }));
    expect(store.count()).toBe(2);

    store.clear();
    expect(store.count()).toBe(0);
    expect(store.getFindings()).toHaveLength(0);
  });

  it('addMany returns count of newly added findings', () => {
    const store = new ResultStore();
    const findings = [
      makeFinding({ line: 1 }),
      makeFinding({ line: 2 }),
      makeFinding({ line: 1 }),
    ];

    const added = store.addMany(findings);
    expect(added).toBe(2);
  });
});