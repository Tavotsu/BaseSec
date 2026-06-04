import { describe, it, expect } from 'vitest';
import { mergeFindings } from '../../src/ai/merger';
import type { Finding } from '../../src/rules/types';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'SQLI-001',
    ruleName: 'SQL Injection',
    category: 'sql-injection',
    severity: 'high',
    filePath: '/src/db.ts',
    line: 10,
    column: 1,
    endLine: 10,
    endColumn: 50,
    message: 'Potential SQL injection',
    codeSnippet: 'db.query(userInput)',
    remediation: 'Use parameterized queries',
    references: [],
    confidence: 'high',
    ...overrides,
  };
}

describe('mergeFindings', () => {
  it('returns static findings unchanged when no AI findings', () => {
    const s = [makeFinding()];
    expect(mergeFindings(s, [])).toHaveLength(1);
  });

  it('appends unique AI findings', () => {
    const s = [makeFinding({ filePath: '/src/a.ts', line: 1 })];
    const ai = [makeFinding({ filePath: '/src/b.ts', line: 1, aiGenerated: true }), ];
    const merged = mergeFindings(s, ai);
    expect(merged).toHaveLength(2);
  });

  it('deduplicates AI finding with same file + line ± 3 + same category', () => {
    const s = [makeFinding({ filePath: '/src/a.ts', line: 10, category: 'sql-injection' })];
    const ai = [makeFinding({ filePath: '/src/a.ts', line: 12, category: 'sql-injection', aiGenerated: true })];
    const merged = mergeFindings(s, ai);
    expect(merged).toHaveLength(1);
  });

  it('keeps AI finding when line diff > 3', () => {
    const s = [makeFinding({ filePath: '/src/a.ts', line: 10, category: 'sql-injection' })];
    const ai = [makeFinding({ filePath: '/src/a.ts', line: 15, category: 'sql-injection', aiGenerated: true })];
    const merged = mergeFindings(s, ai);
    expect(merged).toHaveLength(2);
  });

  it('keeps AI finding when different category even if same file+line', () => {
    const s = [makeFinding({ filePath: '/src/a.ts', line: 10, category: 'sql-injection' })];
    const ai = [makeFinding({ filePath: '/src/a.ts', line: 10, category: 'xss', aiGenerated: true })];
    const merged = mergeFindings(s, ai);
    expect(merged).toHaveLength(2);
  });

  it('sorts merged results by severity', () => {
    const s = [makeFinding({ severity: 'low' })];
    const ai = [makeFinding({ filePath: '/src/b.ts', severity: 'critical', aiGenerated: true })];
    const merged = mergeFindings(s, ai);
    expect(merged[0].severity).toBe('critical');
  });
});
