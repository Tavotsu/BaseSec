import { describe, it, expect, vi, beforeEach } from 'vitest';
import { enrichFindings } from '../../src/ai/enricher';
import type { Finding } from '../../src/rules/types';
import type { LlmProvider } from '../../src/ai/providers/types';

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

function makeProvider(response: string): LlmProvider {
  return {
    name: 'mock',
    call: vi.fn().mockResolvedValue(response),
    validateConnection: vi.fn().mockResolvedValue(true),
  };
}

describe('enrichFindings', () => {
  it('enriches valid finding with AI data', async () => {
    const llmResponse = JSON.stringify({
      isValid: true,
      confidence: 'high',
      explanation: 'This is a real SQL injection vulnerability',
      remediation: 'Use prepared statements',
    });
    const provider = makeProvider(llmResponse);
    const findings = [makeFinding()];
    const result = await enrichFindings(findings, provider, { contextLevel: 'minimal' });

    expect(result).toHaveLength(1);
    expect(result[0].aiEnhanced).toBe(true);
    expect(result[0].aiExplanation).toBe('This is a real SQL injection vulnerability');
    expect(result[0].originalConfidence).toBe('high');
  });

  it('sets confidence to low when isValid is false', async () => {
    const llmResponse = JSON.stringify({
      isValid: false,
      confidence: 'high',
      explanation: 'This is a false positive',
      remediation: 'N/A',
    });
    const provider = makeProvider(llmResponse);
    const findings = [makeFinding()];
    const result = await enrichFindings(findings, provider, { contextLevel: 'minimal' });

    expect(result[0].confidence).toBe('low');
    expect(result[0].aiEnhanced).toBe(true);
  });

  it('returns original finding on provider error', async () => {
    const provider: LlmProvider = {
      name: 'mock',
      call: vi.fn().mockRejectedValue(new Error('Connection refused')),
      validateConnection: vi.fn().mockResolvedValue(false),
    };
    const finding = makeFinding();
    const result = await enrichFindings([finding], provider, { contextLevel: 'minimal' });

    expect(result).toHaveLength(1);
    expect(result[0].aiEnhanced).toBeUndefined();
    expect(result[0].confidence).toBe('high');
  });

  it('respects maxFindings limit — findings beyond limit are passed through unchanged', async () => {
    const provider = makeProvider(JSON.stringify({ isValid: true, confidence: 'medium', explanation: 'ok', remediation: 'ok' }));
    const findings = Array.from({ length: 5 }, (_, i) => makeFinding({ line: i + 1 }));
    const result = await enrichFindings(findings, provider, { contextLevel: 'minimal', maxFindings: 2 });

    expect(result).toHaveLength(5);
    expect(result[0].aiEnhanced).toBe(true);
    expect(result[2].aiEnhanced).toBeUndefined();
  });

  it('returns original finding on unparseable response', async () => {
    const provider = makeProvider('not json at all');
    const finding = makeFinding();
    const result = await enrichFindings([finding], provider, { contextLevel: 'minimal' });
    expect(result[0].aiEnhanced).toBeUndefined();
  });
});
