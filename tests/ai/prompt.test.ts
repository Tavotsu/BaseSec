import { describe, it, expect } from 'vitest';
import {
  buildEnrichmentPrompt,
  buildAnalysisPrompt,
  parseEnrichmentResponse,
  parseAnalysisResponse,
} from '../../src/ai/prompt';

describe('buildEnrichmentPrompt', () => {
  it('includes all fields in output', () => {
    const result = buildEnrichmentPrompt({
      ruleId: 'SQLI-001',
      ruleName: 'SQL Injection',
      severity: 'high',
      category: 'sql-injection',
      codeSnippet: 'db.query(userInput)',
      message: 'Potential SQL injection',
    });
    expect(result).toContain('SQLI-001');
    expect(result).toContain('SQL Injection');
    expect(result).toContain('high');
    expect(result).toContain('db.query(userInput)');
    expect(result).toContain('"isValid"');
  });
});

describe('buildAnalysisPrompt', () => {
  it('includes file content and JSON schema', () => {
    const result = buildAnalysisPrompt({ fileContent: 'const x = req.body;' });
    expect(result).toContain('const x = req.body;');
    expect(result).toContain('"line"');
    expect(result).toContain('"severity"');
  });
});

describe('parseEnrichmentResponse', () => {
  it('parses valid JSON response', () => {
    const raw = JSON.stringify({
      isValid: true,
      confidence: 'high',
      explanation: 'Real vulnerability',
      remediation: 'Use parameterized queries',
    });
    const result = parseEnrichmentResponse(raw);
    expect(result).not.toBeNull();
    expect(result!.isValid).toBe(true);
    expect(result!.confidence).toBe('high');
    expect(result!.explanation).toBe('Real vulnerability');
  });

  it('extracts JSON from text with surrounding content', () => {
    const raw = 'Here is my analysis: {"isValid":false,"confidence":"low","explanation":"Not real","remediation":"N/A"}';
    const result = parseEnrichmentResponse(raw);
    expect(result).not.toBeNull();
    expect(result!.isValid).toBe(false);
  });

  it('returns null for invalid JSON', () => {
    expect(parseEnrichmentResponse('not json')).toBeNull();
  });

  it('returns null when isValid field missing', () => {
    expect(parseEnrichmentResponse('{"confidence":"high"}')).toBeNull();
  });

  it('defaults unknown confidence to medium', () => {
    const raw = JSON.stringify({ isValid: true, confidence: 'unknown', explanation: '', remediation: '' });
    const result = parseEnrichmentResponse(raw);
    expect(result!.confidence).toBe('medium');
  });
});

describe('parseAnalysisResponse', () => {
  it('parses valid array response', () => {
    const raw = JSON.stringify([
      { line: 5, severity: 'high', category: 'xss', message: 'XSS risk', remediation: 'Escape output', confidence: 'medium' },
    ]);
    const result = parseAnalysisResponse(raw);
    expect(result).toHaveLength(1);
    expect(result[0].line).toBe(5);
    expect(result[0].severity).toBe('high');
  });

  it('returns empty array for empty JSON array', () => {
    expect(parseAnalysisResponse('[]')).toEqual([]);
  });

  it('returns empty array for invalid JSON', () => {
    expect(parseAnalysisResponse('not json')).toEqual([]);
  });

  it('filters out items without required fields', () => {
    const raw = JSON.stringify([
      { severity: 'high' },
      { line: 5, message: 'valid' },
    ]);
    const result = parseAnalysisResponse(raw);
    expect(result).toHaveLength(1);
  });
});
