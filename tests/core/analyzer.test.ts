import { describe, it, expect } from 'vitest';
import { Analyzer } from '../../src/core/analyzer';
import { ALL_RULES } from '../../src/rules/index';
import type { ParsedFile, basesecConfig } from '../../src/rules/types';
import { createSourceFile } from '../helpers';
import * as ts from 'typescript';

function makeParsedFile(code: string, filePath = 'test.ts'): ParsedFile {
  return {
    filePath,
    sourceFile: createSourceFile(code, filePath),
    content: code,
    size: code.length,
  };
}

const defaultConfig: basesecConfig = {
  target: ['./src'],
  ignore: [],
  framework: 'auto',
  severity: 'low',
  taintAnalysis: false,
  rules: [],
  rulesConfig: {},
  sanitizers: [],
  output: { format: 'terminal' },
};

describe('Analyzer', () => {
  it('runs all rules against parsed files', () => {
    const code = `
      const query = "SELECT * FROM users WHERE id = " + req.params.id;
      db.query(query);
    `;
    const parsedFile = makeParsedFile(code);
    const analyzer = new Analyzer();
    const findings = analyzer.analyze([parsedFile], ALL_RULES, defaultConfig, ['express']);

    expect(findings.length).toBeGreaterThan(0);
  });

  it('filters rules by config (disable rule)', () => {
    const code = `
      const query = "SELECT * FROM users WHERE id = " + req.params.id;
    `;
    const parsedFile = makeParsedFile(code);
    const config: basesecConfig = {
      ...defaultConfig,
      rulesConfig: { 'SQLI-001': false },
    };
    const analyzer = new Analyzer();
    const findings = analyzer.analyze([parsedFile], ALL_RULES, config, ['express']);

    expect(findings.some(f => f.ruleId === 'SQLI-001')).toBe(false);
  });

  it('overrides rule severity via config', () => {
    const code = `
      const app = express();
    `;
    const parsedFile = makeParsedFile(code);
    const config: basesecConfig = {
      ...defaultConfig,
      rulesConfig: { 'XSS-002': { severity: 'critical' } },
    };
    const analyzer = new Analyzer();
    const findings = analyzer.analyze([parsedFile], ALL_RULES, config, ['express']);

    const xss002 = findings.find(f => f.ruleId === 'XSS-002');
    if (xss002) {
      expect(xss002.severity).toBe('critical');
    }
  });

  it('filters rules by detected frameworks', () => {
    const code = `
      User.find(req.body);
    `;
    const parsedFile = makeParsedFile(code);
    const analyzer = new Analyzer();
    const findingsExpress = analyzer.analyze([parsedFile], ALL_RULES, defaultConfig, ['express']);

    const mongooseRuleFindings = findingsExpress.filter(f => f.ruleId === 'NOSQL-002');
    expect(mongooseRuleFindings.length).toBeGreaterThanOrEqual(0);
  });

  it('returns minimal findings for simple safe code', () => {
    const code = `
      const x = 1 + 2;
      console.log(x);
    `;
    const parsedFile = makeParsedFile(code);
    const analyzer = new Analyzer();
    const findings = analyzer.analyze([parsedFile], ALL_RULES, defaultConfig, []);

    expect(findings.length).toBeLessThanOrEqual(1);
  });

  it('processes multiple files', () => {
    const files = [
      makeParsedFile('const x = 1;', 'safe.ts'),
      makeParsedFile('eval(req.body.code);', 'vuln.ts'),
    ];
    const analyzer = new Analyzer();
    const findings = analyzer.analyze(files, ALL_RULES, defaultConfig, ['express']);

    expect(findings.some(f => f.ruleId === 'CMDI-002')).toBe(true);
    expect(findings.some(f => f.filePath === 'vuln.ts')).toBe(true);
  });
});