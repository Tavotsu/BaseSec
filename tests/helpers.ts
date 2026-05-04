import * as ts from 'typescript';
import type { Finding, Rule, RuleContext, secbaseConfig, TaintGraph } from '../../src/rules/types';

export function createSourceFile(code: string, fileName = 'test.ts'): ts.SourceFile {
  return ts.createSourceFile(
    fileName,
    code,
    ts.ScriptTarget.Latest,
    true,
    fileName.endsWith('.js') ? ts.ScriptKind.JS : ts.ScriptKind.TS,
  );
}

export function createRuleContext(
  code: string,
  fileName = 'test.ts',
  overrides: Partial<RuleContext> = {},
): RuleContext {
  const sourceFile = createSourceFile(code, fileName);
  return {
    sourceFile,
    filePath: fileName,
    content: code,
    config: {
      target: ['./src'],
      ignore: [],
      framework: 'auto',
      severity: 'low',
      taintAnalysis: true,
      rules: [],
      rulesConfig: {},
      sanitizers: [],
      output: { format: 'terminal' },
    },
    ...overrides,
  };
}

export function runRule(rule: Rule, code: string, fileName = 'test.ts'): Finding[] {
  const ctx = createRuleContext(code, fileName);
  return rule.detect(ctx);
}

export function expectFinding(findings: Finding[], ruleId: string): Finding[] {
  return findings.filter((f) => f.ruleId === ruleId);
}

export function expectNoFindings(findings: Finding[], ruleId: string): boolean {
  return findings.filter((f) => f.ruleId === ruleId).length === 0;
}