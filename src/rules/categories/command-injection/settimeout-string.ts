import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { findCallExpressions, getLineAndColumn, getCodeSnippet } from '../../../utils/ast-helpers';
import { isTaintSource } from '../../../utils/patterns';

export const CMDI003 = defineRule({
  id: 'CMDI-003',
  name: 'setTimeout/setInterval with String Argument',
  description: 'Detects setTimeout/setInterval called with a string argument, which acts like eval().',
  category: 'command-injection',
  severity: 'medium',
  frameworks: ['express', 'nestjs', '*'],
  tags: ['cwe:94', 'command-injection'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    for (const fn of ['setTimeout', 'setInterval']) {
      const calls = findCallExpressions(ctx.sourceFile, fn);
      for (const call of calls) {
        if (call.arguments.length > 0) {
          const firstArg = call.arguments[0];
          if (ts.isStringLiteral(firstArg) || ts.isTemplateExpression(firstArg)) {
            const text = call.getText(ctx.sourceFile);
            const { line, column } = getLineAndColumn(ctx.sourceFile, call);
            const confidence: import('../../../rules/types').Confidence = isTaintSource(text) ? 'high' : 'low';
            findings.push({
              ruleId: 'CMDI-003',
              ruleName: 'setTimeout/setInterval with String Argument',
              category: 'command-injection',
              severity: 'medium',
              filePath: ctx.filePath,
              line,
              column,
              endLine: line,
              endColumn: column + text.length,
              message: `${fn}() called with a string argument, which acts like eval().`,
              codeSnippet: getCodeSnippet(ctx.content, line),
              remediation: 'Always pass functions, not strings, to setTimeout/setInterval.',
              references: ['https://cwe.mitre.org/data/definitions/94.html'],
              confidence,
            });
          }
        }
      }
    }

    return findings;
  },
});