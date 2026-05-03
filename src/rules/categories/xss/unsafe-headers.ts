import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { findCallExpressions, getLineAndColumn, getCodeSnippet } from '../../../utils/ast-helpers';
import { isTaintSource } from '../../../utils/patterns';

export const XSS003 = defineRule({
  id: 'XSS-003',
  name: 'Unsafe Response Header with User Input',
  description: 'Detects res.set() or res.setHeader() with user-controlled values, enabling header injection.',
  category: 'xss',
  severity: 'medium',
  frameworks: ['express', '*'],
  tags: ['owasp:a3', 'cwe:79', 'xss'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    for (const method of ['set', 'setHeader']) {
      const calls = findCallExpressions(ctx.sourceFile, method);
      for (const call of calls) {
        const text = call.getText(ctx.sourceFile);
        if (isTaintSource(text)) {
          const { line, column } = getLineAndColumn(ctx.sourceFile, call);
          findings.push({
            ruleId: 'XSS-003',
            ruleName: 'Unsafe Response Header with User Input',
            category: 'xss',
            severity: 'medium',
            filePath: ctx.filePath,
            line,
            column,
            endLine: line,
            endColumn: column + text.length,
            message: `User input used in response header, which may enable header injection or XSS.`,
            codeSnippet: getCodeSnippet(ctx.content, line),
            remediation: 'Validate and sanitize all user input before including it in HTTP headers.',
            references: ['https://owasp.org/www-community/attacks/xss/'],
            confidence: 'medium',
          });
        }
      }
    }

    return findings;
  },
});