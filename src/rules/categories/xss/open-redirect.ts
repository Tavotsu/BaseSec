import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { findCallExpressions, getLineAndColumn, getCodeSnippet } from '../../../utils/ast-helpers';
import { isTaintSource } from '../../../utils/patterns';

export const XSS004 = defineRule({
  id: 'XSS-004',
  name: 'Open Redirect',
  description: 'Detects res.redirect() with user-controlled input, enabling open redirect attacks.',
  category: 'xss',
  severity: 'medium',
  frameworks: ['express', 'nestjs', '*'],
  tags: ['owasp:a1', 'cwe:601', 'xss'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    const calls = findCallExpressions(ctx.sourceFile, 'redirect');
    for (const call of calls) {
      const text = call.getText(ctx.sourceFile);
      if (isTaintSource(text)) {
        const { line, column } = getLineAndColumn(ctx.sourceFile, call);
        findings.push({
          ruleId: 'XSS-004',
          ruleName: 'Open Redirect',
          category: 'xss',
          severity: 'medium',
          filePath: ctx.filePath,
          line,
          column,
          endLine: line,
          endColumn: column + text.length,
          message: `Open redirect: res.redirect() called with user-controlled input.`,
          codeSnippet: getCodeSnippet(ctx.content, line),
          remediation: 'Validate redirect URLs against a whitelist. Use relative URLs or validate the host.',
          references: ['https://owasp.org/www-community/attacks/Open_redirect', 'https://cwe.mitre.org/data/definitions/601.html'],
          confidence: 'medium',
        });
      }
    }

    return findings;
  },
});