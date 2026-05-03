import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { findCallExpressions, getLineAndColumn, getCodeSnippet } from '../../../utils/ast-helpers';
import { isTaintSource } from '../../../utils/patterns';

const SEND_METHODS = ['send', 'json', 'end', 'write'];

export const XSS001 = defineRule({
  id: 'XSS-001',
  name: 'Unsafe res.send() with User Input',
  description: 'Detects res.send(), res.json(), etc. with unsanitized user input, which may allow XSS.',
  category: 'xss',
  severity: 'high',
  frameworks: ['express', '*'],
  tags: ['owasp:a3', 'cwe:79', 'xss'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    for (const method of SEND_METHODS) {
      const calls = findCallExpressions(ctx.sourceFile, method);
      for (const call of calls) {
        const text = call.getText(ctx.sourceFile);
        if (isTaintSource(text) || text.includes('req.body') || text.includes('req.query') || text.includes('req.params')) {
          const { line, column } = getLineAndColumn(ctx.sourceFile, call);
          findings.push({
            ruleId: 'XSS-001',
            ruleName: 'Unsafe res.send() with User Input',
            category: 'xss',
            severity: 'high',
            filePath: ctx.filePath,
            line,
            column,
            endLine: line,
            endColumn: column + text.length,
            message: `Potential XSS: \`res.${method}()\` called with unsanitized user input.`,
            codeSnippet: getCodeSnippet(ctx.content, line),
            remediation: 'Always encode user input before including it in HTTP responses. Use a template engine with auto-escaping.',
            references: ['https://owasp.org/www-community/attacks/xss/', 'https://cwe.mitre.org/data/definitions/79.html'],
            confidence: 'medium',
          });
        }
      }
    }

    return findings;
  },
});