import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isTaintSource } from '../../../utils/patterns';
import { resolveConfidence, isExpressionTainted } from '../../../taint/integration';

const HEADER_RECEIVERS = new Set(['res', 'response', 'ctx']);

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

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr)) {
          const methodName = expr.name.text;
          if (methodName !== 'set' && methodName !== 'setHeader') return 'continue';

          const objText = expr.expression.getText(ctx.sourceFile).toLowerCase();

          const isResReceiver = Array.from(HEADER_RECEIVERS).some(
            (receiver) => objText === receiver || objText.endsWith(receiver)
          );

          if (isResReceiver) {
            const argTexts = node.arguments.map((a) => a.getText(ctx.sourceFile));
            const valueArgText = (methodName === 'set' || methodName === 'setHeader') && node.arguments.length >= 2
              ? argTexts[1]
              : argTexts[0] ?? node.getText(ctx.sourceFile);
            if (isTaintSource(valueArgText) || isExpressionTainted(ctx.taintGraph, valueArgText)) {
              const { line, column } = getLineAndColumn(ctx.sourceFile, node);
              const nodeText = node.getText(ctx.sourceFile);
              findings.push({
                ruleId: 'XSS-003',
                ruleName: 'Unsafe Response Header with User Input',
                category: 'xss',
                severity: 'medium',
                filePath: ctx.filePath,
                line,
                column,
                endLine: line,
                endColumn: column + nodeText.length,
                message: `User input used in response header, which may enable header injection or XSS.`,
                codeSnippet: getCodeSnippet(ctx.content, line),
                remediation: 'Validate and sanitize all user input before including it in HTTP headers.',
                references: ['https://owasp.org/www-community/attacks/xss/'],
                confidence: resolveConfidence(ctx.taintGraph, valueArgText, 'medium'),
              });
            }
          }
        }
      }
      return 'continue';
    });

    return findings;
  },
});