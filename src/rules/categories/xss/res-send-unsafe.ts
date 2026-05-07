import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { findCallExpressions, getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isTaintSource } from '../../../utils/patterns';
import { resolveConfidence, isExpressionTainted } from '../../../taint/integration';

const SEND_METHODS = ['send', 'json', 'end', 'write'];
const RES_RECEIVERS = new Set(['res', 'response', 'ctx']);

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

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr)) {
          const methodName = expr.name.text;
          if (!SEND_METHODS.includes(methodName)) return 'continue';

          const objText = expr.expression.getText(ctx.sourceFile);
          const isRes = RES_RECEIVERS.has(objText) || objText.endsWith('Res') || objText.endsWith('Response') || objText.endsWith('Ctx');
          if (!isRes) return 'continue';

          const argText = node.arguments.length > 0 ? node.arguments[0].getText(ctx.sourceFile) : node.getText(ctx.sourceFile);
          if (isTaintSource(argText) || isExpressionTainted(ctx.taintGraph, argText)) {
            const { line, column } = getLineAndColumn(ctx.sourceFile, node);
            const nodeText = node.getText(ctx.sourceFile);
            findings.push({
              ruleId: 'XSS-001',
              ruleName: 'Unsafe res.send() with User Input',
              category: 'xss',
              severity: 'high',
              filePath: ctx.filePath,
              line,
              column,
              endLine: line,
              endColumn: column + nodeText.length,
              message: `Potential XSS: \`res.${methodName}()\` called with unsanitized user input.`,
              codeSnippet: getCodeSnippet(ctx.content, line),
              remediation: 'Always encode user input before including it in HTTP responses. Use a template engine with auto-escaping.',
              references: ['https://owasp.org/www-community/attacks/xss/', 'https://cwe.mitre.org/data/definitions/79.html'],
              confidence: resolveConfidence(ctx.taintGraph, argText, 'medium'),
            });
          }
        }
      }
      return 'continue';
    });

    return findings;
  },
});