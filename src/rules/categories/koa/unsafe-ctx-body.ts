import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isTaintSource } from '../../../utils/patterns';
import { resolveConfidence, isExpressionTainted } from '../../../taint/integration';

export const KOA003 = defineRule({
  id: 'KOA-003',
  name: 'Unsafe ctx.body with User Input',
  description: 'Detects assignment of user-controlled input directly to ctx.body, which may allow XSS.',
  category: 'xss',
  severity: 'high',
  frameworks: ['koa'],
  tags: ['owasp:a3', 'cwe:79', 'xss'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        const left = node.left;
        if (ts.isPropertyAccessExpression(left)) {
          if (left.name.text === 'body' && (left.expression.getText(ctx.sourceFile) === 'ctx' || left.expression.getText(ctx.sourceFile) === 'ctx.response')) {
            const rightText = node.right.getText(ctx.sourceFile);
            if (isTaintSource(rightText) || isExpressionTainted(ctx.taintGraph, rightText)) {
              const { line, column } = getLineAndColumn(ctx.sourceFile, node);
              const nodeText = node.getText(ctx.sourceFile);
              findings.push({
                ruleId: 'KOA-003',
                ruleName: 'Unsafe ctx.body with User Input',
                category: 'xss',
                severity: 'high',
                filePath: ctx.filePath,
                line,
                column,
                endLine: line,
                endColumn: column + nodeText.length,
                message: `Potential XSS: ctx.body assigned unsanitized user input.`,
                codeSnippet: getCodeSnippet(ctx.content, line),
                remediation: 'Always encode user input before including it in HTTP responses.',
                references: ['https://owasp.org/www-community/attacks/xss/'],
                confidence: resolveConfidence(ctx.taintGraph, rightText, 'medium'),
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
