import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isTaintSource } from '../../../utils/patterns';
import { resolveConfidence, isExpressionTainted } from '../../../taint/integration';

const REDIRECT_RECEIVERS = new Set(['res', 'response', 'ctx']);

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

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr) && expr.name.text === 'redirect') {
          const objText = expr.expression.getText(ctx.sourceFile);
          const isResReceiver = Array.from(REDIRECT_RECEIVERS).some(
            (r) => objText === r || objText.endsWith(r.charAt(0).toUpperCase() + r.slice(1)) || objText.endsWith('Res') || objText.endsWith('Response') || objText.endsWith('Ctx')
          );
          if (!isResReceiver) return 'continue';

          const argText = node.arguments.length > 0 ? node.arguments[0].getText(ctx.sourceFile) : node.getText(ctx.sourceFile);
          if (isTaintSource(argText) || isExpressionTainted(ctx.taintGraph, argText)) {
            const { line, column } = getLineAndColumn(ctx.sourceFile, node);
            const nodeText = node.getText(ctx.sourceFile);
            findings.push({
              ruleId: 'XSS-004',
              ruleName: 'Open Redirect',
              category: 'xss',
              severity: 'medium',
              filePath: ctx.filePath,
              line,
              column,
              endLine: line,
              endColumn: column + nodeText.length,
              message: `Open redirect: res.redirect() called with user-controlled input.`,
              codeSnippet: getCodeSnippet(ctx.content, line),
              remediation: 'Validate redirect URLs against a whitelist. Use relative URLs or validate the host.',
              references: ['https://owasp.org/www-community/attacks/Open_redirect', 'https://cwe.mitre.org/data/definitions/601.html'],
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