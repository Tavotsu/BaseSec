import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';

export const ERR003 = defineRule({
  id: 'ERR-003',
  name: 'Unhandled Promise Rejection',
  description: 'Detects async route handlers without try/catch or .catch(), which can cause unhandled rejections.',
  category: 'error-handling',
  severity: 'low',
  frameworks: ['express', 'nestjs', '*'],
  tags: ['cwe:754', 'error-handling'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr)) {
          const method = expr.name.text;
          if (['then', 'catch', 'finally'].includes(method)) {
            return 'continue';
          }
        }

        const text = node.getText(ctx.sourceFile);
        if (text.includes('await ') || text.startsWith('(async')) {
          const parent = node.parent;
          if (ts.isExpressionStatement(parent) || ts.isReturnStatement(parent)) {
            if (!text.includes('.catch') && !text.includes('try')) {
              const { line, column } = getLineAndColumn(ctx.sourceFile, node);
              if (line > 1) {
                const prevLine = ctx.content.split('\n')[line - 2]?.trim() || '';
                if (!prevLine.includes('try') && !prevLine.includes('.catch')) {
                  return 'continue';
                }
              }
            }
          }
        }
      }
      return 'continue';
    });

    return findings;
  },
});