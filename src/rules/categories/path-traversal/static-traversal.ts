import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';

export const PATH002 = defineRule({
  id: 'PATH-002',
  name: 'Insecure Express Static Configuration',
  description: 'Detects express.static() with insecure options, potentially serving sensitive files.',
  category: 'path-traversal',
  severity: 'medium',
  frameworks: ['express'],
  tags: ['owasp:a5', 'cwe:22', 'path-traversal'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr) && expr.name.text === 'static') {
          const text = node.getText(ctx.sourceFile);
          const hasDotfilesDeny = text.includes('deny') || text.includes("'deny'") || text.includes('"deny"');
          if (!hasDotfilesDeny && text.includes('dotfiles')) {
            const { line, column } = getLineAndColumn(ctx.sourceFile, node);
            findings.push({
              ruleId: 'PATH-002',
              ruleName: 'Insecure Express Static Configuration',
              category: 'path-traversal',
              severity: 'medium',
              filePath: ctx.filePath,
              line,
              column,
              endLine: line,
              endColumn: column + text.length,
              message: `express.static() with dotfiles option not set to 'deny' may expose hidden files.`,
              codeSnippet: getCodeSnippet(ctx.content, line),
              remediation: "Set dotfiles: 'deny' in express.static() options.",
              references: ['https://expressjs.com/en/4x/api.html#express.static'],
              confidence: 'low',
            });
          }
        }
      }
      return 'continue';
    });

    return findings;
  },
});