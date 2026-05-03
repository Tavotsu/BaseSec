import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isTaintSource, containsSqlKeywords } from '../../../utils/patterns';

export const SQLI004 = defineRule({
  id: 'SQLI-004',
  name: 'SQL Injection via Knex Raw Query',
  description: 'Detects knex.raw() calls with string concatenation or template literals containing user input.',
  category: 'sql-injection',
  severity: 'high',
  frameworks: ['express', 'nestjs', '*'],
  tags: ['owasp:a1', 'cwe:89', 'sql-injection'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr) && expr.name.text === 'raw') {
          const text = node.getText(ctx.sourceFile);
          if (isTaintSource(text) || (node.arguments.length === 1 && containsSqlKeywords(text))) {
            const firstArg = node.arguments[0];
            if (firstArg && (ts.isTemplateExpression(firstArg) || ts.isBinaryExpression(firstArg))) {
              const { line, column } = getLineAndColumn(ctx.sourceFile, node);
              findings.push({
                ruleId: 'SQLI-004',
                ruleName: 'SQL Injection via Knex Raw Query',
                category: 'sql-injection',
                severity: 'high',
                filePath: ctx.filePath,
                line,
                column,
                endLine: line,
                endColumn: column + text.length,
                message: `SQL injection via knex.raw() with unsanitized input.`,
                codeSnippet: getCodeSnippet(ctx.content, line),
                remediation: 'Use knex.raw() with parameter bindings: knex.raw(\'SELECT * FROM users WHERE id = ?\', [id])',
                references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
                confidence: 'medium',
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