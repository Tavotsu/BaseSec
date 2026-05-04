import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isTaintSource } from '../../../utils/patterns';

const RAW_QUERY_METHODS = ['.query(', '.raw('];

export const SQLI003 = defineRule({
  id: 'SQLI-003',
  name: 'Raw SQL Query Without Parameters',
  description: 'Detects raw query calls (e.g., manager.query(), repository.query()) without parameterized arguments.',
  category: 'sql-injection',
  severity: 'critical',
  frameworks: ['nestjs', 'typeorm', '*'],
  tags: ['owasp:a1', 'cwe:89', 'sql-injection'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const text = node.getText(ctx.sourceFile);
        const isRawQuery = RAW_QUERY_METHODS.some((m) => text.includes(m));

        if (isRawQuery) {
          const callText = node.expression.getText(ctx.sourceFile);
          const args = node.arguments;
          const singleStringArg = args.length === 1 && (ts.isStringLiteral(args[0]) || ts.isNoSubstitutionTemplateLiteral(args[0]));
          const hasTaint = args.length >= 1 && isTaintSource(text);

          if (singleStringArg || hasTaint) {
            const { line, column } = getLineAndColumn(ctx.sourceFile, node);
            findings.push({
              ruleId: 'SQLI-003',
              ruleName: 'Raw SQL Query Without Parameters',
              category: 'sql-injection',
              severity: 'critical',
              filePath: ctx.filePath,
              line,
              column,
              endLine: line,
              endColumn: column + text.length,
              message: `Raw SQL query call without parameterized arguments. Pass query parameters as a second argument.`,
              codeSnippet: getCodeSnippet(ctx.content, line),
              remediation: 'Pass parameters as a second argument to .query() or use query builders.',
              references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
              confidence: hasTaint ? 'high' : 'medium',
            });
          }
        }
      }
      return 'continue';
    });

    return findings;
  },
});