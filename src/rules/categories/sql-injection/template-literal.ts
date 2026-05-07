import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isTaintSource, containsSqlKeywords } from '../../../utils/patterns';
import { resolveConfidence, isExpressionTainted } from '../../../taint/integration';

export const SQLI002 = defineRule({
  id: 'SQLI-002',
  name: 'SQL Template Literal Injection',
  description: 'Detects SQL queries built via template literals with user input interpolation, which enables SQL injection.',
  category: 'sql-injection',
  severity: 'critical',
  frameworks: ['express', 'nestjs', '*'],
  tags: ['owasp:a1', 'cwe:89', 'sql-injection'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isTemplateExpression(node)) {
        const text = node.getText(ctx.sourceFile);
        let isTainted = isTaintSource(text) || isExpressionTainted(ctx.taintGraph, text);
        let taintText = text;
        if (!isTainted) {
          for (const span of node.templateSpans) {
            const spanText = span.expression.getText(ctx.sourceFile);
            if (isTaintSource(spanText) || isExpressionTainted(ctx.taintGraph, spanText)) {
              isTainted = true;
              taintText = spanText;
              break;
            }
          }
        }
        if (containsSqlKeywords(text) && isTainted) {
          const { line, column } = getLineAndColumn(ctx.sourceFile, node);
          findings.push({
            ruleId: 'SQLI-002',
            ruleName: 'SQL Template Literal Injection',
            category: 'sql-injection',
            severity: 'critical',
            filePath: ctx.filePath,
            line,
            column,
            endLine: line,
            endColumn: column + text.length,
            message: `SQL injection via template literal. User input is interpolated into a SQL query.`,
            codeSnippet: getCodeSnippet(ctx.content, line),
            remediation: 'Use parameterized queries instead of template literals for SQL.',
            references: ['https://owasp.org/www-community/attacks/SQL_Injection', 'https://cwe.mitre.org/data/definitions/89.html'],
            confidence: resolveConfidence(ctx.taintGraph, taintText, 'high'),
          });
        }
      }
      return 'continue';
    });

    return findings;
  },
});