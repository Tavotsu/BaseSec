import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isTaintSource, containsSqlKeywords } from '../../../utils/patterns';
import { resolveConfidence, isExpressionTainted } from '../../../taint/integration';

export const SQLI001 = defineRule({
  id: 'SQLI-001',
  name: 'SQL String Concatenation',
  description: 'Detects SQL queries built via string concatenation with user input, which enables SQL injection.',
  category: 'sql-injection',
  severity: 'critical',
  frameworks: ['express', 'nestjs', '*'],
  tags: ['owasp:a1', 'cwe:89', 'sql-injection'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
        const text = node.getText(ctx.sourceFile);
        const leftText = node.left.getText(ctx.sourceFile);
        const rightText = node.right.getText(ctx.sourceFile);
        const isTainted = (isTaintSource(text) || isTaintSource(leftText) || isTaintSource(rightText))
          || (isExpressionTainted(ctx.taintGraph, leftText) || isExpressionTainted(ctx.taintGraph, rightText));
        if (containsSqlKeywords(text) && isTainted) {
          const taintText = isTaintSource(rightText) || isExpressionTainted(ctx.taintGraph, rightText) ? rightText : leftText;
          const { line, column } = getLineAndColumn(ctx.sourceFile, node);
          findings.push({
            ruleId: 'SQLI-001',
            ruleName: 'SQL String Concatenation',
            category: 'sql-injection',
            severity: 'critical',
            filePath: ctx.filePath,
            line,
            column,
            endLine: line,
            endColumn: column + text.length,
            message: `SQL injection via string concatenation. User input is directly concatenated into a SQL query.`,
            codeSnippet: getCodeSnippet(ctx.content, line),
            remediation: 'Use parameterized queries or an ORM query builder.',
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