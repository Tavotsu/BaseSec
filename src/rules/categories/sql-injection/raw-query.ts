import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isTaintSource } from '../../../utils/patterns';
import { resolveConfidence, isExpressionTainted } from '../../../taint/integration';
import { detectTypeORMPatterns } from '../../../framework/typeorm';

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

    const typeormPatterns = detectTypeORMPatterns(ctx.sourceFile);
    if (typeormPatterns.hasRawQueryWithoutParams) {
      for (const line of typeormPatterns.lineNumbers) {
        const lineText = ctx.content.split('\n')[line - 1] ?? '';
        findings.push({
          ruleId: 'SQLI-003',
          ruleName: 'Raw SQL Query Without Parameters',
          category: 'sql-injection',
          severity: 'critical',
          filePath: ctx.filePath,
          line,
          column: 1,
          endLine: line,
          endColumn: 120,
          message: `TypeORM raw query detected without parameterized arguments.`,
          codeSnippet: getCodeSnippet(ctx.content, line),
          remediation: 'Pass parameters as a second argument to .query() or use query builders.',
          references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
          confidence: resolveConfidence(ctx.taintGraph, lineText, 'medium'),
        });
      }
    }

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const text = node.getText(ctx.sourceFile);
        const isRawQuery = RAW_QUERY_METHODS.some((m) => text.includes(m));

        if (isRawQuery) {
          const args = node.arguments;
          const argText = args.length > 0 ? args[0].getText(ctx.sourceFile) : text;
          const singleStringArg = args.length === 1 && (ts.isStringLiteral(args[0]) || ts.isNoSubstitutionTemplateLiteral(args[0]));
          const hasTaint = args.length >= 1 && (isTaintSource(argText) || isExpressionTainted(ctx.taintGraph, argText));

          if (singleStringArg || hasTaint) {
            const { line, column } = getLineAndColumn(ctx.sourceFile, node);
            const alreadyReported = findings.some(f => f.line === line);
            if (!alreadyReported) {
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
                confidence: resolveConfidence(ctx.taintGraph, argText, hasTaint ? 'high' : 'medium'),
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