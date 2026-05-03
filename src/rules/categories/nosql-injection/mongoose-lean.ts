import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';

export const NOSQL003 = defineRule({
  id: 'NOSQL-003',
  name: 'Mongoose Lean Data Leak',
  description: 'Detects .lean() calls on Mongoose queries that may expose sensitive fields marked with select: false.',
  category: 'nosql-injection',
  severity: 'medium',
  frameworks: ['mongoose'],
  tags: ['cwe:200', 'nosql-injection'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr) && expr.name.text === 'lean') {
          const { line, column } = getLineAndColumn(ctx.sourceFile, node);
          findings.push({
            ruleId: 'NOSQL-003',
            ruleName: 'Mongoose Lean Data Leak',
            category: 'nosql-injection',
            severity: 'medium',
            filePath: ctx.filePath,
            line,
            column,
            endLine: line,
            endColumn: column + node.getText(ctx.sourceFile).length,
            message: `.lean() bypasses Mongoose document middleware, potentially exposing sensitive fields.`,
            codeSnippet: getCodeSnippet(ctx.content, line),
            remediation: 'Use explicit field selection with .select() before .lean(): Model.find().select("-password").lean()',
            references: ['https://mongoosejs.com/docs/guide.html#select', 'https://cwe.mitre.org/data/definitions/200.html'],
            confidence: 'low',
          });
        }
      }
      return 'continue';
    });

    return findings;
  },
});