import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isTaintSource } from '../../../utils/patterns';
import { resolveConfidence, isExpressionTainted } from '../../../taint/integration';

export const NOSQL001 = defineRule({
  id: 'NOSQL-001',
  name: 'MongoDB $where with User Input',
  description: 'Detects use of MongoDB $where operator with user-supplied values, allowing arbitrary JavaScript execution.',
  category: 'nosql-injection',
  severity: 'critical',
  frameworks: ['mongoose', '*'],
  tags: ['owasp:a1', 'cwe:943', 'nosql-injection'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr) && expr.name.text === '$where') {
          const argText = node.arguments.length > 0 ? node.arguments[0].getText(ctx.sourceFile) : node.getText(ctx.sourceFile);
          const isTainted = isTaintSource(argText) || isExpressionTainted(ctx.taintGraph, argText);
          if (node.arguments.length > 0 && isTainted) {
            const { line, column } = getLineAndColumn(ctx.sourceFile, node);
            findings.push({
              ruleId: 'NOSQL-001',
              ruleName: 'MongoDB $where with User Input',
              category: 'nosql-injection',
              severity: 'critical',
              filePath: ctx.filePath,
              line,
              column,
              endLine: line,
              endColumn: column + node.getText(ctx.sourceFile).length,
              message: `MongoDB $where operator with user input allows arbitrary JavaScript execution in the database.`,
              codeSnippet: getCodeSnippet(ctx.content, line),
              remediation: 'Never use $where with user input. Use proper query operators instead.',
              references: ['https://owasp.org/www-community/attacks/NoSQL_Injection'],
              confidence: resolveConfidence(ctx.taintGraph, argText, 'high'),
            });
          }
        }
      }

      if (ts.isPropertyAssignment(node)) {
        const name = node.name;
        if ((ts.isIdentifier(name) && name.text === '$where') || (ts.isStringLiteral(name) && name.text === '$where')) {
          const initText = node.initializer ? node.initializer.getText(ctx.sourceFile) : node.getText(ctx.sourceFile);
          const isTainted = isTaintSource(initText) || isExpressionTainted(ctx.taintGraph, initText);
          if (isTainted) {
            const { line, column } = getLineAndColumn(ctx.sourceFile, node);
            findings.push({
              ruleId: 'NOSQL-001',
              ruleName: 'MongoDB $where with User Input',
              category: 'nosql-injection',
              severity: 'critical',
              filePath: ctx.filePath,
              line,
              column,
              endLine: line,
              endColumn: column + node.getText(ctx.sourceFile).length,
              message: `MongoDB $where operator with user input allows arbitrary JavaScript execution.`,
              codeSnippet: getCodeSnippet(ctx.content, line),
              remediation: 'Never use $where with user input. Use proper query operators instead.',
              references: ['https://owasp.org/www-community/attacks/NoSQL_Injection'],
              confidence: resolveConfidence(ctx.taintGraph, initText, 'high'),
            });
          }
        }
      }
      return 'continue';
    });

    return findings;
  },
});