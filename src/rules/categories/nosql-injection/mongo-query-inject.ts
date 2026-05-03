import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isTaintSource } from '../../../utils/patterns';

const MONGOOSE_FIND_METHODS = ['find', 'findOne', 'findByIdAndUpdate', 'findOneAndUpdate', 'findByIdAndDelete', 'findOneAndDelete', 'findOneAndRemove'];

export const NOSQL002 = defineRule({
  id: 'NOSQL-002',
  name: 'Mongoose Query Object Injection',
  description: 'Detects passing req.body or req.query directly to Mongoose find/findOne, allowing query operator injection.',
  category: 'nosql-injection',
  severity: 'high',
  frameworks: ['mongoose', '*'],
  tags: ['owasp:a1', 'cwe:943', 'nosql-injection'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr) && MONGOOSE_FIND_METHODS.includes(expr.name.text)) {
          const firstArg = node.arguments[0];
          if (firstArg) {
            const argText = firstArg.getText(ctx.sourceFile);
            if (isTaintSource(argText) || argText.includes('req.body') || argText.includes('req.query')) {
              const { line, column } = getLineAndColumn(ctx.sourceFile, node);
              findings.push({
                ruleId: 'NOSQL-002',
                ruleName: 'Mongoose Query Object Injection',
                category: 'nosql-injection',
                severity: 'high',
                filePath: ctx.filePath,
                line,
                column,
                endLine: line,
                endColumn: column + node.getText(ctx.sourceFile).length,
                message: `Passing user input directly to Mongoose query enables NoSQL operator injection (e.g., $ne, $gt).`,
                codeSnippet: getCodeSnippet(ctx.content, line),
                remediation: 'Explicitly pick only expected fields from user input. Use DTOs and validation.',
                references: ['https://owasp.org/www-community/attacks/NoSQL_Injection'],
                confidence: 'high',
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