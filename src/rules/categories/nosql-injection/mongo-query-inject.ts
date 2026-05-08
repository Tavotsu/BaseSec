import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isTaintSource } from '../../../utils/patterns';
import { resolveConfidence, isExpressionTainted } from '../../../taint/integration';
import { detectMongoosePatterns } from '../../../framework/mongoose';

const MONGOOSE_FIND_METHODS = ['find', 'findOne', 'findById', 'findByIdAndUpdate', 'findOneAndUpdate', 'findByIdAndDelete', 'findOneAndDelete', 'findOneAndRemove'];

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

    const mongoosePatterns = detectMongoosePatterns(ctx.sourceFile, ctx.content);
    if (mongoosePatterns.hasDirectQueryPass) {
      for (const line of mongoosePatterns.directQueryLineNumbers) {
        const alreadyReported = findings.some(f => f.line === line);
        if (!alreadyReported) {
          const lineText = ctx.content.split('\n')[line - 1] ?? '';
          findings.push({
            ruleId: 'NOSQL-002',
            ruleName: 'Mongoose Query Object Injection',
            category: 'nosql-injection',
            severity: 'high',
            filePath: ctx.filePath,
            line,
            column: 1,
            endLine: line,
            endColumn: 120,
            message: `Passing user input directly to Mongoose query enables NoSQL operator injection (e.g., $ne, $gt).`,
            codeSnippet: getCodeSnippet(ctx.content, line),
            remediation: 'Explicitly pick only expected fields from user input. Use DTOs and validation.',
            references: ['https://owasp.org/www-community/attacks/NoSQL_Injection'],
            confidence: resolveConfidence(ctx.taintGraph, lineText, 'high'),
          });
        }
      }
    }

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr) && MONGOOSE_FIND_METHODS.includes(expr.name.text)) {
          const firstArg = node.arguments[0];
          if (firstArg) {
            const argText = firstArg.getText(ctx.sourceFile);
            const isTainted = isTaintSource(argText) || isExpressionTainted(ctx.taintGraph, argText);
            if (isTainted) {
              const { line, column } = getLineAndColumn(ctx.sourceFile, node);
              const alreadyReported = findings.some(f => f.line === line);
              if (!alreadyReported) {
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
                  confidence: resolveConfidence(ctx.taintGraph, argText, 'high'),
                });
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