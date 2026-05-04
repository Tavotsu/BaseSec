import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';

export const ERR003 = defineRule({
  id: 'ERR-003',
  name: 'Unhandled Promise Rejection',
  description: 'Detects async route handlers without try/catch or .catch(), and missing project-level unhandledRejection handler.',
  category: 'error-handling',
  severity: 'low',
  frameworks: ['express', 'nestjs', '*'],
  tags: ['cwe:754', 'error-handling'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    let hasGlobalHandler = false;
    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr)) {
          const obj = expr.expression;
          const method = expr.name.text;
          if (
            method === 'on' &&
            ts.isIdentifier(obj) &&
            obj.text === 'process'
          ) {
            const args = node.arguments;
            if (args.length >= 1 && ts.isStringLiteral(args[0])) {
              if (args[0].text === 'unhandledRejection') {
                hasGlobalHandler = true;
              }
            }
          }
        }
      }
      return 'continue';
    });

    if (!hasGlobalHandler) {
      const { line: firstLine } = getLineAndColumn(ctx.sourceFile, ctx.sourceFile.getChildAt(0));
      findings.push({
        ruleId: 'ERR-003',
        ruleName: 'Unhandled Promise Rejection',
        category: 'error-handling',
        severity: 'low',
        filePath: ctx.filePath,
        line: 1,
        column: 1,
        endLine: 1,
        endColumn: 1,
        message: `No process.on('unhandledRejection') handler found. Unhandled promise rejections can crash the process.`,
        codeSnippet: getCodeSnippet(ctx.content, 1),
        remediation: "Add process.on('unhandledRejection', (reason) => { logger.error(reason); }) at the application entry point.",
        references: ['https://nodejs.org/api/process.html#process_event_unhandledrejection'],
        confidence: 'medium',
      });
    }

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr)) {
          const method = expr.name.text;
          if (['then', 'catch', 'finally'].includes(method)) {
            return 'continue';
          }
        }

        const text = node.getText(ctx.sourceFile);
        if (text.includes('await ') || text.startsWith('(async')) {
          const parent = node.parent;
          if (ts.isExpressionStatement(parent) || ts.isReturnStatement(parent)) {
            if (!text.includes('.catch') && !text.includes('try')) {
              const { line, column } = getLineAndColumn(ctx.sourceFile, node);
              const hasNearbyErrorHandling = line > 1 && (() => {
                const prevLine = ctx.content.split('\n')[line - 2]?.trim() || '';
                return prevLine.includes('try') || prevLine.includes('.catch');
              })();
              if (!hasNearbyErrorHandling) {
                findings.push({
                  ruleId: 'ERR-003',
                  ruleName: 'Unhandled Promise Rejection',
                  category: 'error-handling',
                  severity: 'low',
                  filePath: ctx.filePath,
                  line,
                  column,
                  endLine: line,
                  endColumn: column + text.length,
                  message: `Async operation without error handling may cause unhandled promise rejection.`,
                  codeSnippet: getCodeSnippet(ctx.content, line),
                  remediation: 'Wrap async operations in try/catch or chain .catch() handlers.',
                  references: ['https://nodejs.org/api/process.html#process_event_unhandledrejection'],
                  confidence: 'low',
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