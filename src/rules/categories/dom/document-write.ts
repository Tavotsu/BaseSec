import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isStaticLiteral } from '../../../framework/frontend';
import { resolveConfidence } from '../../../taint/integration';
import type { Finding } from '../../../rules/types';

const WRITE_METHODS = new Set(['write', 'writeln']);

export const DOM002 = defineRule({
  id: 'DOM-002',
  name: 'Unsafe document.write()',
  description: 'Detects document.write()/writeln() called with dynamic input, which can lead to DOM-based XSS.',
  category: 'xss',
  severity: 'medium',
  frameworks: ['*'],
  tags: ['owasp:a3', 'cwe:79', 'dom-xss'],
  detect(ctx) {
    const findings: Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const expr = node.expression;
        const objText = expr.expression.getText(ctx.sourceFile);
        if (objText === 'document' && WRITE_METHODS.has(expr.name.text)) {
          if (node.arguments.length > 0 && !isStaticLiteral(node.arguments[0])) {
            const argText = node.arguments[0].getText(ctx.sourceFile);
            const { line, column } = getLineAndColumn(ctx.sourceFile, node);
            findings.push({
              ruleId: 'DOM-002',
              ruleName: 'Unsafe document.write()',
              category: 'xss',
              severity: 'medium',
              filePath: ctx.filePath,
              line,
              column,
              endLine: line,
              endColumn: column + node.getText(ctx.sourceFile).length,
              message: `\`document.${expr.name.text}()\` with dynamic input can introduce DOM-based XSS.`,
              codeSnippet: getCodeSnippet(ctx.content, line),
              remediation: 'Avoid document.write(); build DOM nodes with textContent or a sanitized template instead.',
              references: ['https://owasp.org/www-community/attacks/DOM_Based_XSS', 'https://cwe.mitre.org/data/definitions/79.html'],
              confidence: resolveConfidence(ctx.taintGraph, argText, 'medium'),
            });
          }
        }
      }
      return 'continue';
    });

    return findings;
  },
});
