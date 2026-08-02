import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import type { Finding } from '../../../rules/types';

export const DOM004 = defineRule({
  id: 'DOM-004',
  name: 'postMessage with Wildcard Target Origin',
  description: 'Detects postMessage() calls that use "*" as the target origin, exposing message data to any origin.',
  category: 'misconfiguration',
  severity: 'medium',
  frameworks: ['*'],
  tags: ['owasp:a5', 'cwe:346', 'postmessage'],
  detect(ctx) {
    const findings: Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        const name = ts.isPropertyAccessExpression(expr) ? expr.name.text : ts.isIdentifier(expr) ? expr.text : '';
        if (name === 'postMessage' && node.arguments.length >= 2) {
          const target = node.arguments[1];
          if (ts.isStringLiteral(target) && target.text === '*') {
            const { line, column } = getLineAndColumn(ctx.sourceFile, node);
            findings.push({
              ruleId: 'DOM-004',
              ruleName: 'postMessage with Wildcard Target Origin',
              category: 'misconfiguration',
              severity: 'medium',
              filePath: ctx.filePath,
              line,
              column,
              endLine: line,
              endColumn: column + node.getText(ctx.sourceFile).length,
              message: 'postMessage() uses "*" as targetOrigin, sending data to any origin.',
              codeSnippet: getCodeSnippet(ctx.content, line),
              remediation: 'Pass an explicit target origin (e.g. "https://trusted.example.com") instead of "*".',
              references: ['https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage', 'https://cwe.mitre.org/data/definitions/346.html'],
              confidence: 'high',
            });
          }
        }
      }
      return 'continue';
    });

    return findings;
  },
});
