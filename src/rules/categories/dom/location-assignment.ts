import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isStaticLiteral } from '../../../framework/frontend';
import { resolveConfidence } from '../../../taint/integration';
import type { Finding } from '../../../rules/types';

function isLocationHref(left: ts.Expression, sourceFile: ts.SourceFile): boolean {
  if (!ts.isPropertyAccessExpression(left)) return false;
  const text = left.getText(sourceFile);
  return text === 'location.href' || text === 'window.location.href' ||
    text === 'document.location.href' || text.endsWith('.location.href');
}

export const DOM003 = defineRule({
  id: 'DOM-003',
  name: 'Open Redirect via location/window.open',
  description: 'Detects assignment to location.href or window.open() with dynamic input, which can cause open redirect or javascript: URI execution.',
  category: 'xss',
  severity: 'high',
  frameworks: ['*'],
  tags: ['owasp:a1', 'cwe:601', 'open-redirect'],
  detect(ctx) {
    const findings: Finding[] = [];

    const push = (node: ts.Node, argText: string, what: string) => {
      const { line, column } = getLineAndColumn(ctx.sourceFile, node);
      findings.push({
        ruleId: 'DOM-003',
        ruleName: 'Open Redirect via location/window.open',
        category: 'xss',
        severity: 'high',
        filePath: ctx.filePath,
        line,
        column,
        endLine: line,
        endColumn: column + node.getText(ctx.sourceFile).length,
        message: `${what} with dynamic input can cause an open redirect or execute a javascript: URI.`,
        codeSnippet: getCodeSnippet(ctx.content, line),
        remediation: 'Validate the destination against an allowlist and reject non-http(s) schemes before navigating.',
        references: ['https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet', 'https://cwe.mitre.org/data/definitions/601.html'],
        confidence: resolveConfidence(ctx.taintGraph, argText, 'medium'),
      });
    };

    visit(ctx.sourceFile, (node) => {
      if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        isLocationHref(node.left, ctx.sourceFile) &&
        !isStaticLiteral(node.right)
      ) {
        push(node, node.right.getText(ctx.sourceFile), '`location.href` assignment');
      }

      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const expr = node.expression;
        const objText = expr.expression.getText(ctx.sourceFile);
        if (expr.name.text === 'open' && (objText === 'window' || objText === 'self' || objText === 'top')) {
          if (node.arguments.length > 0 && !isStaticLiteral(node.arguments[0])) {
            push(node, node.arguments[0].getText(ctx.sourceFile), '`window.open()`');
          }
        }
      }

      return 'continue';
    });

    return findings;
  },
});
