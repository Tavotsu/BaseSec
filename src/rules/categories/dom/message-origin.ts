import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import type { Finding } from '../../../rules/types';

// Only the global object receives cross-origin postMessage traffic. Gating on it
// keeps this '*' rule off Node's worker_threads MessagePort.addEventListener('message')
// and off WebSocket/EventSource handlers, where event.origin means something else.
const GLOBAL_RECEIVERS = new Set(['window', 'self', 'globalThis', 'top', 'parent']);

function isGlobalReceiver(node: ts.Expression, sourceFile: ts.SourceFile): boolean {
  return GLOBAL_RECEIVERS.has(node.getText(sourceFile));
}

function handlerChecksOrigin(handler: ts.Node, sourceFile: ts.SourceFile): boolean {
  return handler.getText(sourceFile).includes('origin');
}

export const DOM005 = defineRule({
  id: 'DOM-005',
  name: 'message Listener Without Origin Check',
  description: 'Detects window "message" event listeners whose handler does not validate event.origin, allowing spoofed cross-origin messages.',
  category: 'auth',
  severity: 'high',
  frameworks: ['*'],
  tags: ['owasp:a1', 'cwe:346', 'postmessage'],
  detect(ctx) {
    const findings: Finding[] = [];

    const push = (node: ts.Node) => {
      const { line, column } = getLineAndColumn(ctx.sourceFile, node);
      findings.push({
        ruleId: 'DOM-005',
        ruleName: 'message Listener Without Origin Check',
        category: 'auth',
        severity: 'high',
        filePath: ctx.filePath,
        line,
        column,
        endLine: line,
        endColumn: column + node.getText(ctx.sourceFile).length,
        message: 'A "message" event handler does not validate event.origin.',
        codeSnippet: getCodeSnippet(ctx.content, line),
        remediation: 'Check event.origin against an allowlist at the top of the handler before trusting event.data.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/API/Window/message_event', 'https://cwe.mitre.org/data/definitions/346.html'],
        confidence: 'medium',
      });
    };

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node) && node.arguments.length >= 2) {
        const expr = node.expression;
        const isGlobalListener = ts.isPropertyAccessExpression(expr)
          ? expr.name.text === 'addEventListener' && isGlobalReceiver(expr.expression, ctx.sourceFile)
          : ts.isIdentifier(expr) && expr.text === 'addEventListener';
        if (isGlobalListener) {
          const evt = node.arguments[0];
          if (ts.isStringLiteral(evt) && evt.text === 'message') {
            const handler = node.arguments[1];
            if (!handlerChecksOrigin(handler, ctx.sourceFile)) push(node);
          }
        }
      }

      if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isPropertyAccessExpression(node.left) &&
        node.left.name.text === 'onmessage' &&
        isGlobalReceiver(node.left.expression, ctx.sourceFile) &&
        !handlerChecksOrigin(node.right, ctx.sourceFile)
      ) {
        push(node);
      }

      return 'continue';
    });

    return findings;
  },
});
