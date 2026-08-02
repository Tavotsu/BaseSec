import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isFrontendFile, isStaticLiteral } from '../../../framework/frontend';
import { resolveConfidence, isExpressionTainted } from '../../../taint/integration';
import type { Finding } from '../../../rules/types';

// Hints that the argument carries network/URL data — the DOM-specific angle that
// distinguishes this from the generic eval rule (CMDI-002).
const NETWORK_URL_HINT = /location|fetch|response|responseText|XMLHttpRequest|searchParams|\.json\(|\.text\(|document\.URL|document\.cookie/i;

export const DOM007 = defineRule({
  id: 'DOM-007',
  name: 'Dynamic Code Execution with Network/URL Data',
  description: 'Detects eval()/new Function()/setTimeout(string) fed with network- or URL-derived data in frontend code.',
  category: 'command-injection',
  severity: 'critical',
  frameworks: ['*'],
  tags: ['owasp:a3', 'cwe:95', 'dom-xss'],
  detect(ctx) {
    if (!isFrontendFile(ctx.filePath)) return [];
    const findings: Finding[] = [];

    const flag = (node: ts.Node, argText: string, what: string) => {
      if (!NETWORK_URL_HINT.test(argText) && !isExpressionTainted(ctx.taintGraph, argText)) return;
      const { line, column } = getLineAndColumn(ctx.sourceFile, node);
      findings.push({
        ruleId: 'DOM-007',
        ruleName: 'Dynamic Code Execution with Network/URL Data',
        category: 'command-injection',
        severity: 'critical',
        filePath: ctx.filePath,
        line,
        column,
        endLine: line,
        endColumn: column + node.getText(ctx.sourceFile).length,
        message: `${what} executes network/URL-derived data as code.`,
        codeSnippet: getCodeSnippet(ctx.content, line),
        remediation: 'Never pass remote or URL data to eval/Function/setTimeout. Parse it with JSON.parse or dispatch on a fixed set of actions.',
        references: ['https://owasp.org/www-community/attacks/DOM_Based_XSS', 'https://cwe.mitre.org/data/definitions/95.html'],
        confidence: resolveConfidence(ctx.taintGraph, argText, 'high'),
      });
    };

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isIdentifier(expr) && expr.text === 'eval' && node.arguments.length > 0) {
          flag(node, node.arguments[0].getText(ctx.sourceFile), '`eval()`');
        }
        if (ts.isIdentifier(expr) && (expr.text === 'setTimeout' || expr.text === 'setInterval') && node.arguments.length > 0) {
          const first = node.arguments[0];
          if (!ts.isArrowFunction(first) && !ts.isFunctionExpression(first) && !isStaticLiteral(first)) {
            flag(node, first.getText(ctx.sourceFile), `\`${expr.text}(string)\``);
          }
        }
      }
      if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'Function' && node.arguments && node.arguments.length > 0) {
        flag(node, node.arguments.map((a) => a.getText(ctx.sourceFile)).join(','), '`new Function()`');
      }
      return 'continue';
    });

    return findings;
  },
});
