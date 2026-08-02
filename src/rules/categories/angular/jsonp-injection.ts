import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isStaticLiteral } from '../../../framework/frontend';
import { resolveConfidence } from '../../../taint/integration';
import type { Finding } from '../../../rules/types';

export const NG004 = defineRule({
  id: 'NG-004',
  name: 'HttpClient.jsonp with Dynamic URL',
  description: 'Detects HttpClient.jsonp() with a URL or callback derived from user input, enabling script injection via JSONP.',
  category: 'xss',
  severity: 'high',
  frameworks: ['angular'],
  tags: ['owasp:a3', 'cwe:79', 'angular'],
  detect(ctx) {
    const findings: Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'jsonp') {
        const dynamicArg = node.arguments.find((a) => !isStaticLiteral(a));
        if (dynamicArg) {
          const argText = dynamicArg.getText(ctx.sourceFile);
          const { line, column } = getLineAndColumn(ctx.sourceFile, node);
          findings.push({
            ruleId: 'NG-004',
            ruleName: 'HttpClient.jsonp with Dynamic URL',
            category: 'xss',
            severity: 'high',
            filePath: ctx.filePath,
            line,
            column,
            endLine: line,
            endColumn: column + node.getText(ctx.sourceFile).length,
            message: 'HttpClient.jsonp() with a dynamic URL/callback loads and executes remote script (XSS).',
            codeSnippet: getCodeSnippet(ctx.content, line),
            remediation: 'Prefer a normal CORS request; if JSONP is unavoidable, use only fixed, trusted endpoints.',
            references: ['https://angular.dev/best-practices/security', 'https://cwe.mitre.org/data/definitions/79.html'],
            confidence: resolveConfidence(ctx.taintGraph, argText, 'medium'),
          });
        }
      }
      return 'continue';
    });

    return findings;
  },
});
