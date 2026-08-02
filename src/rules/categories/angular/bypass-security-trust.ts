import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isStaticLiteral } from '../../../framework/frontend';
import { resolveConfidence } from '../../../taint/integration';
import type { Finding } from '../../../rules/types';

const BYPASS_METHODS = new Set([
  'bypassSecurityTrustHtml', 'bypassSecurityTrustScript', 'bypassSecurityTrustStyle',
  'bypassSecurityTrustUrl', 'bypassSecurityTrustResourceUrl',
]);

export const NG001 = defineRule({
  id: 'NG-001',
  name: 'DomSanitizer bypassSecurityTrust with Dynamic Value',
  description: "Detects DomSanitizer.bypassSecurityTrust*() called with a non-literal value, disabling Angular's XSS protection.",
  category: 'xss',
  severity: 'critical',
  frameworks: ['angular'],
  tags: ['owasp:a3', 'cwe:79', 'angular'],
  detect(ctx) {
    const findings: Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const method = node.expression.name.text;
        if (BYPASS_METHODS.has(method) && node.arguments.length > 0 && !isStaticLiteral(node.arguments[0])) {
          const argText = node.arguments[0].getText(ctx.sourceFile);
          const { line, column } = getLineAndColumn(ctx.sourceFile, node);
          findings.push({
            ruleId: 'NG-001',
            ruleName: 'DomSanitizer bypassSecurityTrust with Dynamic Value',
            category: 'xss',
            severity: 'critical',
            filePath: ctx.filePath,
            line,
            column,
            endLine: line,
            endColumn: column + node.getText(ctx.sourceFile).length,
            message: `\`${method}()\` with a non-literal value disables Angular's built-in sanitization (XSS).`,
            codeSnippet: getCodeSnippet(ctx.content, line),
            remediation: 'Avoid bypassing the sanitizer for dynamic values; let Angular sanitize, or sanitize explicitly with DOMPurify.',
            references: ['https://angular.dev/best-practices/security', 'https://cwe.mitre.org/data/definitions/79.html'],
            confidence: resolveConfidence(ctx.taintGraph, argText, 'high'),
          });
        }
      }
      return 'continue';
    });

    return findings;
  },
});
