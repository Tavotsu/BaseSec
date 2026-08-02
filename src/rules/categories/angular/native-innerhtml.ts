import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isStaticLiteral } from '../../../framework/frontend';
import { resolveConfidence } from '../../../taint/integration';
import type { Finding } from '../../../rules/types';

export const NG002 = defineRule({
  id: 'NG-002',
  name: 'innerHTML via ElementRef.nativeElement',
  description: "Detects assignment to nativeElement.innerHTML, bypassing Angular's DOM sanitizer.",
  category: 'xss',
  severity: 'high',
  frameworks: ['angular'],
  tags: ['owasp:a3', 'cwe:79', 'angular'],
  detect(ctx) {
    const findings: Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isPropertyAccessExpression(node.left) &&
        node.left.name.text === 'innerHTML' &&
        ts.isPropertyAccessExpression(node.left.expression) &&
        node.left.expression.name.text === 'nativeElement' &&
        !isStaticLiteral(node.right)
      ) {
        const argText = node.right.getText(ctx.sourceFile);
        const { line, column } = getLineAndColumn(ctx.sourceFile, node);
        findings.push({
          ruleId: 'NG-002',
          ruleName: 'innerHTML via ElementRef.nativeElement',
          category: 'xss',
          severity: 'high',
          filePath: ctx.filePath,
          line,
          column,
          endLine: line,
          endColumn: column + node.getText(ctx.sourceFile).length,
          message: 'Assigning nativeElement.innerHTML bypasses Angular sanitization (XSS).',
          codeSnippet: getCodeSnippet(ctx.content, line),
          remediation: 'Use Angular property binding ([innerText]) or Renderer2; sanitize HTML with DomSanitizer.sanitize().',
          references: ['https://angular.dev/best-practices/security', 'https://cwe.mitre.org/data/definitions/79.html'],
          confidence: resolveConfidence(ctx.taintGraph, argText, 'medium'),
        });
      }
      return 'continue';
    });

    return findings;
  },
});
