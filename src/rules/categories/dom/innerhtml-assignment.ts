import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isStaticLiteral } from '../../../framework/frontend';
import { resolveConfidence } from '../../../taint/integration';
import type { Finding } from '../../../rules/types';

const HTML_SINK_PROPS = new Set(['innerHTML', 'outerHTML']);

export const DOM001 = defineRule({
  id: 'DOM-001',
  name: 'Unsafe innerHTML/outerHTML/insertAdjacentHTML Assignment',
  description: 'Detects assignment of dynamic values to innerHTML/outerHTML or insertAdjacentHTML calls, which can lead to DOM-based XSS.',
  category: 'xss',
  severity: 'high',
  frameworks: ['*'],
  tags: ['owasp:a3', 'cwe:79', 'dom-xss'],
  detect(ctx) {
    const findings: Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isPropertyAccessExpression(node.left) &&
        HTML_SINK_PROPS.has(node.left.name.text) &&
        !isStaticLiteral(node.right)
      ) {
        const rhsText = node.right.getText(ctx.sourceFile);
        const { line, column } = getLineAndColumn(ctx.sourceFile, node);
        findings.push({
          ruleId: 'DOM-001',
          ruleName: 'Unsafe innerHTML/outerHTML/insertAdjacentHTML Assignment',
          category: 'xss',
          severity: 'high',
          filePath: ctx.filePath,
          line,
          column,
          endLine: line,
          endColumn: column + node.getText(ctx.sourceFile).length,
          message: `Assigning a dynamic value to \`.${node.left.name.text}\` can introduce DOM-based XSS.`,
          codeSnippet: getCodeSnippet(ctx.content, line),
          remediation: 'Use textContent, or sanitize the value with DOMPurify before assigning to innerHTML/outerHTML.',
          references: ['https://owasp.org/www-community/attacks/DOM_Based_XSS', 'https://cwe.mitre.org/data/definitions/79.html'],
          confidence: resolveConfidence(ctx.taintGraph, rhsText, 'medium'),
        });
      }

      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === 'insertAdjacentHTML' &&
        node.arguments.length >= 2 &&
        !isStaticLiteral(node.arguments[1])
      ) {
        const argText = node.arguments[1].getText(ctx.sourceFile);
        const { line, column } = getLineAndColumn(ctx.sourceFile, node);
        findings.push({
          ruleId: 'DOM-001',
          ruleName: 'Unsafe innerHTML/outerHTML/insertAdjacentHTML Assignment',
          category: 'xss',
          severity: 'high',
          filePath: ctx.filePath,
          line,
          column,
          endLine: line,
          endColumn: column + node.getText(ctx.sourceFile).length,
          message: 'insertAdjacentHTML() with a dynamic value can introduce DOM-based XSS.',
          codeSnippet: getCodeSnippet(ctx.content, line),
          remediation: 'Sanitize the HTML with DOMPurify, or use insertAdjacentText for plain text.',
          references: ['https://owasp.org/www-community/attacks/DOM_Based_XSS', 'https://cwe.mitre.org/data/definitions/79.html'],
          confidence: resolveConfidence(ctx.taintGraph, argText, 'medium'),
        });
      }

      return 'continue';
    });

    return findings;
  },
});
