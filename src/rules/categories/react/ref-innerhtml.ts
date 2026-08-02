import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isStaticLiteral } from '../../../framework/frontend';
import { resolveConfidence } from '../../../taint/integration';
import type { Finding } from '../../../rules/types';

export const REACT003 = defineRule({
  id: 'REACT-003',
  name: 'innerHTML via React ref',
  description: 'Detects assignment to ref.current.innerHTML in React components, bypassing JSX escaping.',
  category: 'xss',
  severity: 'high',
  frameworks: ['react', 'nextjs'],
  tags: ['owasp:a3', 'cwe:79', 'react'],
  detect(ctx) {
    const findings: Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isPropertyAccessExpression(node.left) &&
        node.left.name.text === 'innerHTML' &&
        ts.isPropertyAccessExpression(node.left.expression) &&
        node.left.expression.name.text === 'current' &&
        !isStaticLiteral(node.right)
      ) {
        const argText = node.right.getText(ctx.sourceFile);
        const { line, column } = getLineAndColumn(ctx.sourceFile, node);
        findings.push({
          ruleId: 'REACT-003',
          ruleName: 'innerHTML via React ref',
          category: 'xss',
          severity: 'high',
          filePath: ctx.filePath,
          line,
          column,
          endLine: line,
          endColumn: column + node.getText(ctx.sourceFile).length,
          message: 'Assigning innerHTML through a React ref bypasses JSX escaping and can cause XSS.',
          codeSnippet: getCodeSnippet(ctx.content, line),
          remediation: 'Set ref.current.textContent, or sanitize with DOMPurify before assigning innerHTML.',
          references: ['https://react.dev/reference/react-dom/components/common', 'https://cwe.mitre.org/data/definitions/79.html'],
          confidence: resolveConfidence(ctx.taintGraph, argText, 'medium'),
        });
      }
      return 'continue';
    });

    return findings;
  },
});
