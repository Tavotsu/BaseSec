import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isStaticLiteral } from '../../../framework/frontend';
import { resolveConfidence } from '../../../taint/integration';
import type { Finding } from '../../../rules/types';

export const REACT001 = defineRule({
  id: 'REACT-001',
  name: 'dangerouslySetInnerHTML with Dynamic Value',
  description: 'Detects React dangerouslySetInnerHTML fed a non-literal value, a direct XSS vector.',
  category: 'xss',
  severity: 'critical',
  frameworks: ['react', 'nextjs'],
  tags: ['owasp:a3', 'cwe:79', 'react'],
  detect(ctx) {
    const findings: Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isJsxAttribute(node) && node.name.getText(ctx.sourceFile) === 'dangerouslySetInnerHTML') {
        const init = node.initializer;
        if (init && ts.isJsxExpression(init) && init.expression && ts.isObjectLiteralExpression(init.expression)) {
          for (const prop of init.expression.properties) {
            if (ts.isPropertyAssignment(prop) && prop.name.getText(ctx.sourceFile) === '__html' && !isStaticLiteral(prop.initializer)) {
              const argText = prop.initializer.getText(ctx.sourceFile);
              const { line, column } = getLineAndColumn(ctx.sourceFile, node);
              findings.push({
                ruleId: 'REACT-001',
                ruleName: 'dangerouslySetInnerHTML with Dynamic Value',
                category: 'xss',
                severity: 'critical',
                filePath: ctx.filePath,
                line,
                column,
                endLine: line,
                endColumn: column + node.getText(ctx.sourceFile).length,
                message: 'dangerouslySetInnerHTML is set from a non-literal value, allowing XSS.',
                codeSnippet: getCodeSnippet(ctx.content, line),
                remediation: 'Render text as children, or sanitize the HTML with DOMPurify before passing __html.',
                references: ['https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html', 'https://cwe.mitre.org/data/definitions/79.html'],
                confidence: resolveConfidence(ctx.taintGraph, argText, 'high'),
              });
            }
          }
        }
      }
      return 'continue';
    });

    return findings;
  },
});
