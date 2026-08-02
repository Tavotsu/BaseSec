import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isStaticLiteral } from '../../../framework/frontend';
import { resolveConfidence } from '../../../taint/integration';
import type { Finding } from '../../../rules/types';

const RENDER_FNS = new Set(['h', 'createElement']);

export const VUE003 = defineRule({
  id: 'VUE-003',
  name: 'innerHTML in Vue Render Function',
  description: 'Detects innerHTML passed via props to a Vue render function h()/createElement(), bypassing template escaping.',
  category: 'xss',
  severity: 'high',
  frameworks: ['vue'],
  tags: ['owasp:a3', 'cwe:79', 'vue'],
  detect(ctx) {
    const findings: Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && RENDER_FNS.has(node.expression.text)) {
        const propsArg = node.arguments[1];
        if (propsArg && ts.isObjectLiteralExpression(propsArg)) {
          for (const prop of propsArg.properties) {
            if (ts.isPropertyAssignment(prop) && prop.name.getText(ctx.sourceFile) === 'innerHTML' && !isStaticLiteral(prop.initializer)) {
              const argText = prop.initializer.getText(ctx.sourceFile);
              const { line, column } = getLineAndColumn(ctx.sourceFile, node);
              findings.push({
                ruleId: 'VUE-003',
                ruleName: 'innerHTML in Vue Render Function',
                category: 'xss',
                severity: 'high',
                filePath: ctx.filePath,
                line,
                column,
                endLine: line,
                endColumn: column + node.getText(ctx.sourceFile).length,
                message: 'innerHTML passed to a Vue render function bypasses template escaping (XSS).',
                codeSnippet: getCodeSnippet(ctx.content, line),
                remediation: 'Pass text children instead of innerHTML, or sanitize with DOMPurify.',
                references: ['https://vuejs.org/guide/best-practices/security.html', 'https://cwe.mitre.org/data/definitions/79.html'],
                confidence: resolveConfidence(ctx.taintGraph, argText, 'medium'),
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
