import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';

export const KOA002 = defineRule({
  id: 'KOA-002',
  name: 'Missing Koa CORS',
  description: 'Detects Koa applications with permissive @koa/cors configuration.',
  category: 'misconfiguration',
  severity: 'high',
  frameworks: ['koa'],
  tags: ['owasp:a5', 'cwe:942', 'misconfiguration'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];
    let hasInsecureCors = false;
    let insecureCorsLine = 1;

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const text = node.getText(ctx.sourceFile);
        if (ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'use') {
          const argText = node.arguments.length > 0 ? node.arguments[0].getText(ctx.sourceFile) : '';
          if (argText.includes('cors') || text.includes('cors') || text.includes('@koa/cors')) {
            if (text.includes('origin') && (text.includes('*') || text.includes('origin: "*"') || text.includes("origin: '*'"))) {
              hasInsecureCors = true;
              const { line } = getLineAndColumn(ctx.sourceFile, node);
              insecureCorsLine = line;
            }
          }
        }
      }
      return 'continue';
    });

    if (hasInsecureCors) {
      findings.push({
        ruleId: 'KOA-002',
        ruleName: 'Permissive Koa CORS Configuration',
        category: 'misconfiguration',
        severity: 'high',
        filePath: ctx.filePath,
        line: insecureCorsLine,
        column: 1,
        endLine: insecureCorsLine,
        endColumn: 1,
        message: `Koa CORS configured with permissive origin.`,
        codeSnippet: getCodeSnippet(ctx.content, insecureCorsLine),
        remediation: 'Restrict CORS origins to trusted domains.',
        references: ['https://github.com/koajs/cors'],
        confidence: 'medium',
      });
    }

    return findings;
  },
});
