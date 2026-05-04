import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';

export const CONF002 = defineRule({
  id: 'CONF-002',
  name: 'Debug Mode in Production',
  description: 'Detects explicit development/debug environment configuration that may expose sensitive data.',
  category: 'misconfiguration',
  severity: 'high',
  frameworks: ['express', 'nestjs', '*'],
  tags: ['owasp:a5', 'cwe:489', 'misconfiguration'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const text = node.getText(ctx.sourceFile);
        if (text.includes("set('env'") || text.includes("set(\"env\"")) {
          if (text.includes("'development'") || text.includes('"development"')) {
            const { line, column } = getLineAndColumn(ctx.sourceFile, node);
            findings.push({
              ruleId: 'CONF-002',
              ruleName: 'Debug Mode in Production',
              category: 'misconfiguration',
              severity: 'high',
              filePath: ctx.filePath,
              line,
              column,
              endLine: line,
              endColumn: column + text.length,
              message: `Express environment explicitly set to 'development', which may expose debug information.`,
              codeSnippet: getCodeSnippet(ctx.content, line),
              remediation: "Set NODE_ENV=production in production. Don't hardcode app.set('env', 'development').",
              references: ['https://expressjs.com/en/advanced/best-practice-performance.html'],
              confidence: 'medium',
            });
          }
        }
      }

      if (ts.isIfStatement(node)) {
        const text = node.getText(ctx.sourceFile);
        if (text.includes('NODE_ENV') && (text.includes("'development'") || text.includes('"development"') || text.includes("'production'") || text.includes('"production"'))) {
          return 'continue';
        }
      }
      return 'continue';
    });

    return findings;
  },
});