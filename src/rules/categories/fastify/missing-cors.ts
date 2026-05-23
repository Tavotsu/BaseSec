import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';

export const FASTIFY003 = defineRule({
  id: 'FASTIFY-003',
  name: 'Missing Fastify CORS',
  description: 'Detects Fastify applications without @fastify/cors registered or with insecure configuration.',
  category: 'misconfiguration',
  severity: 'high',
  frameworks: ['fastify'],
  tags: ['owasp:a5', 'cwe:942', 'misconfiguration'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];
    let hasCors = false;
    let hasInsecureCors = false;
    let insecureCorsLine = 1;

    visit(ctx.sourceFile, (node) => {
      if (ts.isImportDeclaration(node)) {
        const moduleSpecifier = node.moduleSpecifier.getText(ctx.sourceFile);
        const spec = moduleSpecifier.replace(/^['"]|['"]$/g, '');
        if (spec === '@fastify/cors' || spec === 'fastify-cors') {
          hasCors = true;
        }
      }
      if (ts.isCallExpression(node)) {
        const text = node.getText(ctx.sourceFile);
        if (ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'register') {
          const argText = node.arguments.length > 0 ? node.arguments[0].getText(ctx.sourceFile) : '';
          if (argText.includes('cors') || text.includes('cors') || text.includes('@fastify/cors')) {
            hasCors = true;
            if (text.includes('origin') && (text.includes('*') || text.includes('origin: "*"') || text.includes("origin: '*'") || text.includes('origin: true'))) {
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
        ruleId: 'FASTIFY-003',
        ruleName: 'Permissive Fastify CORS Configuration',
        category: 'misconfiguration',
        severity: 'high',
        filePath: ctx.filePath,
        line: insecureCorsLine,
        column: 1,
        endLine: insecureCorsLine,
        endColumn: 1,
        message: `Fastify CORS configured with permissive origin.`,
        codeSnippet: getCodeSnippet(ctx.content, insecureCorsLine),
        remediation: 'Restrict CORS origins to trusted domains.',
        references: ['https://github.com/fastify/fastify-cors'],
        confidence: 'medium',
      });
    }

    return findings;
  },
});
