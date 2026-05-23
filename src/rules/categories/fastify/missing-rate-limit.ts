import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';

export const FASTIFY001 = defineRule({
  id: 'FASTIFY-001',
  name: 'Missing Fastify Rate Limiting',
  description: 'Detects Fastify applications without @fastify/rate-limit registered.',
  category: 'auth',
  severity: 'medium',
  frameworks: ['fastify'],
  tags: ['owasp:a7', 'cwe:307', 'auth'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];
    let hasRateLimit = false;
    let hasFastify = false;
    let fastifyLine = 1;

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const text = node.getText(ctx.sourceFile);
        if (text.includes('fastify()') || text.includes('Fastify()') || text.includes('require(\'fastify\')') || text.includes('require("fastify")')) {
          hasFastify = true;
          const { line } = getLineAndColumn(ctx.sourceFile, node);
          fastifyLine = line;
        }
        if (ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'register') {
          const argText = node.arguments.length > 0 ? node.arguments[0].getText(ctx.sourceFile) : '';
          if (argText.includes('rateLimit') || text.includes('rateLimit') || text.includes('@fastify/rate-limit')) {
            hasRateLimit = true;
          }
        }
      }
      if (ts.isImportDeclaration(node)) {
        const moduleSpecifier = node.moduleSpecifier.getText(ctx.sourceFile);
        const spec = moduleSpecifier.replace(/^['"]|['"]$/g, '');
        if (spec === '@fastify/rate-limit' || spec === 'fastify-rate-limit') {
          hasRateLimit = true;
        }
      }
      return 'continue';
    });

    if (ctx.content.includes('fastify()') || ctx.content.includes('Fastify()') || ctx.content.includes('require(\'fastify\')') || ctx.content.includes('require("fastify")')) {
      hasFastify = true;
    }

    // console.log('hasFastify:', hasFastify, 'hasRateLimit:', hasRateLimit);

    if (hasFastify && !hasRateLimit) {
      findings.push({
        ruleId: 'FASTIFY-001',
        ruleName: 'Missing Fastify Rate Limiting',
        category: 'auth',
        severity: 'medium',
        filePath: ctx.filePath,
        line: fastifyLine,
        column: 1,
        endLine: fastifyLine,
        endColumn: 1,
        message: `Fastify application without @fastify/rate-limit registered. Missing rate limiting may enable brute-force and DoS attacks.`,
        codeSnippet: '',
        remediation: 'Install and register rate-limit: install @fastify/rate-limit, then fastify.register(require(\'@fastify/rate-limit\'))',
        references: ['https://github.com/fastify/fastify-rate-limit'],
        confidence: 'low',
      });
    }

    return findings;
  },
});
