import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';

export const FASTIFY002 = defineRule({
  id: 'FASTIFY-002',
  name: 'Missing Fastify Helmet',
  description: 'Detects Fastify applications without @fastify/helmet registered for security headers.',
  category: 'xss',
  severity: 'medium',
  frameworks: ['fastify'],
  tags: ['owasp:a5', 'cwe:693', 'xss'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];
    let hasHelmet = false;
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
          if (argText.includes('helmet') || text.includes('helmet')) {
            hasHelmet = true;
          }
        }
      }
      if (ts.isImportDeclaration(node)) {
        const moduleSpecifier = node.moduleSpecifier.getText(ctx.sourceFile);
        const spec = moduleSpecifier.replace(/^['"]|['"]$/g, '');
        if (spec === '@fastify/helmet' || spec === 'fastify-helmet') {
          hasHelmet = true;
        }
      }
      return 'continue';
    });

    if (ctx.content.includes('fastify()') || ctx.content.includes('Fastify()') || ctx.content.includes('require(\'fastify\')') || ctx.content.includes('require("fastify")')) {
      hasFastify = true;
    }

    if (hasFastify && !hasHelmet) {
      findings.push({
        ruleId: 'FASTIFY-002',
        ruleName: 'Missing Fastify Helmet',
        category: 'xss',
        severity: 'medium',
        filePath: ctx.filePath,
        line: fastifyLine,
        column: 1,
        endLine: fastifyLine,
        endColumn: 1,
        message: `Fastify application without @fastify/helmet registered. Missing security headers may enable XSS and other attacks.`,
        codeSnippet: '',
        remediation: 'Install and register helmet: install @fastify/helmet, then fastify.register(require(\'@fastify/helmet\'))',
        references: ['https://github.com/fastify/fastify-helmet'],
        confidence: 'low',
      });
    }

    return findings;
  },
});