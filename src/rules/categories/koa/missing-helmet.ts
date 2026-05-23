import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';

export const KOA001 = defineRule({
  id: 'KOA-001',
  name: 'Missing Koa Helmet',
  description: 'Detects Koa applications without koa-helmet used for security headers.',
  category: 'xss',
  severity: 'medium',
  frameworks: ['koa'],
  tags: ['owasp:a5', 'cwe:693', 'xss'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];
    let hasHelmet = false;
    let hasKoa = false;
    let koaLine = 1;

    visit(ctx.sourceFile, (node) => {
      if (ts.isNewExpression(node)) {
        const text = node.getText(ctx.sourceFile);
        if (text.includes('new Koa()')) {
          hasKoa = true;
          const { line } = getLineAndColumn(ctx.sourceFile, node);
          koaLine = line;
        }
      }
      if (ts.isImportDeclaration(node)) {
        const moduleSpecifier = node.moduleSpecifier.getText(ctx.sourceFile);
        const spec = moduleSpecifier.replace(/^['"]|['"]$/g, '');
        if (spec === 'koa-helmet') {
          hasHelmet = true;
        }
      }
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr) && expr.name.text === 'use') {
          const argText = node.arguments.length > 0 ? node.arguments[0].getText(ctx.sourceFile) : '';
          if (argText.includes('helmet') || argText.includes('koa-helmet')) {
            hasHelmet = true;
          }
        }
      }
      return 'continue';
    });

    if (ctx.content.includes('new Koa()') || (ctx.content.includes('require(') && (ctx.content.includes("'koa'") || ctx.content.includes('"koa"')))) {
      hasKoa = true;
    }

    if (hasKoa && !hasHelmet) {
      findings.push({
        ruleId: 'KOA-001',
        ruleName: 'Missing Koa Helmet',
        category: 'xss',
        severity: 'medium',
        filePath: ctx.filePath,
        line: koaLine,
        column: 1,
        endLine: koaLine,
        endColumn: 1,
        message: `Koa application without koa-helmet used. Missing security headers may enable XSS and other attacks.`,
        codeSnippet: '',
        remediation: 'Install and use helmet: npm install koa-helmet, then app.use(helmet())',
        references: ['https://github.com/venables/koa-helmet'],
        confidence: 'low',
      });
    }

    return findings;
  },
});
