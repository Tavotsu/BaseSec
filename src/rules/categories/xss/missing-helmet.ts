import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';

export const XSS002 = defineRule({
  id: 'XSS-002',
  name: 'Missing Helmet Middleware',
  description: 'Detects Express applications without helmet() middleware for security headers.',
  category: 'xss',
  severity: 'medium',
  frameworks: ['express'],
  tags: ['owasp:a5', 'cwe:693', 'xss'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];
    let hasHelmet = false;
    let hasExpress = false;

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const text = node.getText(ctx.sourceFile);
        if (text.includes('helmet(')) {
          hasHelmet = true;
        }
      }
      if (ts.isImportDeclaration(node)) {
        const moduleSpecifier = node.moduleSpecifier.getText(ctx.sourceFile);
        const spec = moduleSpecifier.replace(/^['"]|['"]$/g, '');
        if (spec === 'helmet') {
          hasHelmet = true;
        }
      }
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr) && expr.name.text === 'use') {
          hasExpress = true;
        }
      }
      return 'continue';
    });

    if (ctx.content.includes('express()') || (ctx.content.includes('require(') && (ctx.content.includes("'express'") || ctx.content.includes('"express"')))) {
      hasExpress = true;
    }

    if (hasExpress && !hasHelmet) {
      const lines = ctx.content.split('\n');
      let expressLine = 1;
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes('express()') || lines[i].includes('express(')) {
          expressLine = i + 1;
          break;
        }
      }
      findings.push({
        ruleId: 'XSS-002',
        ruleName: 'Missing Helmet Middleware',
        category: 'xss',
        severity: 'medium',
        filePath: ctx.filePath,
        line: expressLine,
        column: 1,
        endLine: expressLine,
        endColumn: 1,
        message: `Express application without helmet() middleware. Missing security headers may enable XSS and other attacks.`,
        codeSnippet: getCodeSnippet(ctx.content, expressLine),
        remediation: 'Install and use helmet middleware: npm install helmet, then app.use(helmet())',
        references: ['https://helmetjs.github.io/', 'https://owasp.org/www-project-web-security-testing-guide/'],
        confidence: 'low',
      });
    }

    return findings;
  },
});