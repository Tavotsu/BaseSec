import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';

export const CONF001 = defineRule({
  id: 'CONF-001',
  name: 'Missing Content-Security-Policy',
  description: 'Detects Express applications without Content-Security-Policy header or helmet middleware.',
  category: 'misconfiguration',
  severity: 'medium',
  frameworks: ['express'],
  tags: ['owasp:a5', 'cwe:693', 'misconfiguration'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];
    let hasCSP = false;
    let hasExpress = false;
    let expressLine = 1;

    if (ctx.content.includes('express()') || ctx.content.includes("require('express')") || ctx.content.includes('require("express")') || ctx.content.includes("from 'express'") || ctx.content.includes('from "express"')) {
      hasExpress = true;
    }

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const text = node.getText(ctx.sourceFile);
        if (text.includes('helmet()') || text.includes('helmet(') || text.includes('contentSecurityPolicy') || text.includes('Content-Security-Policy')) {
          hasCSP = true;
        }
        if (text.includes('express()')) {
          const { line } = getLineAndColumn(ctx.sourceFile, node);
          expressLine = line;
        }
      }
      return 'continue';
    });

    if (hasExpress && !hasCSP) {
      findings.push({
        ruleId: 'CONF-001',
        ruleName: 'Missing Content-Security-Policy',
        category: 'misconfiguration',
        severity: 'medium',
        filePath: ctx.filePath,
        line: expressLine,
        column: 1,
        endLine: expressLine,
        endColumn: 1,
        message: `Express application without Content-Security-Policy header.`,
        codeSnippet: getCodeSnippet(ctx.content, expressLine),
        remediation: 'Use helmet() middleware or set CSP headers manually: app.use(helmet())',
        references: ['https://owasp.org/www-project-web-security-testing-guide/'],
        confidence: 'low',
      });
    }

    return findings;
  },
});