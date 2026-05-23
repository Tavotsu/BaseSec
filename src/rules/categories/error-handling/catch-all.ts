import { defineRule } from '../../define-rule';
import { getCodeSnippet } from '../../../utils/ast-helpers';

export const ERR002 = defineRule({
  id: 'ERR-002',
  name: 'Missing Global Error Handler',
  description: 'Detects Express applications without a global error handler middleware (4-argument function).',
  category: 'error-handling',
  severity: 'low',
  frameworks: ['express'],
  tags: ['owasp:a5', 'cwe:754', 'error-handling'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];
    let hasExpress = false;
    let hasErrorHandler = false;

    const lines = ctx.content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.includes('express()') || line.includes("require('express')") || line.includes('require("express")') || line.includes("from 'express'") || line.includes('from "express"')) {
        hasExpress = true;
      }

      if (line.includes('.use(') && (line.includes('err,') || line.includes('err :'))) {
        const trimmed = line.trim();
        if (trimmed.includes('(err,') || trimmed.includes('(err ') || trimmed.includes('(err:')) {
          hasErrorHandler = true;
        }
      }
    }

    if (hasExpress && !hasErrorHandler) {
      findings.push({
        ruleId: 'ERR-002',
        ruleName: 'Missing Global Error Handler',
        category: 'error-handling',
        severity: 'low',
        filePath: ctx.filePath,
        line: 1,
        column: 1,
        endLine: 1,
        endColumn: 1,
        message: `Express application without a global error handler middleware.`,
        codeSnippet: '',
        remediation: 'Add a 4-argument error handler: app.use((err, req, res, next) => { ... })',
        references: ['https://expressjs.com/en/guide/error-handling.html'],
        confidence: 'low',
      });
    }

    return findings;
  },
});