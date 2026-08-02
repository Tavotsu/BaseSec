import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { resolveConfidence, isExpressionTainted } from '../../../taint/integration';
import type { Finding } from '../../../rules/types';

const PARAM_HINT = /searchParams|query|params/i;

export const NEXT002 = defineRule({
  id: 'NEXT-002',
  name: 'Open Redirect via Next redirect()',
  description: 'Detects redirect()/res.redirect() with a destination derived from searchParams/query, allowing open redirect.',
  category: 'xss',
  severity: 'high',
  frameworks: ['react', 'nextjs'],
  tags: ['owasp:a1', 'cwe:601', 'open-redirect'],
  detect(ctx) {
    const findings: Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        const name = ts.isIdentifier(expr) ? expr.text : ts.isPropertyAccessExpression(expr) ? expr.name.text : '';
        if (name === 'redirect' && node.arguments.length > 0) {
          const arg = node.arguments[0];
          const argText = arg.getText(ctx.sourceFile);
          if ((PARAM_HINT.test(argText) || isExpressionTainted(ctx.taintGraph, argText)) && !ts.isStringLiteral(arg)) {
            const { line, column } = getLineAndColumn(ctx.sourceFile, node);
            findings.push({
              ruleId: 'NEXT-002',
              ruleName: 'Open Redirect via Next redirect()',
              category: 'xss',
              severity: 'high',
              filePath: ctx.filePath,
              line,
              column,
              endLine: line,
              endColumn: column + node.getText(ctx.sourceFile).length,
              message: 'redirect() destination is derived from request params without validation (open redirect).',
              codeSnippet: getCodeSnippet(ctx.content, line),
              remediation: 'Validate the target against an allowlist of internal paths before redirecting.',
              references: ['https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet', 'https://cwe.mitre.org/data/definitions/601.html'],
              confidence: resolveConfidence(ctx.taintGraph, argText, 'medium'),
            });
          }
        }
      }
      return 'continue';
    });

    return findings;
  },
});
