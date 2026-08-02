import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { resolveConfidence, isExpressionTainted } from '../../../taint/integration';
import type { Finding } from '../../../rules/types';

const NAV_METHODS = new Set(['navigateByUrl', 'navigate']);
const PARAM_HINT = /queryParams|params|snapshot|route|location|\.search|\.hash/i;

export const NG005 = defineRule({
  id: 'NG-005',
  name: 'Open Redirect via Router.navigate',
  description: 'Detects Router.navigateByUrl()/navigate() with a destination derived from route/query params without validation.',
  category: 'xss',
  severity: 'high',
  frameworks: ['angular'],
  tags: ['owasp:a1', 'cwe:601', 'open-redirect'],
  detect(ctx) {
    const findings: Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && NAV_METHODS.has(node.expression.name.text)) {
        const receiver = node.expression.expression.getText(ctx.sourceFile).toLowerCase();
        if (!receiver.includes('router')) return 'continue';
        const arg = node.arguments[0];
        if (!arg) return 'continue';
        const argText = arg.getText(ctx.sourceFile);
        if ((PARAM_HINT.test(argText) || isExpressionTainted(ctx.taintGraph, argText)) && !ts.isStringLiteral(arg)) {
          const { line, column } = getLineAndColumn(ctx.sourceFile, node);
          findings.push({
            ruleId: 'NG-005',
            ruleName: 'Open Redirect via Router.navigate',
            category: 'xss',
            severity: 'high',
            filePath: ctx.filePath,
            line,
            column,
            endLine: line,
            endColumn: column + node.getText(ctx.sourceFile).length,
            message: `\`${node.expression.name.text}()\` destination derived from route/query params without validation (open redirect).`,
            codeSnippet: getCodeSnippet(ctx.content, line),
            remediation: 'Validate the target path against an allowlist before navigating.',
            references: ['https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet', 'https://cwe.mitre.org/data/definitions/601.html'],
            confidence: resolveConfidence(ctx.taintGraph, argText, 'medium'),
          });
        }
      }
      return 'continue';
    });

    return findings;
  },
});
