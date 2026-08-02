import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isFrontendFile } from '../../../framework/frontend';
import { resolveConfidence, isExpressionTainted } from '../../../taint/integration';
import type { Finding } from '../../../rules/types';

const MERGE_FUNCTIONS = new Set(['merge', 'mergeDeep', 'defaultsDeep', 'assignIn', 'extend', 'set', 'setWith']);
const URL_HINT = /location|searchParams|URLSearchParams|\.hash|\.search|params/i;

export const DOM008 = defineRule({
  id: 'DOM-008',
  name: 'Prototype Pollution via URL Parameters',
  description: 'Detects recursive merge/assign of URL-derived data into objects, which can pollute Object.prototype.',
  category: 'misconfiguration',
  severity: 'high',
  frameworks: ['*'],
  tags: ['owasp:a8', 'cwe:1321', 'prototype-pollution'],
  detect(ctx) {
    if (!isFrontendFile(ctx.filePath)) return [];
    const findings: Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        let name = '';
        if (ts.isIdentifier(expr)) name = expr.text;
        else if (ts.isPropertyAccessExpression(expr)) name = expr.name.text;
        const isMerge = MERGE_FUNCTIONS.has(name) || (ts.isPropertyAccessExpression(expr) && expr.name.text === 'assign' && expr.expression.getText(ctx.sourceFile) === 'Object');
        if (isMerge) {
          const tainted = node.arguments.find((a) => {
            const t = a.getText(ctx.sourceFile);
            return URL_HINT.test(t) || isExpressionTainted(ctx.taintGraph, t);
          });
          if (tainted) {
            const { line, column } = getLineAndColumn(ctx.sourceFile, node);
            findings.push({
              ruleId: 'DOM-008',
              ruleName: 'Prototype Pollution via URL Parameters',
              category: 'misconfiguration',
              severity: 'high',
              filePath: ctx.filePath,
              line,
              column,
              endLine: line,
              endColumn: column + node.getText(ctx.sourceFile).length,
              message: 'Merging URL-derived data into an object can pollute Object.prototype.',
              codeSnippet: getCodeSnippet(ctx.content, line),
              remediation: 'Reject __proto__/constructor/prototype keys, or use a Map / Object.create(null) as the merge target.',
              references: ['https://owasp.org/www-community/attacks/Prototype_pollution', 'https://cwe.mitre.org/data/definitions/1321.html'],
              confidence: resolveConfidence(ctx.taintGraph, tainted.getText(ctx.sourceFile), 'medium'),
            });
          }
        }
      }
      return 'continue';
    });

    return findings;
  },
});
