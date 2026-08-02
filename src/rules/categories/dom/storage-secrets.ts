import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { redactSecret } from '../../../utils/redact';
import type { Finding } from '../../../rules/types';

const STORAGE_OBJECTS = new Set(['localStorage', 'sessionStorage']);
const SENSITIVE_KEY = /token|jwt|secret|password|passwd|credential|authorization|auth[_-]?token|api[_-]?key|session[_-]?id|refresh[_-]?token/i;

export const DOM006 = defineRule({
  id: 'DOM-006',
  name: 'Sensitive Data in localStorage/sessionStorage',
  description: 'Detects tokens, JWTs, or credentials stored in localStorage/sessionStorage, which are readable by any script (XSS) on the page.',
  category: 'secrets',
  severity: 'medium',
  frameworks: ['*'],
  tags: ['owasp:a2', 'cwe:522', 'insecure-storage'],
  detect(ctx) {
    const findings: Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const expr = node.expression;
        const objText = expr.expression.getText(ctx.sourceFile);
        if (STORAGE_OBJECTS.has(objText) && expr.name.text === 'setItem' && node.arguments.length >= 1) {
          const keyArg = node.arguments[0];
          const key = ts.isStringLiteral(keyArg) ? keyArg.text : keyArg.getText(ctx.sourceFile);
          if (SENSITIVE_KEY.test(key)) {
            const { line, column } = getLineAndColumn(ctx.sourceFile, node);
            let snippet = getCodeSnippet(ctx.content, line);
            const valArg = node.arguments[1];
            if (valArg && ts.isStringLiteral(valArg)) snippet = redactSecret(snippet, valArg.text);
            findings.push({
              ruleId: 'DOM-006',
              ruleName: 'Sensitive Data in localStorage/sessionStorage',
              category: 'secrets',
              severity: 'medium',
              filePath: ctx.filePath,
              line,
              column,
              endLine: line,
              endColumn: column + node.getText(ctx.sourceFile).length,
              message: `Storing "${key}" in ${objText} exposes it to any script via XSS.`,
              codeSnippet: snippet,
              remediation: 'Keep tokens in httpOnly, Secure cookies or in memory; never in Web Storage.',
              references: ['https://owasp.org/www-community/attacks/xss/', 'https://cwe.mitre.org/data/definitions/522.html'],
              confidence: 'medium',
            });
          }
        }
      }
      return 'continue';
    });

    return findings;
  },
});
