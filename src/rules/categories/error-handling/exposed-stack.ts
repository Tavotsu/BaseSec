import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';

export const ERR001 = defineRule({
  id: 'ERR-001',
  name: 'Exposed Stack Trace',
  description: 'Detects error handlers that send stack traces or error messages to clients.',
  category: 'error-handling',
  severity: 'medium',
  frameworks: ['express', 'nestjs', '*'],
  tags: ['owasp:a5', 'cwe:209', 'error-handling'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const text = node.getText(ctx.sourceFile);
        const callee = node.expression;
        let isResponseSend = false;
        if (ts.isPropertyAccessExpression(callee)) {
          const methodName = callee.name.text;
          isResponseSend = ['send', 'json', 'end', 'write'].includes(methodName);
        }
        if (isResponseSend) {
          const argsText = node.arguments.map(arg => arg.getText(ctx.sourceFile)).join(' ');
          if (argsText.includes('.stack') || argsText.includes('.message')) {
            const { line, column } = getLineAndColumn(ctx.sourceFile, node);
            findings.push({
              ruleId: 'ERR-001',
              ruleName: 'Exposed Stack Trace',
              category: 'error-handling',
              severity: 'medium',
              filePath: ctx.filePath,
              line,
              column,
              endLine: line,
              endColumn: column + text.length,
              message: `Error details sent to client, potentially exposing stack traces.`,
              codeSnippet: getCodeSnippet(ctx.content, line),
              remediation: 'Never send error details to clients. Log them server-side and return generic error messages.',
              references: ['https://cwe.mitre.org/data/definitions/209.html'],
              confidence: 'high',
            });
          }
        }
      }
      return 'continue';
    });

    return findings;
  },
});