import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isTaintSource } from '../../../utils/patterns';
import { resolveConfidence, isExpressionTainted } from '../../../taint/integration';

const EXEC_FUNCTIONS = ['exec', 'execSync', 'spawn', 'execFile', 'execFileSync'];

export const CMDI001 = defineRule({
  id: 'CMDI-001',
  name: 'Command Injection via child_process',
  description: 'Detects child_process functions (exec, execSync, spawn) called with user input, enabling command injection.',
  category: 'command-injection',
  severity: 'critical',
  frameworks: ['express', 'nestjs', '*'],
  tags: ['owasp:a1', 'cwe:78', 'command-injection'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        const methodName = ts.isPropertyAccessExpression(expr)
          ? expr.name.text
          : ts.isIdentifier(expr) ? expr.text : '';

        if (!methodName || !EXEC_FUNCTIONS.includes(methodName)) return 'continue';

        const argText = node.arguments.length > 0 ? node.arguments[0].getText(ctx.sourceFile) : node.getText(ctx.sourceFile);
        const text = node.getText(ctx.sourceFile);
        const isTainted = isTaintSource(argText) || isExpressionTainted(ctx.taintGraph, argText);

        if (methodName === 'spawn' || methodName === 'execFile' || methodName === 'execFileSync') {
          if (node.arguments.length > 1 && !isTainted) return 'continue';
        }

        if (isTainted) {
          const { line, column } = getLineAndColumn(ctx.sourceFile, node);
          findings.push({
            ruleId: 'CMDI-001',
            ruleName: 'Command Injection via child_process',
            category: 'command-injection',
            severity: 'critical',
            filePath: ctx.filePath,
            line,
            column,
            endLine: line,
            endColumn: column + text.length,
            message: `Command injection: \`${methodName}()\` called with user input.`,
            codeSnippet: getCodeSnippet(ctx.content, line),
            remediation: 'Use execFile() or spawn() with argument arrays instead of shell commands. Never concatenate user input into shell commands.',
            references: ['https://owasp.org/www-community/attacks/Command_Injection', 'https://cwe.mitre.org/data/definitions/78.html'],
            confidence: resolveConfidence(ctx.taintGraph, argText, 'high'),
          });
        }
      }
      return 'continue';
    });

    return findings;
  },
});