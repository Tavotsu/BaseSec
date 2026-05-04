import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { findCallExpressions, getLineAndColumn, getCodeSnippet } from '../../../utils/ast-helpers';
import { isTaintSource } from '../../../utils/patterns';

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

    for (const fn of EXEC_FUNCTIONS) {
      const calls = findCallExpressions(ctx.sourceFile, fn);
      for (const call of calls) {
        const text = call.getText(ctx.sourceFile);

        if (fn === 'spawn' || fn === 'execFile' || fn === 'execFileSync') {
          if (call.arguments.length > 1 && !isTaintSource(text)) {
            continue;
          }
        }

        if (isTaintSource(text)) {
          const { line, column } = getLineAndColumn(ctx.sourceFile, call);
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
            message: `Command injection: \`${fn}()\` called with user input.`,
            codeSnippet: getCodeSnippet(ctx.content, line),
            remediation: 'Use execFile() or spawn() with argument arrays instead of shell commands. Never concatenate user input into shell commands.',
            references: ['https://owasp.org/www-community/attacks/Command_Injection', 'https://cwe.mitre.org/data/definitions/78.html'],
            confidence: 'high',
          });
        }
      }
    }

    return findings;
  },
});