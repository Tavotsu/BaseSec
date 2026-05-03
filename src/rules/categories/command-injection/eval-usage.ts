import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { findCallExpressions, getLineAndColumn, getCodeSnippet } from '../../../utils/ast-helpers';
import { isTaintSource } from '../../../utils/patterns';

export const CMDI002 = defineRule({
  id: 'CMDI-002',
  name: 'Use of eval()',
  description: 'Detects use of eval() or new Function() which can execute arbitrary code, especially with user input.',
  category: 'command-injection',
  severity: 'critical',
  frameworks: ['express', 'nestjs', '*'],
  tags: ['owasp:a1', 'cwe:94', 'command-injection'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    const evalCalls = findCallExpressions(ctx.sourceFile, 'eval');
    for (const call of evalCalls) {
      const text = call.getText(ctx.sourceFile);
      const { line, column } = getLineAndColumn(ctx.sourceFile, call);
      const confidence: import('../../../rules/types').Confidence = isTaintSource(text) ? 'high' : 'low';
      findings.push({
        ruleId: 'CMDI-002',
        ruleName: 'Use of eval()',
        category: 'command-injection',
        severity: 'critical',
        filePath: ctx.filePath,
        line,
        column,
        endLine: line,
        endColumn: column + text.length,
        message: confidence === 'high'
          ? `eval() called with user input, enabling arbitrary code execution.`
          : `eval() usage detected. eval() is a security risk and should be avoided.`,
        codeSnippet: getCodeSnippet(ctx.content, line),
        remediation: 'Never use eval() with user input. Refactor to use safer alternatives.',
        references: ['https://owasp.org/www-community/attacks/Code_Injection', 'https://cwe.mitre.org/data/definitions/94.html'],
        confidence,
      });
    }

    visit(ctx.sourceFile, (node) => {
      if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'Function') {
        const text = node.getText(ctx.sourceFile);
        const { line, column } = getLineAndColumn(ctx.sourceFile, node);
        const confidence: import('../../../rules/types').Confidence = isTaintSource(text) ? 'high' : 'low';
        findings.push({
          ruleId: 'CMDI-002',
          ruleName: 'Use of new Function()',
          category: 'command-injection',
          severity: 'critical',
          filePath: ctx.filePath,
          line,
          column,
          endLine: line,
          endColumn: column + text.length,
          message: confidence === 'high'
            ? `new Function() with user input enables arbitrary code execution.`
            : `new Function() usage detected. This is equivalent to eval() and should be avoided.`,
          codeSnippet: getCodeSnippet(ctx.content, line),
          remediation: 'Never use new Function() with user input. Refactor to use safer alternatives.',
          references: ['https://cwe.mitre.org/data/definitions/94.html'],
          confidence,
        });
      }
      return 'continue';
    });

    return findings;
  },
});

import { visit } from '../../../utils/ast-helpers';