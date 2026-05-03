import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';

const BODY_PARSER_CALLS = ['json', 'urlencoded'];

export const CONF004 = defineRule({
  id: 'CONF-004',
  name: 'Unlimited Body Parser',
  description: 'Detects express.json() or express.urlencoded() without a size limit, enabling DoS attacks.',
  category: 'misconfiguration',
  severity: 'medium',
  frameworks: ['express'],
  tags: ['owasp:a5', 'cwe:770', 'misconfiguration'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];
    const seenLines = new Set<number>();

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr) && BODY_PARSER_CALLS.includes(expr.name.text)) {
          const objText = expr.expression.getText(ctx.sourceFile);
          if (objText === 'express' || objText === 'app' || objText.includes('express')) {
            const text = node.getText(ctx.sourceFile);
            const hasLimit = text.includes('limit:');
            if (!hasLimit) {
              const { line, column } = getLineAndColumn(ctx.sourceFile, node);
              if (seenLines.has(line)) return 'continue';
              seenLines.add(line);
              findings.push({
                ruleId: 'CONF-004',
                ruleName: 'Unlimited Body Parser',
                category: 'misconfiguration',
                severity: 'medium',
                filePath: ctx.filePath,
                line,
                column,
                endLine: line,
                endColumn: column + text.length,
                message: `Body parser without size limit. Large payloads can cause DoS.`,
                codeSnippet: getCodeSnippet(ctx.content, line),
                remediation: 'Set a size limit: express.json({ limit: "1mb" })',
                references: ['https://owasp.org/www-community/attacks/Denial_of_service'],
                confidence: 'medium',
              });
            }
          }
        }
      }
      return 'continue';
    });

    return findings;
  },
});