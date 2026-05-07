import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isTaintSource } from '../../../utils/patterns';
import { resolveConfidence, isExpressionTainted } from '../../../taint/integration';

const FS_METHODS = ['readFile', 'readFileSync', 'createReadStream', 'writeFile', 'writeFileSync', 'unlink', 'unlinkSync', 'mkdir', 'mkdirSync', 'readdir', 'readdirSync', 'access', 'accessSync', 'open', 'openSync', 'appendFile', 'appendFileSync'];

export const PATH001 = defineRule({
  id: 'PATH-001',
  name: 'Path Traversal via User Input',
  description: 'Detects filesystem operations with user-controlled paths, enabling path traversal attacks.',
  category: 'path-traversal',
  severity: 'critical',
  frameworks: ['express', 'nestjs', '*'],
  tags: ['owasp:a1', 'cwe:22', 'path-traversal'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr) && FS_METHODS.includes(expr.name.text)) {
          const argText = node.arguments.length > 0 ? node.arguments[0].getText(ctx.sourceFile) : node.getText(ctx.sourceFile);
          if (isTaintSource(argText) || isExpressionTainted(ctx.taintGraph, argText)) {
            const { line, column } = getLineAndColumn(ctx.sourceFile, node);
            const text = node.getText(ctx.sourceFile);
            findings.push({
              ruleId: 'PATH-001',
              ruleName: 'Path Traversal via User Input',
              category: 'path-traversal',
              severity: 'critical',
              filePath: ctx.filePath,
              line,
              column,
              endLine: line,
              endColumn: column + text.length,
              message: `Path traversal: \`${expr.name.text}()\` called with user-controlled path.`,
              codeSnippet: getCodeSnippet(ctx.content, line),
              remediation: 'Use path.basename() to strip directory components. Validate paths with path.resolve() and check they start with an allowed directory.',
              references: ['https://owasp.org/www-community/attacks/Path_Traversal', 'https://cwe.mitre.org/data/definitions/22.html'],
              confidence: resolveConfidence(ctx.taintGraph, argText, 'high'),
            });
          }
        }

        if (ts.isPropertyAccessExpression(expr) && (expr.name.text === 'join' || expr.name.text === 'resolve')) {
          const text = node.getText(ctx.sourceFile);
          for (const arg of node.arguments) {
            const argText = arg.getText(ctx.sourceFile);
            if (isTaintSource(argText) || isExpressionTainted(ctx.taintGraph, argText)) {
              if (text.includes('__dirname')) {
                const { line, column } = getLineAndColumn(ctx.sourceFile, node);
                findings.push({
                  ruleId: 'PATH-001',
                  ruleName: 'Path Traversal via User Input',
                  category: 'path-traversal',
                  severity: 'high',
                  filePath: ctx.filePath,
                  line,
                  column,
                  endLine: line,
                  endColumn: column + text.length,
                  message: `path.${expr.name.text}() with user input may allow path traversal.`,
                  codeSnippet: getCodeSnippet(ctx.content, line),
                  remediation: 'Use path.basename() to strip directory components from user input before joining.',
                  references: ['https://cwe.mitre.org/data/definitions/22.html'],
                  confidence: resolveConfidence(ctx.taintGraph, argText, 'medium'),
                });
              }
              break;
            }
          }
        }
      }
      return 'continue';
    });

    return findings;
  },
});