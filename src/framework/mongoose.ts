import * as ts from 'typescript';
import { visit } from '../utils/ast-helpers';

export interface MongoosePatternInfo {
  hasLeanWithoutSelect: boolean;
  hasDirectQueryPass: boolean;
  hasWhereOperator: boolean;
  schemaNames: string[];
  lineNumbers: number[];
}

export function detectMongoosePatterns(
  sourceFile: ts.SourceFile,
  content: string,
): MongoosePatternInfo {
  const info: MongoosePatternInfo = {
    hasLeanWithoutSelect: false,
    hasDirectQueryPass: false,
    hasWhereOperator: false,
    schemaNames: [],
    lineNumbers: [],
  };

  visit(sourceFile, (node) => {
    if (ts.isCallExpression(node)) {
      const expr = node.expression;
      const text = node.getText(sourceFile);

      if (ts.isPropertyAccessExpression(expr)) {
        const methodName = expr.name.text;

        if (methodName === 'lean') {
          const fullText = content.substring(
            node.parent ? node.parent.getStart(sourceFile) : node.getStart(sourceFile),
            node.parent ? node.parent.getEnd() : node.getEnd(),
          );
          const surroundingText = getSurroundingLine(content, sourceFile, node);
          if (!surroundingText.includes('.select(')) {
            info.hasLeanWithoutSelect = true;
            const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
            info.lineNumbers.push(pos.line + 1);
          }
        }

        if (methodName === 'find' || methodName === 'findOne' || methodName === 'findById') {
          if (node.arguments.length > 0) {
            const firstArg = node.arguments[0];
            if (isReqProperty(firstArg, sourceFile)) {
              info.hasDirectQueryPass = true;
              const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
              info.lineNumbers.push(pos.line + 1);
            }
          }
        }

        if (methodName === '$where' || methodName === 'where') {
          if (node.arguments.length > 0) {
            const firstArgText = node.arguments[0].getText(sourceFile);
            if (firstArgText.includes('req.') || firstArgText.includes('process.')) {
              info.hasWhereOperator = true;
              const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
              info.lineNumbers.push(pos.line + 1);
            }
          }
        }
      }
    }

    if (ts.isNewExpression(node)) {
      if (ts.isIdentifier(node.expression) && node.expression.text === 'Schema') {
        info.schemaNames.push('Schema');
      }
    }

    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
      if (node.expression.text === 'model' && node.arguments.length > 0) {
        const firstArg = node.arguments[0];
        if (ts.isStringLiteral(firstArg)) {
          info.schemaNames.push(firstArg.text);
        }
      }
    }

    return 'continue';
  });

  return info;
}

function isReqProperty(node: ts.Node, sourceFile: ts.SourceFile): boolean {
  const text = node.getText(sourceFile);
  return text.startsWith('req.');
}

function getSurroundingLine(content: string, _sourceFile: ts.SourceFile, node: ts.Node): string {
  const pos = content.substring(0, node.getStart(_sourceFile)).split('\n').length;
  const lines = content.split('\n');
  const start = Math.max(0, pos - 2);
  const end = Math.min(lines.length, pos + 3);
  return lines.slice(start, end).join('\n');
}