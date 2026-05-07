import * as ts from 'typescript';
import { visit } from '../utils/ast-helpers';
import { isTaintSource } from '../utils/patterns';

export interface MongoosePatternInfo {
  hasLeanWithoutSelect: boolean;
  hasDirectQueryPass: boolean;
  hasWhereOperator: boolean;
  schemaNames: string[];
  lineNumbers: number[];
}

const MONGOOSE_QUERY_METHODS = ['find', 'findOne', 'findById', 'findByIdAndUpdate', 'findOneAndUpdate', 'findByIdAndDelete', 'findOneAndDelete', 'findOneAndRemove'];

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

      if (ts.isPropertyAccessExpression(expr)) {
        const methodName = expr.name.text;

        if (methodName === 'lean') {
          const surroundingText = getSurroundingLine(content, sourceFile, node);
          if (!surroundingText.includes('.select(')) {
            info.hasLeanWithoutSelect = true;
            const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
            info.lineNumbers.push(pos.line + 1);
          }
        }

        if (MONGOOSE_QUERY_METHODS.includes(methodName)) {
          if (node.arguments.length > 0) {
            const firstArg = node.arguments[0];
            const argText = firstArg.getText(sourceFile);
            if (isTaintSource(argText) || argText.startsWith('{ ...req.') || argText.startsWith('{...req.')) {
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

function getSurroundingLine(content: string, _sourceFile: ts.SourceFile, node: ts.Node): string {
  const pos = content.substring(0, node.getStart(_sourceFile)).split('\n').length;
  const lines = content.split('\n');
  const start = Math.max(0, pos - 2);
  const end = Math.min(lines.length, pos + 3);
  return lines.slice(start, end).join('\n');
}