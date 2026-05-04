import * as ts from 'typescript';
import { visit } from '../utils/ast-helpers';

export interface TypeORMPatternInfo {
  hasRawQueryWithoutParams: boolean;
  hasQueryBuilder: boolean;
  hasRepositoryFind: boolean;
  lineNumbers: number[];
}

export function detectTypeORMPatterns(
  sourceFile: ts.SourceFile,
  content: string,
): TypeORMPatternInfo {
  const info: TypeORMPatternInfo = {
    hasRawQueryWithoutParams: false,
    hasQueryBuilder: false,
    hasRepositoryFind: false,
    lineNumbers: [],
  };

  visit(sourceFile, (node) => {
    if (ts.isCallExpression(node)) {
      const expr = node.expression;
      const text = node.getText(sourceFile);

      if (ts.isPropertyAccessExpression(expr)) {
        const methodName = expr.name.text;
        const objText = expr.expression.getText(sourceFile);

        if (methodName === 'query') {
          if (node.arguments.length === 1) {
            const argText = node.arguments[0].getText(sourceFile);
            if (isDynamicString(argText)) {
              info.hasRawQueryWithoutParams = true;
              const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
              info.lineNumbers.push(pos.line + 1);
            }
          }
        }

        if (methodName === 'raw') {
          if (node.arguments.length >= 1) {
            const argText = node.arguments[0].getText(sourceFile);
            if (isDynamicString(argText)) {
              info.hasRawQueryWithoutParams = true;
              const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
              info.lineNumbers.push(pos.line + 1);
            }
          }
        }

        if (methodName === 'createQueryBuilder') {
          info.hasQueryBuilder = true;
        }

        if (methodName === 'find' || methodName === 'findOne') {
          if (objText.includes('repository') || objText.includes('Repository') || objText.includes('repo')) {
            info.hasRepositoryFind = true;
          }
        }
      }
    }

    return 'continue';
  });

  return info;
}

function isDynamicString(text: string): boolean {
  return text.includes('req.') || text.includes('${') || text.includes(' + ') || text.includes('process.');
}