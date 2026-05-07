import * as ts from 'typescript';
import { visit } from '../utils/ast-helpers';

export interface TypeORMPatternInfo {
  hasRawQueryWithoutParams: boolean;
  hasQueryBuilder: boolean;
  hasRepositoryFind: boolean;
  lineNumbers: number[];
}

const QUERY_RECEIVERS = ['manager', 'connection', 'queryrunner', 'db', 'getConnection'];
const RAW_RECEIVERS = ['manager', 'connection', 'knex', 'db'];
const REPO_RECEIVERS = ['repository', 'Repository', 'repo', 'Repo'];

export function detectTypeORMPatterns(
  sourceFile: ts.SourceFile,
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
          const isQueryReceiver = QUERY_RECEIVERS.some((r) => objText.toLowerCase().includes(r.toLowerCase()));
          if (isQueryReceiver || node.arguments.length === 1) {
            if (node.arguments.length >= 1) {
              const argText = node.arguments[0].getText(sourceFile);
              const firstArg = node.arguments[0];
              const isDynamic = ts.isTemplateExpression(firstArg) || ts.isBinaryExpression(firstArg)
                || (ts.isIdentifier(firstArg) && isDynamicString(argText));
              if (isDynamic) {
                info.hasRawQueryWithoutParams = true;
                const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
                info.lineNumbers.push(pos.line + 1);
              }
            }
          }
        }

        if (methodName === 'raw') {
          const isRawReceiver = RAW_RECEIVERS.some((r) => objText.toLowerCase().includes(r.toLowerCase()));
          if (isRawReceiver || objText.toLowerCase().includes('typeorm')) {
            if (node.arguments.length >= 1) {
              const argText = node.arguments[0].getText(sourceFile);
              const firstArg = node.arguments[0];
              const isDynamic = ts.isTemplateExpression(firstArg) || ts.isBinaryExpression(firstArg)
                || (ts.isIdentifier(firstArg) && isDynamicString(argText));
              if (isDynamic) {
                info.hasRawQueryWithoutParams = true;
                const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
                info.lineNumbers.push(pos.line + 1);
              }
            }
          }
        }

        if (methodName === 'createQueryBuilder') {
          info.hasQueryBuilder = true;
        }

        if (methodName === 'find' || methodName === 'findOne') {
          if (REPO_RECEIVERS.some((r) => objText.includes(r))) {
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
  return text.includes('req.') || text.includes('params.') || text.includes('query.')
    || text.includes('body.') || text.includes('process.argv')
    || text.includes('${') || text.includes(' + ');
}