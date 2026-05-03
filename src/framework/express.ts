import * as ts from 'typescript';
import type { DetectedFramework } from './detector';
import { visit } from '../utils/ast-helpers';

export interface ExpressRouteInfo {
  method: string;
  path: string;
  hasAuth: boolean;
  line: number;
}

export interface ExpressAppInfo {
  hasHelmet: boolean;
  hasCORS: boolean;
  hasErrorHandler: boolean;
  routes: ExpressRouteInfo[];
}

const HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options'];
const AUTH_MIDDLEWARE_NAMES = [
  'auth', 'authenticate', 'isAuth', 'isAuthenticated', 'requireAuth',
  'jwt', 'passport', 'verifyToken', 'checkAuth', 'ensureAuth',
  'authMiddleware', 'protect', 'guard', 'requireLogin',
];

export function detectExpressPatterns(
  sourceFile: ts.SourceFile,
  content: string,
): ExpressAppInfo {
  const info: ExpressAppInfo = {
    hasHelmet: false,
    hasCORS: false,
    hasErrorHandler: false,
    routes: [],
  };

  info.hasHelmet = content.includes('helmet(') || content.includes("require('helmet')") || content.includes('require("helmet")');
  info.hasCORS = content.includes('cors(') || content.includes("require('cors')") || content.includes('require("cors")');

  visit(sourceFile, (node) => {
    if (ts.isCallExpression(node)) {
      detectRoutes(node, sourceFile, info);
      detectErrorHandler(node, sourceFile, info);
    }
    return 'continue';
  });

  return info;
}

function detectRoutes(
  node: ts.CallExpression,
  sourceFile: ts.SourceFile,
  info: ExpressAppInfo,
): void {
  const expr = node.expression;
  if (!ts.isPropertyAccessExpression(expr)) return;

  const method = expr.name.text;
  if (!HTTP_METHODS.includes(method)) return;

  const objText = expr.expression.getText(sourceFile);
  if (!['app', 'router'].includes(objText) && !objText.endsWith('Router')) return;

  const routePath = getRoutePath(node, sourceFile);
  const hasAuth = hasAuthMiddleware(node, sourceFile);

  const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  info.routes.push({
    method: method.toUpperCase(),
    path: routePath ?? '/',
    hasAuth,
    line: pos.line + 1,
  });
}

function detectErrorHandler(
  node: ts.CallExpression,
  sourceFile: ts.SourceFile,
  info: ExpressAppInfo,
): void {
  const expr = node.expression;
  if (!ts.isPropertyAccessExpression(expr)) return;
  if (expr.name.text !== 'use') return;

  const args = node.arguments;
  if (args.length < 1) return;

  for (const arg of args) {
    if (ts.isArrowFunction(arg) || ts.isFunctionExpression(arg)) {
      const params = arg.parameters;
      if (params.length === 4) {
        info.hasErrorHandler = true;
      }
    }
  }
}

function getRoutePath(
  node: ts.CallExpression,
  sourceFile: ts.SourceFile,
): string | undefined {
  if (node.arguments.length === 0) return undefined;
  const firstArg = node.arguments[0];
  if (ts.isStringLiteral(firstArg)) return firstArg.text;
  return undefined;
}

function hasAuthMiddleware(
  node: ts.CallExpression,
  sourceFile: ts.SourceFile,
): boolean {
  const args = node.arguments;
  for (const arg of args) {
    if (ts.isIdentifier(arg)) {
      const name = arg.text;
      if (AUTH_MIDDLEWARE_NAMES.some((m) => name.toLowerCase().includes(m.toLowerCase()))) {
        return true;
      }
    }
    if (ts.isCallExpression(arg)) {
      const callee = arg.expression.getText(sourceFile);
      if (AUTH_MIDDLEWARE_NAMES.some((m) => callee.toLowerCase().includes(m.toLowerCase()))) {
        return true;
      }
    }
  }
  return false;
}