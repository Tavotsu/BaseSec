import * as ts from 'typescript';
import { visit } from '../utils/ast-helpers';

export interface NestJSControllerInfo {
  className: string;
  routePrefix: string;
  methods: NestJSRouteInfo[];
  hasGuard: boolean;
}

export interface NestJSRouteInfo {
  method: string;
  path: string;
  hasBody: boolean;
  hasParam: boolean;
  hasQuery: boolean;
  hasGuard: boolean;
  line: number;
}

const HTTP_DECORATORS = ['Get', 'Post', 'Put', 'Delete', 'Patch', 'Head', 'Options', 'All'];
const GUARD_DECORATORS = ['UseGuards'];

export function detectNestJSPatterns(
  sourceFile: ts.SourceFile,
): NestJSControllerInfo[] {
  const controllers: NestJSControllerInfo[] = [];

  visit(sourceFile, (node) => {
    if (ts.isClassDeclaration(node)) {
      const controllerInfo = analyzeController(node, sourceFile);
      if (controllerInfo) {
        controllers.push(controllerInfo);
      }
    }
    return 'continue';
  });

  return controllers;
}

function getDecoratorsSafe(node: ts.Node): ts.Decorator[] {
  if (ts.canHaveDecorators(node)) {
    return [...(ts.getDecorators(node) ?? [])];
  }
  return [];
}

function analyzeController(
  node: ts.ClassDeclaration,
  sourceFile: ts.SourceFile,
): NestJSControllerInfo | null {
  let isController = false;
  let routePrefix = '';
  let classHasGuard = false;

  const decorators = getDecoratorsSafe(node);
  for (const dec of decorators) {
    const text = dec.getText(sourceFile);
    if (/^@Controller\b/.test(text)) {
      isController = true;
      const match = text.match(/@Controller\(['"]([^'"]+)['"]\)/);
      if (match) routePrefix = match[1];
    }
    if (/^@UseGuards\b/.test(text)) {
      classHasGuard = true;
    }
  }

  if (!isController) return null;

  const methods: NestJSRouteInfo[] = [];

  for (const member of node.members) {
    if (ts.isMethodDeclaration(member)) {
      const methodInfo = analyzeRouteMethod(member, sourceFile, classHasGuard);
      if (methodInfo) {
        methods.push(methodInfo);
      }
    }
  }

  const className = node.name?.text ?? 'UnknownController';

  return {
    className,
    routePrefix,
    methods,
    hasGuard: classHasGuard,
  };
}

function analyzeRouteMethod(
  node: ts.MethodDeclaration,
  sourceFile: ts.SourceFile,
  classHasGuard: boolean,
): NestJSRouteInfo | null {
  const decorators = getDecoratorsSafe(node);
  if (decorators.length === 0) return null;

  let httpMethod = '';
  let routePath = '/';
  let hasBody = false;
  let hasParam = false;
  let hasQuery = false;
  let hasGuard = classHasGuard;

  for (const dec of decorators) {
    const text = dec.getText(sourceFile);

    for (const method of HTTP_DECORATORS) {
      if (/^@Get\b|^@Post\b|^@Put\b|^@Delete\b|^@Patch\b|^@Head\b|^@Options\b|^@All\b/.test(text) && text.startsWith(`@${method}`)) {
        httpMethod = method.toUpperCase();
        const match = text.match(new RegExp(`@${method}\\(['"\`]([^'"\`]+)['"\`]\\)`));
        if (match) routePath = match[1];
        break;
      }
    }

    if (text.startsWith('@Body')) hasBody = true;
    if (text.startsWith('@Param')) hasParam = true;
    if (text.startsWith('@Query')) hasQuery = true;

    for (const guardDec of GUARD_DECORATORS) {
      if (text.startsWith(`@${guardDec}`)) {
        hasGuard = true;
      }
    }
  }

  if (!httpMethod) return null;

  const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));

  return {
    method: httpMethod,
    path: routePath,
    hasBody,
    hasParam,
    hasQuery,
    hasGuard,
    line: pos.line + 1,
  };
}