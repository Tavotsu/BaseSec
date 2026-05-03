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

function analyzeController(
  node: ts.ClassDeclaration,
  sourceFile: ts.SourceFile,
): NestJSControllerInfo | null {
  let isController = false;
  let routePrefix = '';
  let classHasGuard = false;

  const decorators = (node as any).decorators as ts.NodeArray<ts.Decorator> | undefined;
  if (decorators) {
    for (const dec of decorators) {
      const text = dec.getText(sourceFile);
      if (text.includes('@Controller')) {
        isController = true;
        const match = text.match(/@Controller\(['"]([^'"]+)['"]\)/);
        if (match) routePrefix = match[1];
      }
      if (text.includes('@UseGuards')) {
        classHasGuard = true;
      }
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
  const decorators = (node as any).decorators as ts.NodeArray<ts.Decorator> | undefined;
  if (!decorators) return null;

  let httpMethod = '';
  let routePath = '/';
  let hasBody = false;
  let hasParam = false;
  let hasQuery = false;
  let hasGuard = classHasGuard;

  for (const dec of decorators) {
    const text = dec.getText(sourceFile);

    for (const method of HTTP_DECORATORS) {
      if (text.includes(`@${method}`)) {
        httpMethod = method.toUpperCase();
        const match = text.match(new RegExp(`@${method}\\(['"]([^'"]+)['"]\\)`));
        if (match) routePath = match[1];
        break;
      }
    }

    if (text.includes('@Body')) hasBody = true;
    if (text.includes('@Param')) hasParam = true;
    if (text.includes('@Query')) hasQuery = true;

    for (const guardDec of GUARD_DECORATORS) {
      if (text.includes(`@${guardDec}`)) {
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