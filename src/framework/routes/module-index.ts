import * as ts from 'typescript';
import * as path from 'node:path';
import type { ParsedFile } from '../../rules/types';
import type { ImportGraph } from '../../core/import-graph';

/** Un nombre importado: default, '*' (namespace) o el nombre exportado. */
export interface ImportBinding {
  spec: string;
  imported: string;
}

/** Declaración de nivel superior: función, valor (const/let/var) o clase. */
export type TopDecl =
  | { kind: 'function'; node: ts.Node }
  | { kind: 'value'; init: ts.Expression | undefined }
  | { kind: 'class'; node: ts.ClassDeclaration };

/**
 * Una entrada de exportación. `local` apunta a un nombre de nivel superior (o de import);
 * `value` es una expresión/declaración exportada directamente; `reexport` viene de
 * `export { x as y } from '…'`. `starSpecs` se guarda aparte (`export * from`).
 */
export interface ExportEntry {
  name: string;
  local?: string;
  value?: ts.Node;
  reexport?: { spec: string; imported: string };
  /** `module.exports = …`: las propiedades de un objeto literal valen también como exports con nombre. */
  cjs?: boolean;
}

export interface ModuleFile {
  /** Ruta absoluta normalizada. */
  path: string;
  sf: ts.SourceFile;
  imports: Map<string, ImportBinding>;
  topDecls: Map<string, TopDecl>;
  exports: ExportEntry[];
  starSpecs: string[];
}

/** Resultado de seguir una exportación hasta su origen. */
export interface ResolvedExport {
  file: ModuleFile;
  local?: string;
  value?: ts.Node;
  namespace: boolean;
}

const MAX_EXPORT_DEPTH = 6;

export function isRequireCall(node: ts.Node): node is ts.CallExpression {
  return (
    ts.isCallExpression(node) &&
    ts.isIdentifier(node.expression) &&
    node.expression.text === 'require' &&
    node.arguments.length === 1 &&
    ts.isStringLiteralLike(node.arguments[0])
  );
}

export function requireSpecifier(node: ts.CallExpression): string {
  return (node.arguments[0] as ts.StringLiteralLike).text;
}

function hasModifier(node: ts.Node, kind: ts.SyntaxKind): boolean {
  if (!ts.canHaveModifiers(node)) return false;
  return (ts.getModifiers(node) ?? []).some((m) => m.kind === kind);
}

function isFunctionLike(node: ts.Node | undefined): node is ts.ArrowFunction | ts.FunctionExpression {
  return node !== undefined && (ts.isArrowFunction(node) || ts.isFunctionExpression(node));
}

/** Índice sintáctico de los ficheros parseados: imports, declaraciones y exports. */
export class ModuleIndex {
  private readonly files = new Map<string, ModuleFile>();

  constructor(parsedFiles: ParsedFile[], private readonly graph: ImportGraph) {
    for (const parsed of parsedFiles) {
      const abs = path.resolve(parsed.filePath);
      this.files.set(abs, indexFile(abs, parsed.sourceFile));
    }
  }

  file(absPath: string): ModuleFile | undefined {
    return this.files.get(path.resolve(absPath));
  }

  allFiles(): ModuleFile[] {
    return [...this.files.values()].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  }

  /** Fichero indexado al que apunta un especificador relativo desde `from`, o undefined. */
  target(from: ModuleFile, spec: string): ModuleFile | undefined {
    const resolved = this.graph.resolve(from.path, spec);
    return resolved === undefined ? undefined : this.files.get(resolved);
  }

  /**
   * Sigue la exportación `name` de `file` hasta su origen. Un nombre importado se sigue
   * a su fichero de origen; un namespace se devuelve con `namespace: true`.
   */
  resolveExport(file: ModuleFile, name: string, depth = 0): ResolvedExport | undefined {
    if (depth > MAX_EXPORT_DEPTH) return undefined;

    for (const entry of file.exports) {
      if (entry.name !== name) continue;
      if (entry.value !== undefined) {
        return { file, value: entry.value, namespace: false };
      }
      if (entry.reexport !== undefined) {
        const target = this.target(file, entry.reexport.spec);
        if (target === undefined) return undefined;
        return this.resolveExport(target, entry.reexport.imported, depth + 1);
      }
      if (entry.local !== undefined) {
        return this.resolveLocal(file, entry.local, depth + 1);
      }
    }

    // module.exports = { getUser, other: fn } -> const { getUser } = require('./x')
    for (const entry of file.exports) {
      if (entry.cjs && entry.value !== undefined && ts.isObjectLiteralExpression(entry.value)) {
        const found = this.resolveObjectProperty(file, entry.value, name, depth + 1);
        if (found !== undefined) return found;
      }
    }

    for (const spec of file.starSpecs) {
      const target = this.target(file, spec);
      if (target === undefined) continue;
      const found = this.resolveExport(target, name, depth + 1);
      if (found !== undefined) return found;
    }
    return undefined;
  }

  private resolveObjectProperty(
    file: ModuleFile,
    obj: ts.ObjectLiteralExpression,
    name: string,
    depth: number,
  ): ResolvedExport | undefined {
    for (const prop of obj.properties) {
      if (ts.isShorthandPropertyAssignment(prop) && prop.name.text === name) {
        return this.resolveLocal(file, name, depth);
      }
      if (ts.isPropertyAssignment(prop) && propertyKey(prop.name) === name) {
        const init = prop.initializer;
        if (ts.isIdentifier(init)) return this.resolveLocal(file, init.text, depth);
        return { file, value: init, namespace: false };
      }
      if (ts.isMethodDeclaration(prop) && propertyKey(prop.name) === name) {
        return { file, value: prop, namespace: false };
      }
    }
    return undefined;
  }

  /** Resuelve un nombre local: si es import relativo lo sigue; si no, devuelve el propio nombre. */
  resolveLocal(file: ModuleFile, local: string, depth = 0): ResolvedExport | undefined {
    if (depth > MAX_EXPORT_DEPTH) return undefined;
    const binding = file.imports.get(local);
    if (binding !== undefined) {
      const target = this.target(file, binding.spec);
      if (target === undefined) return undefined;
      if (binding.imported === '*') {
        return { file: target, namespace: true };
      }
      return this.resolveExport(target, binding.imported, depth + 1);
    }
    return { file, local, namespace: false };
  }
}

function propertyKey(name: ts.PropertyName): string | undefined {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNoSubstitutionTemplateLiteral(name)) {
    return name.text;
  }
  return undefined;
}

function indexFile(abs: string, sf: ts.SourceFile): ModuleFile {
  const file: ModuleFile = {
    path: abs,
    sf,
    imports: new Map(),
    topDecls: new Map(),
    exports: [],
    starSpecs: [],
  };

  for (const stmt of sf.statements) {
    if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier)) {
      collectImport(file, stmt);
    } else if (
      ts.isImportEqualsDeclaration(stmt) &&
      ts.isExternalModuleReference(stmt.moduleReference) &&
      ts.isStringLiteral(stmt.moduleReference.expression)
    ) {
      // import express = require('express')
      file.imports.set(stmt.name.text, { spec: stmt.moduleReference.expression.text, imported: 'default' });
    } else if (ts.isVariableStatement(stmt)) {
      collectVariableStatement(file, stmt);
    } else if (ts.isFunctionDeclaration(stmt) && stmt.name) {
      file.topDecls.set(stmt.name.text, { kind: 'function', node: stmt });
    } else if (ts.isClassDeclaration(stmt) && stmt.name) {
      file.topDecls.set(stmt.name.text, { kind: 'class', node: stmt });
    } else if (ts.isExportAssignment(stmt)) {
      collectExpressionExport(file, 'default', stmt.expression);
    } else if (ts.isExportDeclaration(stmt)) {
      collectExportDeclaration(file, stmt);
    } else if (ts.isExpressionStatement(stmt)) {
      collectCommonJsExport(file, stmt.expression);
    }
  }

  for (const stmt of sf.statements) {
    if (ts.isVariableStatement(stmt) && hasModifier(stmt, ts.SyntaxKind.ExportKeyword)) {
      for (const decl of stmt.declarationList.declarations) {
        if (ts.isIdentifier(decl.name)) {
          file.exports.push({ name: decl.name.text, local: decl.name.text });
        }
      }
    }
    if (
      (ts.isFunctionDeclaration(stmt) || ts.isClassDeclaration(stmt)) &&
      hasModifier(stmt, ts.SyntaxKind.ExportKeyword)
    ) {
      const isDefault = hasModifier(stmt, ts.SyntaxKind.DefaultKeyword);
      if (stmt.name) {
        file.exports.push(
          isDefault
            ? { name: 'default', local: stmt.name.text }
            : { name: stmt.name.text, local: stmt.name.text },
        );
      } else if (isDefault) {
        file.exports.push({ name: 'default', value: stmt });
      }
    }
  }

  return file;
}

function collectImport(file: ModuleFile, stmt: ts.ImportDeclaration): void {
  const spec = (stmt.moduleSpecifier as ts.StringLiteral).text;
  const clause = stmt.importClause;
  if (!clause) return;
  if (clause.name) {
    file.imports.set(clause.name.text, { spec, imported: 'default' });
  }
  const named = clause.namedBindings;
  if (named && ts.isNamespaceImport(named)) {
    file.imports.set(named.name.text, { spec, imported: '*' });
  } else if (named && ts.isNamedImports(named)) {
    for (const element of named.elements) {
      const imported = (element.propertyName ?? element.name).text;
      file.imports.set(element.name.text, { spec, imported });
    }
  }
}

function collectVariableStatement(file: ModuleFile, stmt: ts.VariableStatement): void {
  for (const decl of stmt.declarationList.declarations) {
    const init = decl.initializer;

    if (ts.isIdentifier(decl.name)) {
      file.topDecls.set(decl.name.text, { kind: 'value', init });
    }

    if (init === undefined) continue;

    // const x = require('./y')  /  const x = require('./y').name
    if (isRequireCall(init) && ts.isIdentifier(decl.name)) {
      file.imports.set(decl.name.text, { spec: requireSpecifier(init), imported: 'default' });
    } else if (isRequireCall(init) && ts.isObjectBindingPattern(decl.name)) {
      bindRequireDestructuring(file, decl.name, requireSpecifier(init));
    } else if (
      ts.isPropertyAccessExpression(init) &&
      isRequireCall(init.expression) &&
      ts.isIdentifier(decl.name)
    ) {
      file.imports.set(decl.name.text, {
        spec: requireSpecifier(init.expression),
        imported: init.name.text,
      });
    }
  }
}

function bindRequireDestructuring(
  file: ModuleFile,
  pattern: ts.ObjectBindingPattern,
  spec: string,
): void {
  for (const element of pattern.elements) {
    if (element.dotDotDotToken || !ts.isIdentifier(element.name)) continue;
    const imported = element.propertyName && ts.isIdentifier(element.propertyName)
      ? element.propertyName.text
      : element.propertyName && ts.isStringLiteral(element.propertyName)
        ? element.propertyName.text
        : element.name.text;
    file.imports.set(element.name.text, { spec, imported });
  }
}

function collectExpressionExport(file: ModuleFile, name: string, expr: ts.Expression): void {
  if (ts.isIdentifier(expr)) {
    file.exports.push({ name, local: expr.text });
  } else {
    file.exports.push({ name, value: expr });
  }
}

function collectExportDeclaration(file: ModuleFile, stmt: ts.ExportDeclaration): void {
  const spec = stmt.moduleSpecifier && ts.isStringLiteral(stmt.moduleSpecifier)
    ? stmt.moduleSpecifier.text
    : undefined;

  if (!stmt.exportClause) {
    if (spec !== undefined) file.starSpecs.push(spec);
    return;
  }
  if (!ts.isNamedExports(stmt.exportClause)) return;

  for (const element of stmt.exportClause.elements) {
    const exported = element.name.text;
    const imported = (element.propertyName ?? element.name).text;
    if (spec !== undefined) {
      file.exports.push({ name: exported, reexport: { spec, imported } });
    } else {
      file.exports.push({ name: exported, local: imported });
    }
  }
}

/** module.exports = x, module.exports.name = x, exports.name = x. */
function collectCommonJsExport(file: ModuleFile, expr: ts.Expression): void {
  if (!ts.isBinaryExpression(expr) || expr.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return;
  const left = expr.left;

  if (isModuleExports(left)) {
    collectExpressionExport(file, 'default', expr.right);
    const last = file.exports[file.exports.length - 1];
    if (last !== undefined && last.name === 'default') last.cjs = true;
    return;
  }
  if (
    ts.isPropertyAccessExpression(left) &&
    (isModuleExports(left.expression) || (ts.isIdentifier(left.expression) && left.expression.text === 'exports'))
  ) {
    collectExpressionExport(file, left.name.text, expr.right);
  }
}

function isModuleExports(node: ts.Expression): boolean {
  return (
    ts.isPropertyAccessExpression(node) &&
    ts.isIdentifier(node.expression) &&
    node.expression.text === 'module' &&
    node.name.text === 'exports'
  );
}

/** Función asociada a un nombre de nivel superior: declaración o const con arrow/function. */
export function localFunctionNode(file: ModuleFile, name: string): ts.Node | undefined {
  const decl = file.topDecls.get(name);
  if (!decl) return undefined;
  if (decl.kind === 'function') return decl.node;
  if (decl.kind === 'value' && isFunctionLike(decl.init)) return decl.init;
  return undefined;
}
