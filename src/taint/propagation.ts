import * as ts from 'typescript';
import type { TaintInfo, TaintSourceInfo } from './types';
import { visit } from '../utils/ast-helpers';
import { TAINT_SOURCES } from '../utils/patterns';

const SANITIZER_NAMES = new Set([
  'escapeHtml', 'encodeURI', 'encodeURIComponent',
  'sanitize', 'DOMPurify.sanitize', 'validator.escape', 'validator.trim',
  'escapeJavaScript',
]);

const SANITIZER_PREFIXES = [
  'escape', 'sanitize', 'encode',
];

export class TaintPropagation {
  private taintMap: Map<string, TaintInfo> = new Map();
  private sourceFile: ts.SourceFile;
  private content: string;
  private customSanitizers: string[];

  constructor(sourceFile: ts.SourceFile, content: string, customSanitizers: string[] = []) {
    this.sourceFile = sourceFile;
    this.content = content;
    this.customSanitizers = customSanitizers;
  }

  analyze(): Map<string, TaintInfo> {
    this.analyzeDeclarations();
    this.analyzeAssignments();
    this.analyzeTemplateLiterals();
    this.analyzeStringConcatenations();
    this.analyzeDestructuring();
    this.analyzeSpread();
    return this.taintMap;
  }

  isTainted(variableName: string): boolean {
    return this.taintMap.has(variableName);
  }

  getTaintInfo(variableName: string): TaintInfo | undefined {
    return this.taintMap.get(variableName);
  }

  getAllTaintedVariables(): Map<string, TaintInfo> {
    return new Map(this.taintMap);
  }

  private analyzeDeclarations(): void {
    visit(this.sourceFile, (node) => {
      if (ts.isVariableDeclaration(node) && node.initializer) {
        const varName = this.getVariableName(node.name);
        if (!varName) return 'continue';

        const initText = node.initializer.getText(this.sourceFile);

        if (this.isTaintExpression(initText)) {
          this.markTainted(varName, this.detectSourceKind(initText), node);
        } else if (this.isSanitizerCall(node.initializer)) {
          // Sanitizer call — check if argument is tainted
          const argText = this.getFirstArgumentText(node.initializer);
          if (argText && this.resolvesToTainted(argText)) {
            this.markSanitized(varName, this.getSanitizerName(node.initializer), node);
          }
        } else if (this.resolvesToTainted(initText)) {
          this.propagateTaint(initText, varName, node);
        }
      }
      return 'continue';
    });
  }

  private analyzeAssignments(): void {
    visit(this.sourceFile, (node) => {
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        if (ts.isIdentifier(node.left)) {
          const varName = node.left.text;
          const rightText = node.right.getText(this.sourceFile);

          if (this.isTaintExpression(rightText)) {
            this.markTainted(varName, this.detectSourceKind(rightText), node);
          } else if (this.resolvesToTainted(rightText)) {
            this.propagateTaint(rightText, varName, node);
          }
        }
      }
      return 'continue';
    });
  }

  private analyzeTemplateLiterals(): void {
    visit(this.sourceFile, (node) => {
      if (ts.isVariableDeclaration(node) && node.initializer) {
        if (ts.isTemplateExpression(node.initializer) || ts.isNoSubstitutionTemplateLiteral(node.initializer)) {
          const varName = this.getVariableName(node.name);
          if (!varName) return 'continue';

          if (this.templateLiteralHasTaint(node.initializer)) {
            const sources = this.getTemplateLiteralSources(node.initializer);
            if (sources.length === 0) return 'continue';
            const pos = this.sourceFile.getLineAndCharacterOfPosition(node.getStart(this.sourceFile));
            this.taintMap.set(varName, {
              sources,
              isSanitized: false,
              sanitizers: [],
            });
          }
        }
      }
      return 'continue';
    });
  }

  private analyzeStringConcatenations(): void {
    visit(this.sourceFile, (node) => {
      if (ts.isVariableDeclaration(node) && node.initializer) {
        if (ts.isBinaryExpression(node.initializer) && node.initializer.operatorToken.kind === ts.SyntaxKind.PlusToken) {
          const varName = this.getVariableName(node.name);
          if (!varName) return 'continue';

          const leftText = node.initializer.left.getText(this.sourceFile);
          const rightText = node.initializer.right.getText(this.sourceFile);

          if (this.isTaintExpression(leftText) || this.isTaintExpression(rightText) ||
              this.resolvesToTainted(leftText) || this.resolvesToTainted(rightText)) {
            const sources: TaintSourceInfo[] = [];
            if (this.isTaintExpression(leftText) || this.resolvesToTainted(leftText)) {
              sources.push(...this.getExpressionSources(leftText));
            }
            if (this.isTaintExpression(rightText) || this.resolvesToTainted(rightText)) {
              sources.push(...this.getExpressionSources(rightText));
            }

            if (sources.length > 0) {
              this.taintMap.set(varName, {
                sources,
                isSanitized: false,
                sanitizers: [],
              });
            }
          }
        }
      }
      return 'continue';
    });
  }

  private analyzeDestructuring(): void {
    visit(this.sourceFile, (node) => {
      if (ts.isVariableDeclaration(node) && ts.isObjectBindingPattern(node.name)) {
        if (!node.initializer) return 'continue';

        const initText = node.initializer.getText(this.sourceFile);
        if (!this.isTaintExpression(initText) && !this.resolvesToTainted(initText)) return 'continue';

        for (const element of node.name.elements) {
          if (ts.isBindingElement(element) && ts.isIdentifier(element.name)) {
            const varName = element.name.text;
            const pos = this.sourceFile.getLineAndCharacterOfPosition(element.getStart(this.sourceFile));
            this.taintMap.set(varName, {
              sources: [{
                kind: this.detectSourceKind(initText),
                expression: initText,
                line: pos.line + 1,
                column: pos.character + 1,
                variableName: varName,
              }],
              isSanitized: false,
              sanitizers: [],
            });
          }
        }
      }
      return 'continue';
    });
  }

  private analyzeSpread(): void {
    visit(this.sourceFile, (node) => {
      if (ts.isVariableDeclaration(node) && node.initializer) {
        if (ts.isObjectLiteralExpression(node.initializer)) {
          for (const prop of node.initializer.properties) {
            if (ts.isSpreadAssignment(prop)) {
              const spreadText = prop.expression.getText(this.sourceFile);
              if (this.isTaintExpression(spreadText) || this.resolvesToTainted(spreadText)) {
                const varName = this.getVariableName(node.name);
                if (varName) {
                  const pos = this.sourceFile.getLineAndCharacterOfPosition(node.getStart(this.sourceFile));
                  this.taintMap.set(varName, {
                    sources: [{
                      kind: this.detectSourceKind(spreadText),
                      expression: spreadText,
                      line: pos.line + 1,
                      column: pos.character + 1,
                    }],
                    isSanitized: false,
                    sanitizers: [],
                  });
                }
              }
            }
          }
        }
      }
      return 'continue';
    });
  }

  private markTainted(varName: string, kind: string, node: ts.Node): void {
    const pos = this.sourceFile.getLineAndCharacterOfPosition(node.getStart(this.sourceFile));
    this.taintMap.set(varName, {
      sources: [{
        kind,
        expression: kind,
        line: pos.line + 1,
        column: pos.character + 1,
        variableName: varName,
      }],
      isSanitized: false,
      sanitizers: [],
    });
  }

  private markSanitized(varName: string, sanitizer: string, node: ts.Node): void {
    const pos = this.sourceFile.getLineAndCharacterOfPosition(node.getStart(this.sourceFile));
    const existing = this.taintMap.get(varName);
    if (existing) {
      existing.isSanitized = true;
      existing.sanitizers.push(sanitizer);
    } else {
      this.taintMap.set(varName, {
        sources: [],
        isSanitized: true,
        sanitizers: [sanitizer],
      });
    }
  }

  private propagateTaint(exprText: string, varName: string, node: ts.Node): void {
    const sources = this.getExpressionSources(exprText);
    if (sources.length > 0) {
      const pos = this.sourceFile.getLineAndCharacterOfPosition(node.getStart(this.sourceFile));
      this.taintMap.set(varName, {
        sources,
        isSanitized: false,
        sanitizers: [],
      });
    }
  }

  private isTaintExpression(text: string): boolean {
    for (const src of TAINT_SOURCES) {
      if (text === src || text.startsWith(src + '.') || text.startsWith(src + '[')) {
        return true;
      }
    }
    if (text.includes('process.argv')) return true;
    return false;
  }

  private detectSourceKind(text: string): string {
    for (const src of TAINT_SOURCES) {
      if (text.startsWith(src)) return src;
    }
    return 'unknown';
  }

  private resolvesToTainted(text: string): boolean {
    for (const [varName, info] of this.taintMap) {
      if (info.isSanitized) continue;
      if (text === varName || text.startsWith(varName + '.') || text.startsWith(varName + '[')) {
        return true;
      }
    }
    return this.isTaintExpression(text);
  }

  private getExpressionSources(text: string): TaintSourceInfo[] {
    const sources: TaintSourceInfo[] = [];

    for (const src of TAINT_SOURCES) {
      if (text === src || text.startsWith(src + '.') || text.startsWith(src + '[')) {
        sources.push({
          kind: src,
          expression: text,
          line: 0,
          column: 0,
        });
      }
    }

    for (const [varName, info] of this.taintMap) {
      if (text === varName || text.startsWith(varName + '.') || text.startsWith(varName + '[')) {
        sources.push(...info.sources);
      }
    }

    return sources;
  }

  private templateLiteralHasTaint(node: ts.TemplateExpression | ts.NoSubstitutionTemplateLiteral): boolean {
    if (ts.isNoSubstitutionTemplateLiteral(node)) return false;

    for (const span of node.templateSpans) {
      const exprText = span.expression.getText(this.sourceFile);
      if (this.isTaintExpression(exprText) || this.resolvesToTainted(exprText)) {
        return true;
      }
    }
    return false;
  }

  private getTemplateLiteralSources(node: ts.TemplateExpression | ts.NoSubstitutionTemplateLiteral): TaintSourceInfo[] {
    const sources: TaintSourceInfo[] = [];
    if (ts.isNoSubstitutionTemplateLiteral(node)) return sources;

    for (const span of node.templateSpans) {
      const exprText = span.expression.getText(this.sourceFile);
      if (this.isTaintExpression(exprText) || this.resolvesToTainted(exprText)) {
        sources.push(...this.getExpressionSources(exprText));
      }
    }
    return sources;
  }

  private isSanitizerCall(expr: ts.Node): boolean {
    if (ts.isCallExpression(expr)) {
      const callee = expr.expression.getText(this.sourceFile);
      if (SANITIZER_NAMES.has(callee)) return true;
      for (const custom of this.customSanitizers) {
        if (callee === custom || callee.endsWith('.' + custom)) return true;
      }
      for (const prefix of SANITIZER_PREFIXES) {
        if (callee.startsWith(prefix)) return true;
      }
    }
    return false;
  }

  private getFirstArgumentText(expr: ts.Expression): string | undefined {
    if (ts.isCallExpression(expr) && expr.arguments.length > 0) {
      return expr.arguments[0].getText(this.sourceFile);
    }
    return undefined;
  }

  private getSanitizerName(expr: ts.Expression): string {
    if (ts.isCallExpression(expr)) {
      return expr.expression.getText(this.sourceFile);
    }
    return 'unknown';
  }

  private getVariableName(name: ts.BindingName): string | undefined {
    if (ts.isIdentifier(name)) return name.text;
    return undefined;
  }
}