import * as ts from 'typescript';
import * as fs from 'node:fs';
import type { ParsedFile, ParseError } from '../rules/types';

export class Parser {
  parseFile(filePath: string): ParsedFile | ParseError {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const ext = filePath.substring(filePath.lastIndexOf('.'));
      const scriptKind = this.getScriptKind(ext);

      const sourceFile = ts.createSourceFile(
        filePath,
        content,
        ts.ScriptTarget.Latest,
        true,
        scriptKind,
      );

      return {
        filePath,
        sourceFile,
        content,
        size: content.length,
      };
    } catch (e) {
      return {
        filePath,
        error: e instanceof Error ? e.message : String(e),
      };
    }
  }

  parseFiles(filePaths: string[]): ParsedFile[] {
    const results: ParsedFile[] = [];
    for (const filePath of filePaths) {
      const result = this.parseFile(filePath);
      if ('sourceFile' in result) {
        results.push(result);
      }
    }
    return results;
  }

  private getScriptKind(ext: string): ts.ScriptKind {
    switch (ext) {
      case '.ts':
      case '.tsx':
        return ts.ScriptKind.TS;
      case '.js':
        return ts.ScriptKind.JS;
      case '.jsx':
        return ts.ScriptKind.JSX;
      case '.mjs':
      case '.mts':
        return ts.ScriptKind.TS;
      case '.cjs':
      case '.cts':
        return ts.ScriptKind.TS;
      default:
        return ts.ScriptKind.Unknown;
    }
  }
}