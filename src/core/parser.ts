import * as ts from 'typescript';
import * as fs from 'node:fs';
import type { ParsedFile, ParseError } from '../rules/types';
import { extractSfcScript } from './sfc-extractor';

export class Parser {
  parseContent(filePath: string, content: string): ParsedFile | ParseError {
    try {
      const dotIdx = filePath.lastIndexOf('.');
      if (dotIdx === -1) {
        return {
          filePath,
          error: `File has no extension: ${filePath}`,
        };
      }
      const ext = filePath.substring(dotIdx);

      // SFCs: parse the extracted <script> as TS; keep `content` raw so template
      // rules and getCodeSnippet see the whole file at real line numbers.
      let scriptText = content;
      let scriptKind: ts.ScriptKind;
      if (ext === '.vue' || ext === '.svelte') {
        const extracted = extractSfcScript(content);
        scriptText = extracted.scriptText;
        scriptKind = extracted.scriptKind;
      } else {
        scriptKind = this.getScriptKind(ext);
      }

      const sourceFile = ts.createSourceFile(
        filePath,
        scriptText,
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
    } catch (error) {
      return {
        filePath,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  parseFile(filePath: string): ParsedFile | ParseError {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      return this.parseContent(filePath, content);
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
        return ts.ScriptKind.TS;
      case '.tsx':
        return ts.ScriptKind.TSX;
      case '.js':
        return ts.ScriptKind.JS;
      case '.jsx':
        return ts.ScriptKind.JSX;
      case '.mjs':
        return ts.ScriptKind.JS;
      case '.cjs':
        return ts.ScriptKind.JS;
      case '.mts':
      case '.cts':
        return ts.ScriptKind.TS;
      default:
        return ts.ScriptKind.Unknown;
    }
  }
}