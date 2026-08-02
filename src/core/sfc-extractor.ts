import * as ts from 'typescript';

export interface ExtractedScript {
  scriptText: string;
  scriptKind: ts.ScriptKind;
}

// Turns a .vue/.svelte single-file component into a TS-parseable string of the
// SAME length and newline layout as the raw file: every character outside a
// <script> body is blanked to a space (newlines preserved), leaving only the
// script code at its real byte/line offset. AST node positions then match the
// real file lines directly — no lineOffset math anywhere, and getCodeSnippet on
// the raw content still returns the true source line.
//
// ponytail: string extraction, no @vue/compiler-sfc / svelte compiler dep. Covers
// <script>, <script setup>, <script context="module">, lang="ts"/"tsx". Edge it
// won't parse: a "</script>" inside a script string literal (non-greedy cut).
// Upgrade path: swap in the framework compilers if template-AST precision is needed.
const SCRIPT_BLOCK = /<script\b([^>]*)>([\s\S]*?)<\/script\b[^>]*>/gi;
const LANG_TS = /lang\s*=\s*["']ts["']/i;
const LANG_TSX = /lang\s*=\s*["']tsx["']/i;

export function extractSfcScript(content: string): ExtractedScript {
  const chars = new Array<string>(content.length);
  for (let i = 0; i < content.length; i++) {
    chars[i] = content[i] === '\n' ? '\n' : content[i] === '\r' ? '\r' : ' ';
  }

  let hasTs = false;
  let hasTsx = false;
  SCRIPT_BLOCK.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = SCRIPT_BLOCK.exec(content)) !== null) {
    const attrs = m[1];
    if (LANG_TSX.test(attrs)) hasTsx = true;
    else if (LANG_TS.test(attrs)) hasTs = true;

    const bodyStart = m.index + m[0].indexOf('>') + 1;
    const bodyEnd = bodyStart + m[2].length;
    for (let i = bodyStart; i < bodyEnd && i < content.length; i++) {
      chars[i] = content[i];
    }
  }

  const scriptKind = hasTsx ? ts.ScriptKind.TSX : hasTs ? ts.ScriptKind.TS : ts.ScriptKind.JS;
  return { scriptText: chars.join(''), scriptKind };
}
