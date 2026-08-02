import { describe, it, expect } from 'vitest';
import * as ts from 'typescript';
import { extractSfcScript } from '../../src/core/sfc-extractor';
import { Parser } from '../../src/core/parser';

describe('extractSfcScript', () => {
  it('keeps the script body, blanks the template, preserves line layout', () => {
    const vue = [
      '<template>',            // 1
      '  <div v-html="x" />',  // 2
      '</template>',           // 3
      '<script lang="ts">',    // 4
      'const secret = "a";',   // 5
      '</script>',             // 6
    ].join('\n');
    const { scriptText, scriptKind } = extractSfcScript(vue);
    expect(scriptKind).toBe(ts.ScriptKind.TS);
    expect(scriptText.split('\n').length).toBe(vue.split('\n').length);
    expect(scriptText).toContain('const secret');
    expect(scriptText).not.toContain('v-html');
    expect(scriptText.split('\n')[4]).toContain('const secret');
  });

  it('handles a template-only SFC (no script)', () => {
    const { scriptText } = extractSfcScript('<div>{@html y}</div>');
    expect(scriptText.trim()).toBe('');
  });

  it('keeps both <script> and <script setup> blocks', () => {
    const vue = '<script>const a = 1;</script>\n<script setup>const b = 2;</script>';
    const { scriptText } = extractSfcScript(vue);
    expect(scriptText).toContain('const a = 1;');
    expect(scriptText).toContain('const b = 2;');
  });
});

describe('Parser SFC integration', () => {
  it('parses a .vue <script> at real file line numbers', () => {
    const vue = '<template>\n  <p>{{ x }}</p>\n</template>\n<script>\nel.innerHTML = userInput;\n</script>';
    const res = new Parser().parseContent('comp.vue', vue);
    expect('sourceFile' in res).toBe(true);
    if (!('sourceFile' in res)) return;
    let line = -1;
    const walk = (n: ts.Node) => {
      if (ts.isBinaryExpression(n) && ts.isPropertyAccessExpression(n.left) && n.left.name.text === 'innerHTML') {
        line = res.sourceFile.getLineAndCharacterOfPosition(n.getStart(res.sourceFile)).line + 1;
      }
      ts.forEachChild(n, walk);
    };
    walk(res.sourceFile);
    expect(line).toBe(5);
  });

  it('keeps raw content on the ParsedFile for template scanning', () => {
    const svelte = '<script>let x;</script>\n<div>{@html x}</div>';
    const res = new Parser().parseContent('page.svelte', svelte);
    expect('content' in res && (res as { content: string }).content).toBe(svelte);
  });
});
