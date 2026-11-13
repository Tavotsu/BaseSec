import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { Parser } from '../../src/core/parser';
import { buildImportGraph } from '../../src/core/import-graph';
import type { ParsedFile } from '../../src/rules/types';

const ROOT = path.resolve('/virtual/graph');
const abs = (rel: string): string => path.join(ROOT, rel);

function parse(files: Record<string, string>): ParsedFile[] {
  const parser = new Parser();
  return Object.entries(files).map(([rel, code]) => {
    const result = parser.parseContent(abs(rel), code);
    if (!('sourceFile' in result)) throw new Error(result.error);
    return result;
  });
}

describe('import graph (review)', () => {
  it('follows import x = require("./y")', () => {
    const graph = buildImportGraph(parse({ 'a.ts': `import y = require('./y');`, 'y.ts': 'export const y = 1;' }));
    expect(graph.importsOf(abs('a.ts'))).toEqual([abs('y.ts')]);
  });

  it('reachableFrom caps at exactly maxDepth hops (a chain of 8 files)', () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 8; i++) files[`f${i}.ts`] = i < 7 ? `import './f${i + 1}';` : 'export {};';
    const graph = buildImportGraph(parse(files));
    expect(graph.reachableFrom(abs('f0.ts'), 0)).toEqual([abs('f0.ts')]);
    expect(graph.reachableFrom(abs('f0.ts'), 2).map((f) => path.basename(f))).toEqual(['f0.ts', 'f1.ts', 'f2.ts']);
    expect(graph.reachableFrom(abs('f0.ts')).map((f) => path.basename(f))).toEqual(
      ['f0.ts', 'f1.ts', 'f2.ts', 'f3.ts', 'f4.ts', 'f5.ts', 'f6.ts'],
    );
  });

  it('uses the shortest path for the depth cap when a file is reachable by two routes', () => {
    const graph = buildImportGraph(
      parse({
        'a.ts': `import './b'; import './d';`,
        'b.ts': `import './c';`,
        'c.ts': `import './d';`,
        'd.ts': `import './e';`,
        'e.ts': 'export {};',
      }),
    );
    // d está a 1 salto (directo) y a 3 (vía b, c): e debe alcanzarse con maxDepth 2.
    expect(graph.reachableFrom(abs('a.ts'), 2).map((f) => path.basename(f))).toContain('e.ts');
  });

  it('returns only the file itself when it is not part of the graph', () => {
    const graph = buildImportGraph(parse({ 'a.ts': 'export {};' }));
    expect(graph.reachableFrom(abs('nope.ts'))).toEqual([abs('nope.ts')]);
    expect(graph.importsOf(abs('nope.ts'))).toEqual([]);
  });
});
