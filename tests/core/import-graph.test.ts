import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { Parser } from '../../src/core/parser';
import { buildImportGraph } from '../../src/core/import-graph';
import type { ParsedFile } from '../../src/rules/types';

const ROOT = path.resolve('/virtual/project/src');
const abs = (rel: string): string => path.join(ROOT, rel);

function parsedFiles(files: Record<string, string>): ParsedFile[] {
  const parser = new Parser();
  return Object.entries(files).map(([rel, code]) => {
    const result = parser.parseContent(abs(rel), code);
    if (!('sourceFile' in result)) throw new Error(result.error);
    return result;
  });
}

describe('buildImportGraph', () => {
  it('reaches the sink through route -> service -> db and not the decoy', () => {
    const graph = buildImportGraph(parsedFiles({
      'routes/users.ts': "import { userService } from '../services/user';",
      'services/user.ts': "import { db } from '../db/users';",
      'db/users.ts': 'export const db = {};',
      'db/other.ts': 'export const other = {};',
    }));

    const reachable = graph.reachableFrom(abs('routes/users.ts'));
    expect(reachable).toContain(abs('services/user.ts'));
    expect(reachable).toContain(abs('db/users.ts'));
    expect(reachable).not.toContain(abs('db/other.ts'));
  });

  it('resolves a folder import to its index file and follows export *', () => {
    const graph = buildImportGraph(parsedFiles({
      'routes/barrel.ts': "import { userService } from '../services';",
      'services/index.ts': "export * from './user';",
      'services/user.ts': "import { db } from '../db/users';",
      'db/users.ts': 'export const db = {};',
    }));

    expect(graph.resolve(abs('routes/barrel.ts'), '../services')).toBe(abs('services/index.ts'));
    const reachable = graph.reachableFrom(abs('routes/barrel.ts'));
    expect(reachable).toContain(abs('services/user.ts'));
    expect(reachable).toContain(abs('db/users.ts'));
  });

  it('maps a .js specifier to the .ts file it names', () => {
    const graph = buildImportGraph(parsedFiles({
      'routes/jsext.ts': "import { userService } from '../services/user.js';",
      'services/user.ts': "import { db } from '../db/users';",
      'db/users.ts': 'export const db = {};',
    }));

    expect(graph.importsOf(abs('routes/jsext.ts'))).toEqual([abs('services/user.ts')]);
    expect(graph.reachableFrom(abs('routes/jsext.ts'))).toContain(abs('db/users.ts'));
  });

  it('terminates on cycles and visits each file once', () => {
    const graph = buildImportGraph(parsedFiles({
      'routes/cycle.ts': "import { a } from '../services/cycle-a';",
      'services/cycle-a.ts': "import { db } from '../db/users';\nimport { b } from './cycle-b';",
      'services/cycle-b.ts': "import { a } from './cycle-a';",
      'db/users.ts': 'export const db = {};',
    }));

    const reachable = graph.reachableFrom(abs('routes/cycle.ts'));
    expect(reachable).toContain(abs('services/cycle-a.ts'));
    expect(reachable).toContain(abs('services/cycle-b.ts'));
    expect(reachable).toContain(abs('db/users.ts'));
    expect(new Set(reachable).size).toBe(reachable.length);
  });

  it('caps the traversal depth (default 6, configurable)', () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 9; i++) {
      files[`n${i}.ts`] = i < 8 ? `import './n${i + 1}';` : 'export {};';
    }
    const graph = buildImportGraph(parsedFiles(files));

    const capped = graph.reachableFrom(abs('n0.ts'));
    expect(capped).toContain(abs('n6.ts'));
    expect(capped).not.toContain(abs('n7.ts'));

    const deeper = graph.reachableFrom(abs('n0.ts'), 8);
    expect(deeper).toContain(abs('n8.ts'));
  });

  it('collects require() and import() with literal relative specifiers', () => {
    const graph = buildImportGraph(parsedFiles({
      'app.js': "const r = require('./routes/a');\nconst lazy = import('./routes/b');",
      'routes/a.js': 'module.exports = {};',
      'routes/b.ts': 'export {};',
    }));

    expect(graph.importsOf(abs('app.js'))).toEqual([abs('routes/a.js'), abs('routes/b.ts')]);
  });

  it('ignores bare specifiers and non-literal requires', () => {
    const graph = buildImportGraph(parsedFiles({
      'routes/users.ts': "import express from 'express';\nimport { pg } from 'pg';\nconst x = require(dynamicName);",
    }));

    expect(graph.importsOf(abs('routes/users.ts'))).toEqual([]);
    expect(graph.resolve(abs('routes/users.ts'), 'express')).toBeUndefined();
  });

  it('returns undefined for a relative specifier with no matching file', () => {
    const graph = buildImportGraph(parsedFiles({
      'routes/users.ts': "import { x } from './missing';",
    }));

    expect(graph.importsOf(abs('routes/users.ts'))).toEqual([]);
    expect(graph.resolve(abs('routes/users.ts'), './missing')).toBeUndefined();
  });
});
