import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Pipeline } from '../../src/core/pipeline';
import { Parser } from '../../src/core/parser';
import { buildRouteArtifact } from '../../src/core/route-emitter';
import type { RouteArtifact } from '../../src/framework/routes/types';
import type { ParsedFile, ScanResult } from '../../src/rules/types';

const FIXTURE = fileURLToPath(new URL('../fixtures/next-src', import.meta.url));

function collectParsed(): ParsedFile[] {
  const files: string[] = [];
  const walk = (dir: string): void => {
    for (const name of fs.readdirSync(dir)) {
      const full = path.join(dir, name);
      if (fs.statSync(full).isDirectory()) walk(full);
      else if (/\.(ts|js)$/.test(name)) files.push(full);
    }
  };
  walk(FIXTURE);
  return new Parser().parseFiles(files);
}

let scan: ScanResult;
let artifact: RouteArtifact;

beforeAll(async () => {
  scan = await new Pipeline(undefined, { noCache: true }).run(FIXTURE, { noDeps: true });
  artifact = buildRouteArtifact({
    parsedFiles: collectParsed(),
    frameworks: ['nextjs', 'react'],
    root: FIXTURE,
    findings: scan.findings,
  });
});

describe('buildRouteArtifact (next-src fixture with real findings)', () => {
  it('records nextjs as the framework of the artifact and only nextjs routes', () => {
    expect(artifact.frameworks).toContain('nextjs');
    expect(artifact.routes.length).toBeGreaterThan(0);
    expect(artifact.routes.every((r) => r.framework === 'nextjs')).toBe(true);
  });

  it('correlates the SQL template finding of the GET handler with via: handler', () => {
    const route = artifact.routes.find((r) => r.method === 'GET' && r.path === '/web/api/users')!;
    expect(route).toBeDefined();

    const sqlLine = fs
      .readFileSync(path.join(FIXTURE, 'app/api/users/route.ts'), 'utf-8')
      .split('\n')
      .findIndex((l) => l.includes('db.query')) + 1;

    expect(route.staticFindings).toContainEqual({
      ruleId: 'SQLI-002',
      filePath: 'app/api/users/route.ts',
      line: sqlLine,
      via: 'handler',
    });
  });

  it('marks the same finding as import-graph, not handler, for the POST handler of that file', () => {
    const post = artifact.routes.find((r) => r.method === 'POST' && r.path === '/web/api/users')!;
    const sqlLine = fs
      .readFileSync(path.join(FIXTURE, 'app/api/users/route.ts'), 'utf-8')
      .split('\n')
      .findIndex((l) => l.includes('db.query')) + 1;
    expect(post.staticFindings).toContainEqual({
      ruleId: 'SQLI-002',
      filePath: 'app/api/users/route.ts',
      line: sqlLine,
      via: 'import-graph',
    });
  });
});
