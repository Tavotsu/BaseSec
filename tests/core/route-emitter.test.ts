import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Pipeline } from '../../src/core/pipeline';
import { Parser } from '../../src/core/parser';
import {
  buildRouteArtifact,
  defaultArtifactPath,
  findProjectRoot,
  writeRouteArtifact,
} from '../../src/core/route-emitter';
import type { RouteArtifact } from '../../src/framework/routes/types';
import type { ScanResult } from '../../src/rules/types';

const FIXTURE = fileURLToPath(new URL('../fixtures/express-src', import.meta.url));

let scan: ScanResult;
let artifact: RouteArtifact;

/** Orden por unidades de código, igual que el emisor (no localeCompare). */
function byCodeUnits(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function collectParsed() {
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

beforeAll(async () => {
  scan = await new Pipeline(undefined, { noCache: true }).run(FIXTURE, { noDeps: true, emitRoutes: true });
  artifact = scan.routes!;
});

function withoutTimestamp(a: RouteArtifact): Omit<RouteArtifact, 'generatedAt'> {
  const { generatedAt: _ignored, ...rest } = a;
  return rest;
}

describe('buildRouteArtifact (express-src fixture with real findings)', () => {
  it('correlates a SQLI finding in the sink file with via: import-graph', () => {
    const route = artifact.routes.find((r) => r.method === 'GET' && r.path === '/api/users/:id')!;
    expect(route.staticFindings).toContainEqual({
      ruleId: 'SQLI-001',
      filePath: 'db/users.ts',
      line: 5,
      via: 'import-graph',
    });
  });

  it('marks a finding inside the handler range with via: handler', () => {
    const route = artifact.routes.find((r) => r.method === 'POST' && r.path === '/api/users')!;
    expect(route.line).toBe(10);
    expect(route.endLine).toBe(14);
    expect(route.staticFindings).toContainEqual({
      ruleId: 'SQLI-001',
      filePath: 'routes/users.ts',
      line: 12,
      via: 'handler',
    });
  });

  it('lists reachable files relative to the root, sorted, including the handler file', () => {
    const route = artifact.routes.find((r) => r.method === 'GET' && r.path === '/api/users/:id')!;
    expect(route.reachableFiles).toEqual([
      'controllers/users.ts',
      'db/pool.ts',
      'db/users.ts',
      'services/users.ts',
    ]);
  });

  it('uses root-relative paths with / separators everywhere', () => {
    for (const route of artifact.routes) {
      expect(path.isAbsolute(route.filePath)).toBe(false);
      expect(route.filePath).not.toContain('\\');
      for (const f of route.reachableFiles) expect(path.isAbsolute(f)).toBe(false);
    }
  });

  it('sorts routes by (path, method, filePath, line) and unresolved entries by location', () => {
    const sorted = [...artifact.routes].sort((a, b) =>
      byCodeUnits(a.path, b.path) ||
      byCodeUnits(a.method, b.method) ||
      byCodeUnits(a.filePath, b.filePath) ||
      a.line - b.line,
    );
    expect(artifact.routes).toEqual(sorted);
    expect(artifact.unresolved.map((u) => u.filePath)).toEqual(['routes/dyn.ts', 'routes/orphan.ts']);
  });

  it('is deterministic: the same input gives the same artifact except generatedAt', () => {
    const again = buildRouteArtifact({
      parsedFiles: collectParsed(),
      frameworks: artifact.frameworks,
      root: FIXTURE,
      findings: scan.findings,
    });
    expect(withoutTimestamp(again)).toEqual(withoutTimestamp(artifact));
  });

  it('records the target as the absolute root and version 1', () => {
    expect(artifact.version).toBe(1);
    expect(artifact.target).toBe(FIXTURE);
    expect(artifact.frameworks).toEqual(['express']);
  });
});

describe('defaultArtifactPath', () => {
  it('is stable per root and lives under ~/.basesec/routes', () => {
    const first = defaultArtifactPath(FIXTURE);
    expect(defaultArtifactPath(FIXTURE)).toBe(first);
    expect(path.basename(path.dirname(first))).toBe('routes');
    expect(path.basename(first)).toMatch(/^[0-9a-f]{12}\.json$/);
    expect(defaultArtifactPath(path.join(FIXTURE, 'routes'))).not.toBe(first);
  });
});

describe('findProjectRoot', () => {
  it('walks up to the nearest package.json', () => {
    expect(findProjectRoot(path.join(FIXTURE, 'routes', 'users.ts'))).toBe(FIXTURE);
    expect(findProjectRoot(path.join(FIXTURE, 'routes'))).toBe(FIXTURE);
    expect(findProjectRoot(FIXTURE)).toBe(FIXTURE);
  });
});

describe('writeRouteArtifact', () => {
  let tmp: string;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-routes-'));
  });

  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it('writes valid JSON with mode 0600 and leaves no temporary files', () => {
    const file = path.join(tmp, 'out', 'routes.json');
    const written = writeRouteArtifact(artifact, file);

    expect(written).toBe(file);
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
    const parsed = JSON.parse(fs.readFileSync(file, 'utf-8'));
    expect(parsed.version).toBe(1);
    expect(parsed.routes.length).toBe(artifact.routes.length);
    expect(fs.readdirSync(path.dirname(file))).toEqual(['routes.json']);
  });

  it('warns once on stderr when the file is written inside the project root', () => {
    const root = path.join(tmp, 'project');
    fs.mkdirSync(root);
    const inside: RouteArtifact = { ...artifact, target: root };
    const spy = vi.spyOn(console, 'error').mockImplementation(() => undefined);

    writeRouteArtifact(inside, path.join(root, 'routes.json'));

    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(
      'Note: the route artifact describes your whole API surface; add it to .gitignore.',
    );
  });

  it('does not warn when the file is outside the project root', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    writeRouteArtifact(artifact, path.join(tmp, 'routes.json'));
    expect(spy).not.toHaveBeenCalled();
  });
});
