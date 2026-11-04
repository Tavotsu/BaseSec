import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { Parser } from '../../src/core/parser';
import { buildImportGraph } from '../../src/core/import-graph';
import {
  buildRouteArtifact,
  defaultArtifactPath,
  writeRouteArtifact,
} from '../../src/core/route-emitter';
import type { Finding, ParsedFile } from '../../src/rules/types';
import type { RouteArtifact } from '../../src/framework/routes/types';

const ROOT = path.resolve('/virtual/perf');

function parse(files: Record<string, string>): ParsedFile[] {
  const parser = new Parser();
  return Object.entries(files).map(([rel, code]) => {
    const result = parser.parseContent(path.join(ROOT, rel), code);
    if (!('sourceFile' in result)) throw new Error(result.error);
    return result;
  });
}

function finding(rel: string, line: number, ruleId = 'SQLI-001', category: Finding['category'] = 'injection'): Finding {
  return {
    ruleId,
    severity: 'high',
    category,
    message: 'm',
    filePath: path.join(ROOT, rel),
    line,
    column: 1,
  } as Finding;
}

describe('buildRouteArtifact performance (in-memory synthetic project)', () => {
  it('handles ~2000 files and ~500 routes in under 3 s', () => {
    const files: Record<string, string> = {};
    const SERVICES = 1500;
    for (let i = 0; i < SERVICES; i++) {
      // cadena lineal con ramas: cada servicio importa los dos siguientes
      const imports = [i + 1, i + 2]
        .filter((n) => n < SERVICES)
        .map((n) => `import { s${n} } from './s${n}';`)
        .join('\n');
      files[`services/s${i}.ts`] = `${imports}\nexport const s${i} = () => ${i};\n`;
    }
    const CONTROLLERS = 500;
    let routerImports = '';
    let routerUses = '';
    for (let i = 0; i < CONTROLLERS; i++) {
      files[`controllers/c${i}.ts`] =
        `import { s${i % SERVICES} } from '../services/s${i % SERVICES}';\n` +
        `export function h${i}(req, res) {\n  const { q } = req.query;\n  res.json(s${i % SERVICES}());\n}\n`;
      files[`routes/r${i}.ts`] =
        `import express from 'express';\nimport { h${i} } from '../controllers/c${i}';\n` +
        `const r = express.Router();\nr.get('/item/:id', h${i});\nr.post('/', h${i});\nexport default r;\n`;
      routerImports += `import r${i} from './routes/r${i}';\n`;
      routerUses += `app.use('/api/v${i}', r${i});\n`;
    }
    files['app.ts'] = `import express from 'express';\n${routerImports}const app = express();\n${routerUses}`;
    expect(Object.keys(files).length).toBeGreaterThanOrEqual(2000);

    const parsed = parse(files);
    const findings: Finding[] = [];
    for (let i = 0; i < SERVICES; i += 3) findings.push(finding(`services/s${i}.ts`, 2));

    const start = Date.now();
    const artifact = buildRouteArtifact({ parsedFiles: parsed, frameworks: ['express'], root: ROOT, findings });
    const elapsed = Date.now() - start;

    expect(artifact.routes).toHaveLength(CONTROLLERS * 2);
    expect(artifact.routes[0].staticFindings.length).toBeGreaterThan(0);
    expect(elapsed).toBeLessThan(3000);
  });

  it('resolves imports only against the parsed files (the graph module never imports fs)', () => {
    const source = fs.readFileSync(path.resolve(__dirname, '../../src/core/import-graph.ts'), 'utf-8');
    expect(source).not.toMatch(/from 'node:fs'|from 'fs'|require\('fs'\)/);
    const graph = buildImportGraph(parse({ 'a.ts': `import './b';`, 'b.ts': 'export {};' }));
    expect(graph.reachableFrom(path.join(ROOT, 'a.ts'))).toEqual([path.join(ROOT, 'a.ts'), path.join(ROOT, 'b.ts')]);
  });
});

describe('buildRouteArtifact correlation', () => {
  const files = {
    'app.ts': `
      import express from 'express';
      import { h } from './h';
      const app = express();
      app.get('/a', h);
    `,
    'h.ts': `
      import { dep } from './dep';
      export function h(req, res) {
        dep();
      }
    `,
    'dep.ts': 'export const dep = () => 1;\n',
    'other.ts': 'export const other = 1;\n',
  };

  it('dedupes findings, excludes dependency-check and empty paths, and separates handler / import-graph', () => {
    const parsed = parse(files);
    const findings: Finding[] = [
      finding('h.ts', 4),
      finding('h.ts', 4),
      finding('h.ts', 3, 'X-1'),
      finding('dep.ts', 1),
      finding('other.ts', 1),
      finding('h.ts', 4, 'DEP-1', 'dependency-check'),
      { ...finding('h.ts', 4, 'EMPTY-1'), filePath: '' },
    ];
    const artifact = buildRouteArtifact({ parsedFiles: parsed, frameworks: ['express'], root: ROOT, findings });
    const route = artifact.routes[0];
    expect(route.staticFindings).toEqual([
      { ruleId: 'SQLI-001', filePath: 'dep.ts', line: 1, via: 'import-graph' },
      { ruleId: 'X-1', filePath: 'h.ts', line: 3, via: 'handler' },
      { ruleId: 'SQLI-001', filePath: 'h.ts', line: 4, via: 'handler' },
    ]);
    expect(route.reachableFiles).toEqual(['dep.ts', 'h.ts']);
  });

  it('is deterministic regardless of the order of files and findings', () => {
    const findingsA = [finding('dep.ts', 1), finding('h.ts', 4), finding('h.ts', 3, 'X-1')];
    const entries = Object.entries(files);
    const a = buildRouteArtifact({
      parsedFiles: parse(Object.fromEntries(entries)),
      frameworks: ['express', 'fastify'],
      root: ROOT,
      findings: findingsA,
    });
    const b = buildRouteArtifact({
      parsedFiles: parse(Object.fromEntries([...entries].reverse())),
      frameworks: ['fastify', 'express'],
      root: ROOT,
      findings: [...findingsA].reverse(),
    });
    const strip = (x: RouteArtifact) => ({ ...x, generatedAt: '' });
    expect(JSON.stringify(strip(a))).toBe(JSON.stringify(strip(b)));
  });

  it('does not crash on projects without routes', () => {
    const parsed = parse({ 'x.ts': 'export const x = 1;' });
    const artifact = buildRouteArtifact({
      parsedFiles: parsed,
      frameworks: ['express', 'nestjs'],
      root: ROOT,
      findings: [],
    });
    expect(artifact.routes).toEqual([]);
    expect(artifact.unresolved).toEqual([]);
  });
});

describe('writeRouteArtifact hardening', () => {
  let tmp: string;
  let oldHome: string | undefined;
  const artifactFor = (target: string): RouteArtifact => ({
    version: 1,
    generatedAt: '2026-01-01T00:00:00.000Z',
    target,
    frameworks: [],
    routes: [],
    unresolved: [],
  });

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-write-'));
    oldHome = process.env.HOME;
    process.env.HOME = path.join(tmp, 'home');
    fs.mkdirSync(process.env.HOME, { recursive: true });
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
  });

  afterEach(() => {
    if (oldHome === undefined) delete process.env.HOME;
    else process.env.HOME = oldHome;
    vi.restoreAllMocks();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it('replaces a symlink planted at the destination instead of writing through it', () => {
    const victim = path.join(tmp, 'victim.txt');
    fs.writeFileSync(victim, 'ORIGINAL');
    const dest = path.join(tmp, 'out', 'routes.json');
    fs.mkdirSync(path.dirname(dest));
    fs.symlinkSync(victim, dest);

    writeRouteArtifact(artifactFor(path.join(tmp, 'proj')), dest);

    expect(fs.readFileSync(victim, 'utf-8')).toBe('ORIGINAL');
    expect(fs.lstatSync(dest).isSymbolicLink()).toBe(false);
    expect(JSON.parse(fs.readFileSync(dest, 'utf-8')).version).toBe(1);
    expect(fs.statSync(dest).mode & 0o777).toBe(0o600);
  });

  it('does not follow a symlink planted at a guessable temporary name', () => {
    const victim = path.join(tmp, 'victim.txt');
    fs.writeFileSync(victim, 'ORIGINAL');
    const dir = path.join(tmp, 'out');
    fs.mkdirSync(dir);
    // El nombre temporal es aleatorio: plantar los nombres antiguos (pid / timestamp) no sirve.
    fs.symlinkSync(victim, path.join(dir, `.routes.json.${process.pid}.${Date.now()}.tmp`));

    writeRouteArtifact(artifactFor(tmp), path.join(dir, 'routes.json'));
    expect(fs.readFileSync(victim, 'utf-8')).toBe('ORIGINAL');
  });

  it('cleans up the temporary file when the rename fails (destination is a directory)', () => {
    const dir = path.join(tmp, 'out');
    fs.mkdirSync(path.join(dir, 'routes.json'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'routes.json', 'keep'), 'x');
    expect(() => writeRouteArtifact(artifactFor(tmp), path.join(dir, 'routes.json'))).toThrow();
    expect(fs.readdirSync(dir)).toEqual(['routes.json']);
  });

  it('forces the default directory to 0700 even if it existed with looser permissions', () => {
    const project = path.join(tmp, 'proj');
    const routesDir = path.join(process.env.HOME as string, '.basesec', 'routes');
    fs.mkdirSync(routesDir, { recursive: true, mode: 0o755 });
    fs.chmodSync(routesDir, 0o755);

    const written = writeRouteArtifact(artifactFor(project));

    expect(written).toBe(defaultArtifactPath(project));
    expect(path.dirname(written)).toBe(routesDir);
    expect(fs.statSync(routesDir).mode & 0o777).toBe(0o700);
    expect(fs.statSync(written).mode & 0o777).toBe(0o600);
  });

  it('refuses a default directory that is a symlink', () => {
    const base = path.join(process.env.HOME as string, '.basesec');
    fs.mkdirSync(base, { recursive: true });
    const elsewhere = path.join(tmp, 'elsewhere');
    fs.mkdirSync(elsewhere);
    fs.symlinkSync(elsewhere, path.join(base, 'routes'));
    expect(() => writeRouteArtifact(artifactFor(path.join(tmp, 'proj')))).toThrow();
    expect(fs.readdirSync(elsewhere)).toEqual([]);
  });

  it('does not chmod the parent of an explicit --routes-out path', () => {
    const dir = path.join(tmp, 'shared');
    fs.mkdirSync(dir, { mode: 0o755 });
    fs.chmodSync(dir, 0o755);
    writeRouteArtifact(artifactFor(tmp), path.join(dir, 'r.json'));
    expect(fs.statSync(dir).mode & 0o777).toBe(0o755);
  });

  it('warns for files inside the root, also for a directory whose name starts with ".."', () => {
    const project = path.join(tmp, 'proj');
    fs.mkdirSync(path.join(project, '..cache'), { recursive: true });
    const errSpy = vi.spyOn(console, 'error');
    writeRouteArtifact(artifactFor(project), path.join(project, '..cache', 'r.json'));
    expect(errSpy).toHaveBeenCalledTimes(1);
  });
});
