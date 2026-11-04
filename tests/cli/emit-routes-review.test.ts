import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../src/cli/commands/scan';
import { validateRouteOptions } from '../../src/cli/validation';
import { Pipeline } from '../../src/core/pipeline';
import * as emitter from '../../src/core/route-emitter';
import type { CliOptions } from '../../src/rules/types';

const FIXTURE = fileURLToPath(new URL('../fixtures/express-src', import.meta.url));

function baseOptions(overrides: Partial<CliOptions> = {}): CliOptions {
  return {
    format: 'json',
    severity: 'low',
    ignore: [],
    noTaint: false,
    quiet: true,
    strict: false,
    framework: 'auto',
    noColor: true,
    noBanner: true,
    noCache: true,
    noDeps: true,
    ...overrides,
  };
}

describe('pipeline without --emit-routes', () => {
  it('builds nothing: result.routes is undefined and the route emitter is never called', async () => {
    const spy = vi.spyOn(emitter, 'buildRouteArtifact');
    try {
      const result = await new Pipeline(undefined, { noCache: true }).run(FIXTURE, { noDeps: true });
      expect(result.routes).toBeUndefined();
      expect('routes' in result).toBe(false);
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  it('gives the same findings with and without emitRoutes', async () => {
    const plain = await new Pipeline(undefined, { noCache: true }).run(FIXTURE, { noDeps: true });
    const spy = vi.spyOn(emitter, 'buildRouteArtifact');
    const withRoutes = await new Pipeline(undefined, { noCache: true }).run(FIXTURE, { noDeps: true, emitRoutes: true });
    expect(spy).toHaveBeenCalledTimes(1);
    spy.mockRestore();
    expect(withRoutes.routes).toBeDefined();
    expect(withRoutes.findings).toEqual(plain.findings);
  });
});

describe('runScan --emit-routes', () => {
  let tmp: string;
  let cwd: string;
  let logSpy: ReturnType<typeof vi.spyOn>;
  let errSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    cwd = process.cwd();
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-emit-review-'));
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    errSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
  });

  afterEach(() => {
    process.chdir(cwd);
    vi.restoreAllMocks();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it('exits 2 for --routes-out without --emit-routes, and writes nothing', async () => {
    const out = path.join(tmp, 'r.json');
    const code = await runScan(FIXTURE, baseOptions({ routesOut: out }));
    expect(code).toBe(2);
    expect(fs.existsSync(out)).toBe(false);
  });

  it('exits 2 for --emit-routes with --ai before running any analysis', async () => {
    const spy = vi.spyOn(Pipeline.prototype, 'run');
    const code = await runScan(FIXTURE, baseOptions({ emitRoutes: true, ai: true }));
    expect(code).toBe(2);
    expect(spy).not.toHaveBeenCalled();
  });

  it('resolves a relative --routes-out against the cwd', async () => {
    process.chdir(tmp);
    const code = await runScan(FIXTURE, baseOptions({ emitRoutes: true, routesOut: 'rel/out.json' }));
    expect(code).toBe(0);
    const expected = fs.realpathSync(path.join(tmp, 'rel', 'out.json'));
    expect(fs.existsSync(expected)).toBe(true);
    expect(logSpy.mock.calls.map((c) => String(c[0])).join('\n')).toContain('Artifact: ');
  });

  it('warns on stderr when the artifact lands inside the project root, and prints the summary on stdout', async () => {
    const project = path.join(tmp, 'proj');
    fs.mkdirSync(project);
    fs.writeFileSync(path.join(project, 'package.json'), '{"dependencies":{"express":"4"}}');
    fs.writeFileSync(
      path.join(project, 'app.js'),
      "const express = require('express');\nconst app = express();\napp.get('/ping', (req, res) => res.end());\n",
    );
    const out = path.join(project, 'routes.json');
    const code = await runScan(project, baseOptions({ emitRoutes: true, routesOut: out }));
    expect(code).toBe(0);
    expect(errSpy.mock.calls.map((c) => String(c[0])).join('\n')).toContain('add it to .gitignore');
    const stdout = logSpy.mock.calls.map((c) => String(c[0])).join('\n');
    expect(stdout).toMatch(/Routes: 1 \(1 express, 0 nestjs\) · unresolved: 0/);
    expect(JSON.parse(fs.readFileSync(out, 'utf-8')).routes[0].path).toBe('/ping');
  });
});

describe('validateRouteOptions edge cases', () => {
  it('treats an empty --routes-out as present (still requires --emit-routes)', () => {
    expect(validateRouteOptions({ emitRoutes: false, routesOut: '', ai: false })).toMatch(/requires --emit-routes/);
  });
});
