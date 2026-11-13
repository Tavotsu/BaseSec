import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../src/cli/commands/scan';
import { validateRouteOptions } from '../../src/cli/validation';
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

describe('scan --emit-routes', () => {
  let tmp: string;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-emit-'));
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it('writes the artifact to --routes-out, prints the summary and exits 0', async () => {
    const out = path.join(tmp, 'routes.json');
    const code = await runScan(FIXTURE, baseOptions({ emitRoutes: true, routesOut: out }));

    expect(code).toBe(0);
    const artifact = JSON.parse(fs.readFileSync(out, 'utf-8'));
    expect(artifact.version).toBe(1);
    expect(artifact.routes.some((r: { path: string; method: string }) => r.method === 'GET' && r.path === '/api/users/:id')).toBe(true);

    const printed = logSpy.mock.calls.map((c) => String(c[0])).join('\n');
    // Fase 2b añade el recuento de nextjs al resumen (siempre listado con los tres frameworks).
    expect(printed).toMatch(/Routes: \d+ \(\d+ express, \d+ nestjs, \d+ nextjs\) · unresolved: \d+/);
    expect(printed).toContain(`Artifact: ${out}`);
  });

  it('does not print the findings report when emitting routes', async () => {
    const out = path.join(tmp, 'routes.json');
    await runScan(FIXTURE, baseOptions({ emitRoutes: true, routesOut: out }));
    const printed = logSpy.mock.calls.map((c) => String(c[0])).join('\n');
    expect(printed).not.toContain('"findings"');
  });
});

describe('validateRouteOptions', () => {
  it('accepts --emit-routes alone and --emit-routes with --routes-out', () => {
    expect(validateRouteOptions({ emitRoutes: true, ai: false })).toBeUndefined();
    expect(validateRouteOptions({ emitRoutes: true, routesOut: '/tmp/x.json', ai: false })).toBeUndefined();
  });

  it('rejects --routes-out without --emit-routes', () => {
    expect(validateRouteOptions({ emitRoutes: false, routesOut: '/tmp/x.json', ai: false })).toMatch(/requires --emit-routes/);
  });

  it('rejects --emit-routes combined with --ai', () => {
    expect(validateRouteOptions({ emitRoutes: true, ai: true })).toMatch(/cannot be combined with --ai/);
  });

  it('accepts a plain scan without route flags', () => {
    expect(validateRouteOptions({ emitRoutes: false, ai: false })).toBeUndefined();
  });
});
