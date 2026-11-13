import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  RouteArtifactError,
  isArtifactStale,
  loadRouteArtifact,
  toSurfaceEndpoints,
  validateRouteArtifact,
} from '../../src/dast/surface';
import type { ExtractedRoute, RouteArtifact } from '../../src/framework/routes/types';

let workDir: string;

beforeEach(() => {
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-surface-'));
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(workDir, { recursive: true, force: true });
});

function route(overrides: Partial<ExtractedRoute> = {}): ExtractedRoute {
  return {
    method: 'GET',
    path: '/a',
    framework: 'express',
    filePath: 'src/routes.ts',
    line: 3,
    endLine: 9,
    hasAuth: false,
    params: [],
    reachableFiles: [],
    staticFindings: [],
    ...overrides,
  };
}

function artifact(routes: Array<Partial<ExtractedRoute>> = [{}], overrides: Record<string, unknown> = {}): RouteArtifact {
  return {
    version: 1,
    generatedAt: '2026-08-02T10:00:00.000Z',
    target: workDir,
    frameworks: ['express'],
    routes: routes.map((r) => route(r)),
    unresolved: [],
    ...overrides,
  } as RouteArtifact;
}

function writeArtifact(value: unknown): string {
  const file = path.join(workDir, 'routes.json');
  fs.writeFileSync(file, JSON.stringify(value));
  return file;
}

function expectInvalid(value: unknown, message: RegExp | string): void {
  const error = (() => {
    try {
      validateRouteArtifact(value);
      return undefined;
    } catch (e) {
      return e;
    }
  })();
  expect(error).toBeInstanceOf(RouteArtifactError);
  expect((error as Error).message).toMatch(message);
}

describe('loadRouteArtifact', () => {
  it('loads a valid artifact from disk', () => {
    const file = writeArtifact(artifact([{ path: '/users/:id', method: 'GET' }]));
    const loaded = loadRouteArtifact(file);
    expect(loaded.version).toBe(1);
    expect(loaded.routes[0].path).toBe('/users/:id');
  });

  it('rejects broken JSON without echoing the file contents', () => {
    const file = path.join(workDir, 'broken.json');
    fs.writeFileSync(file, '{"secret-marker": ');
    let caught: unknown;
    try {
      loadRouteArtifact(file);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RouteArtifactError);
    expect((caught as Error).message).not.toContain('secret-marker');
  });

  it('rejects a special file instead of reading it to the end', () => {
    expect(() => loadRouteArtifact('/dev/zero')).toThrow(RouteArtifactError);
  });

  it('rejects a directory', () => {
    expect(() => loadRouteArtifact(workDir)).toThrow(RouteArtifactError);
  });

  it('rejects a missing file', () => {
    expect(() => loadRouteArtifact(path.join(workDir, 'missing.json'))).toThrow(RouteArtifactError);
  });

  it('rejects a file larger than 20 MB without reading it', () => {
    const file = path.join(workDir, 'huge.json');
    fs.writeFileSync(file, '');
    fs.truncateSync(file, 20 * 1024 * 1024 + 1);
    expect(() => loadRouteArtifact(file)).toThrow(/supera/);
  });
});

describe('validateRouteArtifact', () => {
  it('accepts a valid artifact', () => {
    expect(() => validateRouteArtifact(artifact([{ path: '/a' }]))).not.toThrow();
  });

  it('rejects another version', () => {
    expectInvalid(artifact([], { version: 2 }), /versión de artefacto no soportada/);
  });

  it.each([
    ['//evil.com'],
    ['http://x'],
    ['/a\\b'],
    ['/a\u0007b'],
    ['/' + 'x'.repeat(2048)],
  ])('rejects the route path %j', (routePath) => {
    expectInvalid(artifact([{ path: routePath }]), /routes\[0\]\.path/);
  });

  it.each([['../x.ts'], ['src/../../x.ts'], ['/etc/passwd']])('rejects the filePath %s', (filePath) => {
    expectInvalid(artifact([{ filePath }]), /routes\[0\]\.filePath/);
  });

  it.each([['/a/./b'], ['/a/..'], ['/a/%2e%2e/b'], ['/%2E/x'], ['/a/.%2e/b']])(
    'rejects dot segments that new URL would collapse: %s',
    (routePath) => {
      expectInvalid(artifact([{ path: routePath }]), /routes\[0\]\.path/);
    },
  );

  it.each([['/%2F%2Fevil.com'], ['/..%2F'], ['/@evil.com'], ['/a:b'], ['/a?x=1']])(
    'accepts %s because new URL keeps it inside the target origin',
    (routePath) => {
      expect(() => validateRouteArtifact(artifact([{ path: routePath }]))).not.toThrow();
      expect(new URL(routePath, 'http://127.0.0.1:3000').origin).toBe('http://127.0.0.1:3000');
    },
  );

  it.each([['/\t//x'], ['/a\tb'], ['/a\nb'], ['/a\u0000b']])('rejects control characters in the path %j', (routePath) => {
    expectInvalid(artifact([{ path: routePath }]), /routes\[0\]\.path/);
  });

  it.each([['src\\..\\x.ts'], ['src\\a.ts'], ['C:/x.ts'], ['src/a\u0000.ts'], ['src/a/../b.ts'], ['..'], ['']])(
    'rejects the filePath %j',
    (filePath) => {
      expectInvalid(artifact([{ filePath }]), /routes\[0\]\.filePath/);
    },
  );

  it('rejects unexpected types: null, numbers as strings and non-arrays', () => {
    expectInvalid(artifact([{ line: '5' as unknown as number }]), /routes\[0\]\.line/);
    expectInvalid(artifact([{ path: null as unknown as string }]), /routes\[0\]\.path/);
    expectInvalid(artifact([{ hasAuth: 'yes' as unknown as boolean }]), /routes\[0\]\.hasAuth/);
    expectInvalid(artifact([{ params: null as unknown as [] }]), /routes\[0\]\.params/);
    expectInvalid({ ...artifact([]), routes: [null] }, /routes\[0\]/);
    expectInvalid(artifact([], { routes: {} }), /routes/);
    expectInvalid(artifact([], { unresolved: null }), /unresolved/);
    expectInvalid(artifact([], { frameworks: [1] }), /frameworks/);
    expectInvalid(artifact([], { generatedAt: 5 }), /generatedAt/);
    expectInvalid(artifact([], { target: 'relative/dir' }), /target/);
    expectInvalid(artifact([], { target: '/tmp/a\u001b[2Jb' }), /target/);
    expectInvalid(null, /raíz/);
    expectInvalid([], /raíz/);
  });

  it('rejects more than 50000 routes', () => {
    const many = Array.from({ length: 50001 }, () => route());
    expectInvalid({ ...artifact([]), routes: many }, /routes/);
  });

  it('returns a clean copy: extra properties and an own __proto__ do not survive', () => {
    const raw = JSON.parse(
      JSON.stringify(artifact([{ path: '/a' }])).replace(
        '"version":1',
        '"version":1,"__proto__":{"polluted":true},"extra":"x"',
      ),
    );
    expect(Object.prototype.hasOwnProperty.call(raw, '__proto__')).toBe(true);

    const loaded = validateRouteArtifact(raw) as unknown as Record<string, unknown>;
    expect(Object.prototype.hasOwnProperty.call(loaded, '__proto__')).toBe(false);
    expect(loaded.extra).toBeUndefined();
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.keys(loaded).sort()).toEqual(['frameworks', 'generatedAt', 'routes', 'target', 'unresolved', 'version']);
  });

  it('rejects endLine smaller than line', () => {
    expectInvalid(artifact([{ line: 10, endLine: 4 }]), /routes\[0\]\.endLine/);
  });

  it('rejects an unknown method and reports the index', () => {
    expectInvalid(artifact([{ path: '/a' }, { method: 'TRACE' as ExtractedRoute['method'] }]), /routes\[1\]\.method/);
  });

  it('rejects a non-integer line', () => {
    expectInvalid(artifact([{ line: 1.5 }]), /routes\[0\]\.line/);
  });

  it('rejects a broken unresolved entry', () => {
    expectInvalid(artifact([], { unresolved: [{ filePath: 'src/a.ts', line: 'x', reason: 'r' }] }), /unresolved\[0\]\.line/);
  });
});

describe('toSurfaceEndpoints', () => {
  it('deduplicates by method and path, keeping the first route', () => {
    const endpoints = toSurfaceEndpoints(
      artifact([
        { path: '/a', filePath: 'first.ts', line: 1, endLine: 2 },
        { path: '/a', filePath: 'second.ts', line: 5, endLine: 6 },
      ]),
    );
    expect(endpoints).toHaveLength(1);
    expect(endpoints[0].route.filePath).toBe('first.ts');
  });

  it('treats ALL as GET and collapses it with an existing GET', () => {
    const endpoints = toSurfaceEndpoints(artifact([{ method: 'ALL', path: '/x' }, { method: 'GET', path: '/x' }]));
    expect(endpoints.map((e) => e.method)).toEqual(['GET']);
  });

  it('substitutes sample values for :id, :id?, :slug+ and :slug*', () => {
    const concrete = (p: string): string => toSurfaceEndpoints(artifact([{ path: p }]))[0].concretePath;
    expect(concrete('/users/:id')).toBe('/users/1');
    expect(concrete('/users/:id?')).toBe('/users/1');
    expect(concrete('/files/:slug+')).toBe('/files/x');
    expect(concrete('/files/:slug*')).toBe('/files');
    expect(concrete('/')).toBe('/');
  });

  it('encodes every substituted value with encodeURIComponent', () => {
    const spy = vi.spyOn(globalThis, 'encodeURIComponent');
    toSurfaceEndpoints(artifact([{ path: '/users/:id' }]));
    expect(spy).toHaveBeenCalledWith('1');
  });

  it('marks POST, PUT, PATCH and DELETE as mutating and returns a stable order', () => {
    const endpoints = toSurfaceEndpoints(
      artifact([
        { method: 'POST', path: '/z' },
        { method: 'PUT', path: '/a' },
        { method: 'GET', path: '/a' },
        { method: 'HEAD', path: '/m' },
      ]),
    );
    expect(endpoints.map((e) => `${e.method} ${e.path}`)).toEqual(['GET /a', 'PUT /a', 'HEAD /m', 'POST /z']);
    expect(endpoints.map((e) => e.mutating)).toEqual([false, true, false, true]);
  });
});

describe('isArtifactStale', () => {
  const generatedAt = Date.parse('2026-08-02T10:00:00.000Z');

  function sourceFile(name: string, mtimeMs: number): void {
    const dir = path.join(workDir, 'src');
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, name);
    fs.writeFileSync(file, 'export {};\n');
    fs.utimesSync(file, new Date(mtimeMs), new Date(mtimeMs));
  }

  it('is false when every route file is older than the artifact', () => {
    sourceFile('routes.ts', generatedAt - 3600_000);
    expect(isArtifactStale(artifact([{ filePath: 'src/routes.ts' }], { generatedAt: new Date(generatedAt).toISOString() }))).toBe(false);
  });

  it('is true when a route file is newer than the artifact', () => {
    sourceFile('routes.ts', generatedAt + 3600_000);
    expect(isArtifactStale(artifact([{ filePath: 'src/routes.ts' }], { generatedAt: new Date(generatedAt).toISOString() }))).toBe(true);
  });

  it('is true when a route file no longer exists', () => {
    expect(isArtifactStale(artifact([{ filePath: 'src/gone.ts' }], { generatedAt: new Date(generatedAt).toISOString() }))).toBe(true);
  });

  it('does not stat files outside the target: a symlink pointing out is ignored', () => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-outside-'));
    try {
      const secret = path.join(outside, 'secret.ts');
      fs.writeFileSync(secret, 'x');
      fs.utimesSync(secret, new Date(generatedAt + 3600_000), new Date(generatedAt + 3600_000));
      fs.mkdirSync(path.join(workDir, 'src'), { recursive: true });
      fs.symlinkSync(secret, path.join(workDir, 'src', 'link.ts'));
      fs.symlinkSync(outside, path.join(workDir, 'linked-dir'));

      const generated = new Date(generatedAt).toISOString();
      expect(isArtifactStale(artifact([{ filePath: 'src/link.ts' }], { generatedAt: generated }))).toBe(false);
      expect(isArtifactStale(artifact([{ filePath: 'linked-dir/secret.ts' }], { generatedAt: generated }))).toBe(false);
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  it('does not resolve a ".." filePath that reaches outside the target', () => {
    const parent = path.dirname(workDir);
    const sibling = fs.mkdtempSync(path.join(parent, 'basesec-sibling-'));
    try {
      fs.writeFileSync(path.join(sibling, 'x.ts'), 'x');
      fs.utimesSync(path.join(sibling, 'x.ts'), new Date(generatedAt + 3600_000), new Date(generatedAt + 3600_000));
      const filePath = `../${path.basename(sibling)}/x.ts`;
      const unsafe = { ...artifact([{}]), routes: [route({ filePath })] };
      expect(isArtifactStale({ ...unsafe, generatedAt: new Date(generatedAt).toISOString() })).toBe(false);
    } finally {
      fs.rmSync(sibling, { recursive: true, force: true });
    }
  });

  it('is true when the target directory no longer exists', () => {
    const gone = path.join(workDir, 'gone');
    expect(isArtifactStale(artifact([{ filePath: 'src/a.ts' }], { target: gone }))).toBe(true);
  });

  it('accepts a file whose name starts with two dots', () => {
    sourceFile('..hidden.ts', generatedAt - 3600_000);
    expect(isArtifactStale(artifact([{ filePath: 'src/..hidden.ts' }], { generatedAt: new Date(generatedAt).toISOString() }))).toBe(false);
  });
});
