import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Parser } from '../../src/core/parser';
import { buildImportGraph } from '../../src/core/import-graph';
import { extractExpressRoutes } from '../../src/framework/routes/express-routes';
import type { ExtractionResult } from '../../src/framework/routes/types';
import type { ParsedFile } from '../../src/rules/types';

const FIXTURE = fileURLToPath(new URL('../fixtures/express-src', import.meta.url));
const VIRTUAL_ROOT = path.resolve('/virtual/app');

function walk(dir: string, out: string[] = []): string[] {
  for (const name of fs.readdirSync(dir)) {
    const full = path.join(dir, name);
    if (fs.statSync(full).isDirectory()) walk(full, out);
    else if (/\.(ts|js)$/.test(name)) out.push(full);
  }
  return out;
}

function extractFromFixture(): ExtractionResult {
  const parsed = new Parser().parseFiles(walk(FIXTURE));
  return extractExpressRoutes({ parsedFiles: parsed, graph: buildImportGraph(parsed), root: FIXTURE });
}

function extractSnippets(files: Record<string, string>): ExtractionResult {
  const parser = new Parser();
  const parsed: ParsedFile[] = Object.entries(files).map(([rel, code]) => {
    const result = parser.parseContent(path.join(VIRTUAL_ROOT, rel), code);
    if (!('sourceFile' in result)) throw new Error(result.error);
    return result;
  });
  return extractExpressRoutes({ parsedFiles: parsed, graph: buildImportGraph(parsed), root: VIRTUAL_ROOT });
}

/** Línea 1-based de la primera ocurrencia de `needle` en el fichero. */
function lineOf(relFile: string, needle: string): number {
  const lines = fs.readFileSync(path.join(FIXTURE, relFile), 'utf-8').split('\n');
  const index = lines.findIndex((l) => l.includes(needle));
  if (index === -1) throw new Error(`"${needle}" not found in ${relFile}`);
  return index + 1;
}

describe('extractExpressRoutes (express-src fixture)', () => {
  const result = extractFromFixture();

  it('composes the mount prefixes across files: GET /api/users/:id', () => {
    const route = result.routes.find((r) => r.method === 'GET' && r.path === '/api/users/:id');
    expect(route).toBeDefined();
    expect(route!.params).toContainEqual({ name: 'id', in: 'path' });
    expect(route!.hasAuth).toBe(true);
    expect(route!.framework).toBe('express');
  });

  it('points the handler of GET /api/users/:id to its file and range in another module', () => {
    const route = result.routes.find((r) => r.method === 'GET' && r.path === '/api/users/:id')!;
    expect(route.filePath).toBe('controllers/users.ts');
    const start = lineOf('controllers/users.ts', 'export function getUser');
    expect(route.line).toBe(start);
    expect(route.endLine).toBeGreaterThan(start);
    const closing = fs.readFileSync(path.join(FIXTURE, 'controllers/users.ts'), 'utf-8').split('\n')[route.endLine - 1];
    expect(closing.trim()).toBe('}');
  });

  it('extracts body params from req.body destructuring and accesses: POST /api/users', () => {
    const route = result.routes.find((r) => r.method === 'POST' && r.path === '/api/users');
    expect(route).toBeDefined();
    expect(route!.filePath).toBe('routes/users.ts');
    expect(route!.params).toEqual([
      { name: 'email', in: 'body' },
      { name: 'name', in: 'body' },
    ]);
    expect(route!.hasAuth).toBe(false);
  });

  it('lists a non-literal path as unresolved and emits no route for it', () => {
    expect(result.unresolved).toContainEqual(expect.objectContaining({
      filePath: 'routes/dyn.ts',
      reason: 'path no literal',
    }));
    expect(result.routes.some((r) => r.path.includes('dynamic'))).toBe(false);
  });

  it('lists a never-mounted router as unresolved', () => {
    expect(result.unresolved).toContainEqual(expect.objectContaining({
      filePath: 'routes/orphan.ts',
      reason: 'router sin montaje conocido',
    }));
    expect(result.routes.some((r) => r.path.includes('secret'))).toBe(false);
  });

  it('expands app.route(path).get().head() into GET and HEAD', () => {
    const health = result.routes.filter((r) => r.path === '/health').map((r) => r.method).sort();
    expect(health).toEqual(['GET', 'HEAD']);
  });

  it('follows module.exports = router through require() in a mount', () => {
    const route = result.routes.find((r) => r.path === '/api/legacy/ping');
    expect(route?.method).toBe('GET');
    expect(route?.filePath).toBe('routes/legacy.js');
  });
});

describe('extractExpressRoutes (snippets)', () => {
  it('ignores obj.get(path, fn) on an object that is not a router', () => {
    const result = extractSnippets({
      'app.ts': `
        const store = { get(key: string, fn: () => void) { return fn(); } };
        store.get('x', () => {});
      `,
    });
    expect(result.routes).toEqual([]);
    expect(result.unresolved).toEqual([]);
  });

  it('does not treat app.get(name) with a single argument as a route', () => {
    const result = extractSnippets({
      'app.ts': `
        import express from 'express';
        const app = express();
        app.get('view engine');
      `,
    });
    expect(result.routes).toEqual([]);
  });

  it('emits one route per mount prefix when a router is mounted twice', () => {
    const result = extractSnippets({
      'app.ts': `
        import express from 'express';
        const app = express();
        const r = express.Router();
        r.get('/x', (req, res) => res.end());
        app.use('/a', r);
        app.use('/b', r);
      `,
    });
    expect(result.routes.map((r) => r.path).sort()).toEqual(['/a/x', '/b/x']);
  });

  it('stops on a mount cycle and reports it as unresolved', () => {
    const result = extractSnippets({
      'app.ts': `
        import express from 'express';
        const app = express();
        const a = express.Router();
        const b = express.Router();
        a.get('/x', (req, res) => res.end());
        app.use('/a', a);
        a.use('/b', b);
        b.use('/c', a);
      `,
    });
    expect(result.routes.map((r) => r.path)).toEqual(['/a/x']);
    expect(result.unresolved).toContainEqual(expect.objectContaining({ reason: 'ciclo de montaje' }));
  });

  it('reads query params from a handler whose request parameter is not named req', () => {
    const result = extractSnippets({
      'app.ts': `
        import express from 'express';
        const app = express();
        app.get('/q', (request, res) => res.send(request.query.q));
      `,
    });
    expect(result.routes).toHaveLength(1);
    expect(result.routes[0].params).toEqual([{ name: 'q', in: 'query' }]);
  });

  it('applies router.use(auth) only to routes declared after it', () => {
    const result = extractSnippets({
      'app.ts': `
        import express from 'express';
        const app = express();
        const r = express.Router();
        r.get('/before', (req, res) => res.end());
        r.use(requireLogin);
        r.get('/after', (req, res) => res.end());
        app.use('/v', r);
      `,
    });
    const byPath = Object.fromEntries(result.routes.map((r) => [r.path, r.hasAuth]));
    expect(byPath['/v/before']).toBe(false);
    expect(byPath['/v/after']).toBe(true);
  });

  it('marks routes as auth when the mount itself carries an auth middleware', () => {
    const result = extractSnippets({
      'app.ts': `
        import express from 'express';
        const app = express();
        const r = express.Router();
        r.get('/x', (req, res) => res.end());
        app.use('/admin', requireAuth, r);
      `,
    });
    expect(result.routes[0].hasAuth).toBe(true);
  });

  it('lists routes under a non-literal mount prefix as unresolved', () => {
    const result = extractSnippets({
      'app.ts': `
        import express from 'express';
        const app = express();
        const r = express.Router();
        r.get('/x', (req, res) => res.end());
        const prefix = process.env.API_PREFIX;
        app.use(prefix, r);
      `,
    });
    expect(result.routes).toEqual([]);
    expect(result.unresolved).toContainEqual(expect.objectContaining({ reason: 'prefijo de montaje no literal' }));
  });
});

describe('extractExpressRoutes (objetos no-Express por nombre)', () => {
  const handler = '(req, res) => res.end()';

  it('does not emit an Express route for app = fastify(); app.get(...)', () => {
    const result = extractSnippets({
      'app.ts': `
        import fastify from 'fastify';
        const app = fastify();
        app.get('/x', ${handler});
      `,
    });
    expect(result.routes).toEqual([]);
  });

  it('does not emit routes for other non-Express factories, by identifier or require() call', () => {
    const result = extractSnippets({
      'app.ts': `
        const apiRouter = polka();
        apiRouter.get('/p', ${handler});
        const app = require('restify').createServer();
        app.get('/q', ${handler});
        const server = require('koa')();
        const router = require('fastify')();
        router.get('/r', ${handler});
      `,
    });
    expect(result.routes.map((r) => r.path)).toEqual([]);
  });

  it('still emits GET /y for app = express(); app.get(...)', () => {
    const result = extractSnippets({
      'app.ts': `
        import express from 'express';
        const app = express();
        app.get('/y', ${handler});
      `,
    });
    expect(result.routes).toContainEqual(expect.objectContaining({ method: 'GET', path: '/y', framework: 'express' }));
  });

  it('still emits a route for a mounted express.Router()', () => {
    const result = extractSnippets({
      'app.ts': `
        import express from 'express';
        const app = express();
        const r = express.Router();
        r.get('/z', ${handler});
        app.use('/v1', r);
      `,
    });
    expect(result.routes).toContainEqual(expect.objectContaining({ method: 'GET', path: '/v1/z' }));
  });

  it('keeps treating an unknown factory (makeServer()) as a router, conservatively', () => {
    const result = extractSnippets({
      'app.ts': `
        const app = makeServer();
        app.get('/w', ${handler});
      `,
    });
    expect(result.routes).toContainEqual(expect.objectContaining({ method: 'GET', path: '/w' }));
  });
});
