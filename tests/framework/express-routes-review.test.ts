import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { Parser } from '../../src/core/parser';
import { buildImportGraph } from '../../src/core/import-graph';
import { extractExpressRoutes } from '../../src/framework/routes/express-routes';
import type { ExtractionResult } from '../../src/framework/routes/types';
import type { ParsedFile } from '../../src/rules/types';

const ROOT = path.resolve('/virtual/review');

function extract(files: Record<string, string>): ExtractionResult {
  const parser = new Parser();
  const parsed: ParsedFile[] = Object.entries(files).map(([rel, code]) => {
    const result = parser.parseContent(path.join(ROOT, rel), code);
    if (!('sourceFile' in result)) throw new Error(result.error);
    return result;
  });
  return extractExpressRoutes({ parsedFiles: parsed, graph: buildImportGraph(parsed), root: ROOT });
}

const pairs = (r: ExtractionResult): string[] => r.routes.map((x) => `${x.method} ${x.path}`).sort();

const ROUTER_FILE = `
  import express from 'express';
  const router = express.Router();
  router.get('/x', (req, res) => res.end());
  export default router;
`;

describe('use(x, router): prefix vs middleware', () => {
  it('treats an identifier that resolves to a string const as the prefix', () => {
    const r = extract({
      'app.ts': `
        import express from 'express';
        import router from './router';
        const app = express();
        const BASE = '/dyn';
        app.use(BASE, router);
      `,
      'router.ts': ROUTER_FILE,
    });
    expect(pairs(r)).toEqual(['GET /dyn/x']);
  });

  it('accepts a template literal without expressions and `as const` as a literal const', () => {
    const r = extract({
      'app.ts': `
        import express from 'express';
        import router from './router';
        const app = express();
        const A = \`/tpl\`;
        const B = '/cst' as const;
        app.use(A, router);
        app.use(B, router);
      `,
      'router.ts': ROUTER_FILE,
    });
    expect(pairs(r)).toEqual(['GET /cst/x', 'GET /tpl/x']);
  });

  it('follows a string const imported from a relative file', () => {
    const r = extract({
      'app.ts': `
        import express from 'express';
        import router from './router';
        import { API } from './config';
        const app = express();
        app.use(API, router);
      `,
      'config.ts': `export const API = '/v2';`,
      'router.ts': ROUTER_FILE,
    });
    expect(pairs(r)).toEqual(['GET /v2/x']);
  });

  it('treats an identifier that resolves to something else as middleware (prefix "")', () => {
    const r = extract({
      'app.ts': `
        import express from 'express';
        import router from './router';
        const app = express();
        const logger = (req, res, next) => next();
        app.use(logger, router);
      `,
      'router.ts': ROUTER_FILE,
    });
    expect(pairs(r)).toEqual(['GET /x']);
    expect(r.unresolved).toEqual([]);
  });

  it('treats an unresolvable identifier (imported package) as middleware', () => {
    const r = extract({
      'app.ts': `
        import express from 'express';
        import cors from 'cors';
        import apiRouter from './router';
        const app = express();
        app.use(cors, apiRouter);
      `,
      'router.ts': ROUTER_FILE,
    });
    expect(pairs(r)).toEqual(['GET /x']);
  });

  it('counts an auth-named middleware identifier as auth of the mount', () => {
    const r = extract({
      'app.ts': `
        import express from 'express';
        import router from './router';
        import { requireAuth } from 'auth-lib';
        const app = express();
        app.use(requireAuth, router);
      `,
      'router.ts': ROUTER_FILE,
    });
    expect(r.routes).toHaveLength(1);
    expect(r.routes[0].path).toBe('/x');
    expect(r.routes[0].hasAuth).toBe(true);
  });

  it('sends a clearly-string but non-literal prefix to unresolved', () => {
    for (const decl of [
      'const p = process.env.API_PREFIX;',
      "const base = '/a'; const p = base + '/x';",
      'const base = "/a"; const p = `${base}/x`;',
    ]) {
      const r = extract({
        'app.ts': `
          import express from 'express';
          import router from './router';
          const app = express();
          ${decl}
          app.use(p, router);
        `,
        'router.ts': ROUTER_FILE,
      });
      expect(r.routes, decl).toEqual([]);
      expect(r.unresolved, decl).toContainEqual(
        expect.objectContaining({ reason: 'prefijo de montaje no literal' }),
      );
    }
  });

  it('sends inline non-literal prefixes (template with expressions, regex, process.env) to unresolved', () => {
    for (const first of ['`/a/${v}`', '/^\\/api/', 'process.env.PREFIX', "'/a' + v"]) {
      const r = extract({
        'app.ts': `
          import express from 'express';
          import router from './router';
          const app = express();
          app.use(${first}, router);
        `,
        'router.ts': ROUTER_FILE,
      });
      expect(r.routes, first).toEqual([]);
      expect(r.unresolved, first).toContainEqual(
        expect.objectContaining({ reason: 'prefijo de montaje no literal' }),
      );
    }
  });

  it('does not treat a prefix-like unresolvable name as middleware', () => {
    const r = extract({
      'app.ts': `
        import express from 'express';
        import router from './router';
        import { API_PREFIX } from '@app/config';
        const app = express();
        app.use(API_PREFIX, router);
      `,
      'router.ts': ROUTER_FILE,
    });
    expect(r.routes).toEqual([]);
    expect(r.unresolved).toContainEqual(expect.objectContaining({ reason: 'prefijo de montaje no literal' }));
  });
});

describe('mounts without prefix and with prefix arrays', () => {
  it('mounts app.use(router), app.use(require("./routes")) and app.use(auth, router) at ""', () => {
    const r = extract({
      'app.ts': `
        const express = require('express');
        const app = express();
        const router = express.Router();
        router.get('/local', (req, res) => res.end());
        app.use(router);
        app.use(require('./routes'));
        app.use(authenticate, require('./secured'));
      `,
      'routes.js': `
        const express = require('express');
        const r = express.Router();
        r.get('/required', (req, res) => res.end());
        module.exports = r;
      `,
      'secured.js': `
        const express = require('express');
        const r = express.Router();
        r.get('/secured', (req, res) => res.end());
        module.exports = r;
      `,
    });
    expect(pairs(r)).toEqual(['GET /local', 'GET /required', 'GET /secured']);
    expect(r.routes.find((x) => x.path === '/secured')!.hasAuth).toBe(true);
    expect(r.routes.find((x) => x.path === '/required')!.hasAuth).toBe(false);
  });

  it('mounts several routers passed to one use() call', () => {
    const r = extract({
      'app.ts': `
        import express from 'express';
        const app = express();
        const a = express.Router(); a.get('/a', (q, s) => s.end());
        const b = express.Router(); b.get('/b', (q, s) => s.end());
        app.use('/m', a, b);
        app.use(a, b);
      `,
    });
    expect(pairs(r)).toEqual(['GET /a', 'GET /b', 'GET /m/a', 'GET /m/b']);
  });

  it('emits one route per prefix of an array mount', () => {
    const r = extract({
      'app.ts': `
        import express from 'express';
        import router from './router';
        const app = express();
        app.use(['/a', '/b'], router);
      `,
      'router.ts': ROUTER_FILE,
    });
    expect(pairs(r)).toEqual(['GET /a/x', 'GET /b/x']);
  });

  it('mounts at the root with app.use("/", router)', () => {
    const r = extract({
      'app.ts': `
        import express from 'express';
        import router from './router';
        const app = express();
        app.use('/', router);
      `,
      'router.ts': ROUTER_FILE,
    });
    expect(pairs(r)).toEqual(['GET /x']);
  });
});

describe('path composition', () => {
  it('normalizes /api + / + /users/ + :id', () => {
    const r = extract({
      'app.ts': `
        import express from 'express';
        import api from './api';
        const app = express();
        app.use('/api/', api);
      `,
      'api.ts': `
        import express from 'express';
        import users from './users';
        const api = express.Router();
        api.use('/', users);
        export default api;
      `,
      'users.ts': `
        import express from 'express';
        const users = express.Router();
        users.use('/users/', express.Router());
        users.get('/users/', (q, s) => s.end());
        users.get('/users//:id', (q, s) => s.end());
        users.get('/', (q, s) => s.end());
        export default users;
      `,
    });
    expect(pairs(r)).toEqual(['GET /api', 'GET /api/users', 'GET /api/users/:id']);
  });

  it('router.get("/") under /api/users is /api/users', () => {
    const r = extract({
      'app.ts': `
        import express from 'express';
        const app = express();
        const users = express.Router();
        users.get('/', (q, s) => s.end());
        app.use('/api/users', users);
      `,
    });
    expect(pairs(r)).toEqual(['GET /api/users']);
  });

  it('keeps optional params and strips regex constraints from named params', () => {
    const r = extract({
      'app.ts': `
        import express from 'express';
        const app = express();
        app.get('/a/:id?', (q, s) => s.end());
        app.get('/b/:id(\\\\d+)', (q, s) => s.end());
        app.get('/c/:id(\\\\d+)?', (q, s) => s.end());
      `,
    });
    expect(pairs(r)).toEqual(['GET /a/:id?', 'GET /b/:id', 'GET /c/:id?']);
    expect(r.routes.find((x) => x.path === '/b/:id')!.params).toContainEqual({ name: 'id', in: 'path' });
    expect(r.unresolved).toEqual([]);
  });

  it('sends wildcard / regex-string paths to unresolved as "path con patrón"', () => {
    const r = extract({
      'app.ts': `
        import express from 'express';
        const app = express();
        app.get('/ab*cd', (q, s) => s.end());
        app.get('/a(b)?c', (q, s) => s.end());
        app.all('*', (q, s) => s.end());
        app.get('/ok', (q, s) => s.end());
        app.get(['/x', '/y*'], (q, s) => s.end());
      `,
    });
    expect(pairs(r)).toEqual(['GET /ok', 'GET /x']);
    const reasons = r.unresolved.map((u) => u.reason);
    expect(reasons.filter((x) => x === 'path con patrón')).toHaveLength(4);
  });

  it('sends a mount prefix with a pattern to unresolved', () => {
    const r = extract({
      'app.ts': `
        import express from 'express';
        import router from './router';
        const app = express();
        app.use('/ab*cd', router);
      `,
      'router.ts': ROUTER_FILE,
    });
    expect(r.routes).toEqual([]);
    expect(r.unresolved).toContainEqual(expect.objectContaining({ reason: 'path con patrón' }));
  });
});

describe('invented or lost routes', () => {
  it('ignores app.get(name) settings getters, Map/axios/cache objects, router.param, app.locals', () => {
    const r = extract({
      'app.ts': `
        import express from 'express';
        import axios from 'axios';
        const app = express();
        const cache = new Map();
        const mapRouter = new Map();
        const env = app.get('env');
        app.get('view engine');
        app.set('x', 1);
        app.locals.title = 'x';
        axios.get('/remote', handler);
        cache.get('/key', fn);
        mapRouter.get('/key', fn);
        const router = express.Router();
        router.param('id', (req, res, next) => next());
        router.get('/real', (q, s) => s.end());
        app.use('/r', router);
      `,
    });
    expect(pairs(r)).toEqual(['GET /r/real']);
    expect(r.unresolved).toEqual([]);
  });

  it('emits router.all as method ALL', () => {
    const r = extract({
      'app.ts': `
        import express from 'express';
        const app = express();
        app.all('/any', (q, s) => s.end());
      `,
    });
    expect(pairs(r)).toEqual(['ALL /any']);
  });

  it('does not fail on files without routes or with syntax-only content', () => {
    const r = extract({
      'empty.ts': '',
      'util.ts': 'export const x = 1;',
      'class.ts': 'export class A { get(a, b) { return a + b; } }',
    });
    expect(r).toEqual({ routes: [], unresolved: [] });
  });

  it('does not duplicate unresolved entries when a router with a bad prefix is mounted twice', () => {
    const r = extract({
      'app.ts': `
        import express from 'express';
        import router from './router';
        const app = express();
        app.use(process.env.A, router);
        app.use(process.env.A, router);
      `,
      'router.ts': ROUTER_FILE,
    });
    expect(r.unresolved).toHaveLength(1);
  });
});

describe('handlers in other files', () => {
  const ROUTE = (line: string, imports: string): Record<string, string> => ({
    'app.ts': `
      import express from 'express';
      ${imports}
      const app = express();
      ${line}
    `,
  });

  it('export default function', () => {
    const r = extract({
      ...ROUTE("app.get('/a', handler);", "import handler from './h';"),
      'h.ts': 'export default function handler(req, res) {\n  const { q } = req.query;\n}\n',
    });
    expect(r.routes[0].filePath).toBe('h.ts');
    expect(r.routes[0].line).toBe(1);
    expect(r.routes[0].endLine).toBe(3);
    expect(r.routes[0].params).toContainEqual({ name: 'q', in: 'query' });
  });

  it('export const getUser = async (...) =>', () => {
    const r = extract({
      ...ROUTE("app.get('/a', getUser);", "import { getUser } from './h';"),
      'h.ts': 'export const getUser = async (request, res) => {\n  request.body.name;\n};\n',
    });
    expect(r.routes[0].filePath).toBe('h.ts');
    expect(r.routes[0].params).toContainEqual({ name: 'name', in: 'body' });
  });

  it('exports.getUser = function', () => {
    const r = extract({
      ...ROUTE("app.get('/a', getUser);", "const { getUser } = require('./h');"),
      'h.js': 'exports.getUser = function (req, res) {\n  req.query.z;\n};\n',
    });
    expect(r.routes[0].filePath).toBe('h.js');
    expect(r.routes[0].params).toContainEqual({ name: 'z', in: 'query' });
  });

  it('module.exports = { getUser } (shorthand, property and method forms)', () => {
    const files = {
      'h.js': [
        'function getUser(req, res) {',
        '  req.query.fromShorthand;',
        '}',
        'module.exports = {',
        '  getUser,',
        '  other: (req, res) => { req.query.fromProp; },',
        '  third(req, res) { req.query.fromMethod; },',
        '};',
      ].join('\n'),
    };
    const r = extract({
      ...ROUTE(
        "app.get('/a', getUser);\napp.get('/b', ctl.other);\napp.get('/c', ctl.third);",
        "const { getUser } = require('./h'); const ctl = require('./h');",
      ),
      ...files,
    });
    const byPath = Object.fromEntries(r.routes.map((x) => [x.path, x]));
    expect(byPath['/a'].filePath).toBe('h.js');
    expect(byPath['/a'].params).toContainEqual({ name: 'fromShorthand', in: 'query' });
    expect(byPath['/b'].filePath).toBe('h.js');
    expect(byPath['/b'].params).toContainEqual({ name: 'fromProp', in: 'query' });
    expect(byPath['/c'].filePath).toBe('h.js');
    expect(byPath['/c'].params).toContainEqual({ name: 'fromMethod', in: 'query' });
  });

  it('class instance: controller = new UserController() in the same file or imported', () => {
    const r = extract({
      'app.ts': `
        import express from 'express';
        import { UserController } from './ctl';
        import { instance } from './ctl';
        const app = express();
        const controller = new UserController();
        app.get('/a/:id', controller.getById);
        app.get('/b', instance.arrow);
        app.get('/c', controller.getById.bind(controller));
        app.get('/d', UserController.make);
      `,
      'ctl.ts': [
        'export class UserController {',
        '  getById(req, res) {',
        '    req.query.verbose;',
        '  }',
        '  arrow = async (req, res) => { req.body.title; };',
        '  static make(req, res) { req.query.s; }',
        '}',
        'export const instance = new UserController();',
      ].join('\n'),
    });
    const byPath = Object.fromEntries(r.routes.map((x) => [x.path, x]));
    expect(byPath['/a/:id'].filePath).toBe('ctl.ts');
    expect(byPath['/a/:id'].line).toBe(2);
    expect(byPath['/a/:id'].endLine).toBe(4);
    expect(byPath['/a/:id'].params).toContainEqual({ name: 'verbose', in: 'query' });
    expect(byPath['/b'].filePath).toBe('ctl.ts');
    expect(byPath['/b'].params).toContainEqual({ name: 'title', in: 'body' });
    expect(byPath['/c'].filePath).toBe('ctl.ts');
    expect(byPath['/d'].params).toContainEqual({ name: 's', in: 'query' });
  });

  it('unwraps asyncHandler(fn) wrappers', () => {
    const r = extract({
      ...ROUTE(
        "app.get('/a', asyncHandler(getUser));\napp.get('/b', wrap(async (req, res) => { req.query.w; }));",
        "import { getUser } from './h'; import { asyncHandler, wrap } from './wrap';",
      ),
      'h.ts': 'export function getUser(req, res) {}\n',
    });
    const byPath = Object.fromEntries(r.routes.map((x) => [x.path, x]));
    expect(byPath['/a'].filePath).toBe('h.ts');
    expect(byPath['/b'].params).toContainEqual({ name: 'w', in: 'query' });
  });

  it('falls back to the route call range when the handler cannot be resolved (never invented)', () => {
    const r = extract({
      'app.ts': [
        "import express from 'express';",
        "import { missing } from './h';",
        "import external from 'some-lib';",
        'const app = express();',
        "app.get('/a', missing);",
        "app.get('/b', external.handler);",
        "app.get('/c',",
        '  unknownFn,',
        ');',
      ].join('\n'),
      'h.ts': 'export const other = 1;\n',
    });
    const byPath = Object.fromEntries(r.routes.map((x) => [x.path, x]));
    expect(byPath['/a'].filePath).toBe('app.ts');
    expect(byPath['/a'].line).toBe(5);
    expect(byPath['/b'].line).toBe(6);
    expect(byPath['/c'].line).toBe(7);
    expect(byPath['/c'].endLine).toBe(9);
    expect(byPath['/a'].params).toEqual([]);
  });

  it('takes query/body params from the resolved handler, not from the route file', () => {
    const r = extract({
      'app.ts': `
        import express from 'express';
        import { h } from './h';
        const app = express();
        const noise = (req) => req.query.fromRouteFile;
        app.get('/a', h);
      `,
      'h.ts': 'export function h(req, res) { req.query.fromHandler; }\n',
    });
    const names = r.routes[0].params.map((p) => p.name);
    expect(names).toContain('fromHandler');
    expect(names).not.toContain('fromRouteFile');
  });

  it('reads params through casts like (req.query as any).x', () => {
    const r = extract({
      ...ROUTE("app.get('/a', (req, res) => { (req.query as any).cast; });", ''),
    });
    expect(r.routes[0].params).toContainEqual({ name: 'cast', in: 'query' });
  });
});

describe('import x = require()', () => {
  it('recognizes express imported with TS import-equals', () => {
    const r = extract({
      'app.ts': `
        import express = require('express');
        const server = express();
        server.get('/ie', (q, s) => s.end());
      `,
    });
    expect(pairs(r)).toEqual(['GET /ie']);
  });
});
