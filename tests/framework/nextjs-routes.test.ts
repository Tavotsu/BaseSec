import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Parser } from '../../src/core/parser';
import { buildImportGraph } from '../../src/core/import-graph';
import { extractNextRoutes } from '../../src/framework/routes/nextjs-routes';
import { segmentsToPieces } from '../../src/framework/routes/nextjs-routes';
import { classifyNextFile, isNextRouteHandlerPath } from '../../src/framework/routes/nextjs-files';
import type { ExtractionResult } from '../../src/framework/routes/types';
import type { ParsedFile } from '../../src/rules/types';

const FIXTURE = fileURLToPath(new URL('../fixtures/next-src', import.meta.url));
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
  return extractNextRoutes({ parsedFiles: parsed, graph: buildImportGraph(parsed), root: FIXTURE });
}

function extractSnippets(files: Record<string, string>, root = VIRTUAL_ROOT): ExtractionResult {
  const parser = new Parser();
  const parsed: ParsedFile[] = Object.entries(files).map(([rel, code]) => {
    const result = parser.parseContent(path.join(root, rel), code);
    if (!('sourceFile' in result)) throw new Error(result.error);
    return result;
  });
  return extractNextRoutes({ parsedFiles: parsed, graph: buildImportGraph(parsed), root });
}

/** Línea 1-based de la primera ocurrencia de `needle` en un fichero del fixture. */
function lineOf(relFile: string, needle: string): number {
  const lines = fs.readFileSync(path.join(FIXTURE, relFile), 'utf-8').split('\n');
  const index = lines.findIndex((l) => l.includes(needle));
  if (index === -1) throw new Error(`"${needle}" not found in ${relFile}`);
  return index + 1;
}

describe('extractNextRoutes (next-src fixture, basePath /web)', () => {
  const result = extractFromFixture();
  const find = (method: string, routePath: string) =>
    result.routes.find((r) => r.method === method && r.path === routePath);

  it('prefixes every route with basePath from next.config.js', () => {
    expect(result.routes.length).toBeGreaterThan(0);
    expect(result.routes.every((r) => r.path.startsWith('/web'))).toBe(true);
    expect(result.routes.every((r) => r.framework === 'nextjs')).toBe(true);
  });

  it('emits GET, HEAD (implicit) and POST for the App Router users route with their params', () => {
    const get = find('GET', '/web/api/users')!;
    expect(get).toBeDefined();
    expect(get.filePath).toBe('app/api/users/route.ts');
    expect(get.params).toContainEqual({ name: 'q', in: 'query' });
    expect(find('HEAD', '/web/api/users')).toBeDefined();

    const post = find('POST', '/web/api/users')!;
    expect(post.params).toContainEqual({ name: 'email', in: 'body' });
    expect(post.line).toBe(lineOf('app/api/users/route.ts', 'export async function POST'));
  });

  it('points GET of users at the handler range', () => {
    const get = find('GET', '/web/api/users')!;
    expect(get.line).toBe(lineOf('app/api/users/route.ts', 'export async function GET'));
    expect(get.endLine).toBeGreaterThan(get.line);
  });

  it('maps a dynamic segment to a path param and detects auth with getServerSession', () => {
    const route = find('GET', '/web/api/users/:id')!;
    expect(route).toBeDefined();
    expect(route.params).toContainEqual({ name: 'id', in: 'path' });
    expect(route.hasAuth).toBe(true);
    expect(find('HEAD', '/web/api/users/:id')).toBeDefined();
  });

  it('drops route groups and emits an export { handler as GET } alias', () => {
    expect(find('GET', '/web/api/stats')).toBeDefined();
    expect(find('HEAD', '/web/api/stats')).toBeDefined();
    expect(result.routes.some((r) => r.path.includes('(admin)'))).toBe(false);
  });

  it('maps catch-all and optional catch-all segments to :name+ and :name*', () => {
    const files = find('GET', '/web/api/files/:path+')!;
    expect(files.params).toContainEqual({ name: 'path', in: 'path' });
    const docs = find('GET', '/web/api/docs/:slug*')!;
    expect(docs.params).toContainEqual({ name: 'slug', in: 'path' });
  });

  it('does not emit routes from private folders (_lib) or parallel slots (@modal)', () => {
    expect(result.routes.some((r) => r.filePath.includes('_lib') || r.filePath.includes('@modal'))).toBe(false);
  });

  it('emits only POST for a Pages Router handler that compares req.method, with a body param', () => {
    const post = find('POST', '/web/api/legacy')!;
    expect(post).toBeDefined();
    expect(post.params).toContainEqual({ name: 'token', in: 'body' });
    expect(find('GET', '/web/api/legacy')).toBeUndefined();
    expect(result.routes.filter((r) => r.path === '/web/api/legacy')).toHaveLength(1);
  });

  it('maps pages/api/index.ts to the folder path, not to /index', () => {
    expect(find('GET', '/web/api')).toBeDefined();
    expect(result.routes.some((r) => r.path.endsWith('/index'))).toBe(false);
  });

  it('lists Server Actions as unresolved', () => {
    expect(result.unresolved).toContainEqual({
      filePath: 'app/actions.ts',
      line: 1,
      reason: 'Server Actions de Next.js',
    });
  });

  it('reports hasAuth false when there is no middleware.ts', () => {
    expect(find('GET', '/web/api/stats')!.hasAuth).toBe(false);
    expect(find('GET', '/web/api/users')!.hasAuth).toBe(false);
  });
});

describe('segment conversion', () => {
  it('maps the table of plan 5.7 segment by segment', () => {
    expect(segmentsToPieces(['api', 'users'])).toEqual({ kind: 'path', pieces: ['api', 'users'] });
    expect(segmentsToPieces(['api', '[id]'])).toEqual({ kind: 'path', pieces: ['api', ':id'] });
    expect(segmentsToPieces(['[...slug]'])).toEqual({ kind: 'path', pieces: [':slug+'] });
    expect(segmentsToPieces(['[[...slug]]'])).toEqual({ kind: 'path', pieces: [':slug*'] });
    expect(segmentsToPieces(['(admin)', 'stats'])).toEqual({ kind: 'path', pieces: ['stats'] });
    expect(segmentsToPieces(['%5Fprivate'])).toEqual({ kind: 'path', pieces: ['_private'] });
  });

  it('discards the whole route for private and parallel segments', () => {
    expect(segmentsToPieces(['_lib'])).toEqual({ kind: 'discard' });
    expect(segmentsToPieces(['api', '@modal'])).toEqual({ kind: 'discard' });
  });

  it('leaves interception segments unresolved', () => {
    expect(segmentsToPieces(['(.)photo'])).toEqual({ kind: 'unresolved', reason: 'ruta interceptada de Next.js' });
    expect(segmentsToPieces(['(..)photo'])).toEqual({ kind: 'unresolved', reason: 'ruta interceptada de Next.js' });
    expect(segmentsToPieces(['(...)photo'])).toEqual({ kind: 'unresolved', reason: 'ruta interceptada de Next.js' });
  });
});

describe('classifyNextFile', () => {
  it('accepts the App Router under src/ and rejects other files', () => {
    expect(classifyNextFile('src/app/api/x/route.ts')).toEqual({ kind: 'app-route', segments: ['api', 'x'] });
    expect(classifyNextFile('app/route.mjs')).toEqual({ kind: 'app-route', segments: [] });
    expect(classifyNextFile('app/api/x/page.tsx')).toBeNull();
  });

  it('excludes test, spec and declaration files', () => {
    expect(classifyNextFile('pages/api/x.test.ts')).toBeNull();
    expect(classifyNextFile('app/api/x/route.spec.ts')).toBeNull();
    expect(classifyNextFile('pages/api/x.d.ts')).toBeNull();
  });

  it('keeps the api folder in Pages segments and drops index', () => {
    expect(classifyNextFile('pages/api/x.ts')).toEqual({ kind: 'pages-api', segments: ['api', 'x'] });
    expect(classifyNextFile('src/pages/api/users/index.tsx')).toEqual({ kind: 'pages-api', segments: ['api', 'users'] });
  });

  it('recognises absolute paths for the taint module', () => {
    expect(isNextRouteHandlerPath('/home/u/proj/app/api/x/route.ts')).toBe(true);
    expect(isNextRouteHandlerPath('/home/u/proj/src/pages/api/x.ts')).toBe(true);
    expect(isNextRouteHandlerPath('/home/u/proj/lib/x.ts')).toBe(false);
    expect(isNextRouteHandlerPath('/home/u/proj/app/api/x/route.test.ts')).toBe(false);
  });
});

describe('extractNextRoutes (snippets)', () => {
  it('reports hasAuth unknown when middleware.ts exists and the handler shows no auth', () => {
    const result = extractSnippets({
      'middleware.ts': 'export function middleware() {}\n',
      'app/api/open/route.ts': 'export async function GET() { return Response.json({}); }\n',
      'app/api/closed/route.ts': 'import { auth } from "x";\nexport async function GET() { await auth(); return Response.json({}); }\n',
    });
    expect(result.routes.find((r) => r.path === '/api/open')!.hasAuth).toBe('unknown');
    expect(result.routes.find((r) => r.path === '/api/closed')!.hasAuth).toBe(true);
  });

  it('treats a wrapper with an auth-like name as auth', () => {
    const result = extractSnippets({
      'app/api/wrapped/route.ts': [
        'async function handler() { return Response.json({}); }',
        'export const GET = withAuth(handler);',
      ].join('\n'),
    });
    const route = result.routes.find((r) => r.path === '/api/wrapped')!;
    expect(route.method).toBe('GET');
    expect(route.hasAuth).toBe(true);
    expect(route.line).toBe(1);
  });

  it('resolves an export alias to a handler in another module through the import graph', () => {
    const result = extractSnippets({
      'lib/handlers.ts': 'export async function handler(req: Request) { return Response.json({ q: new URL(req.url).searchParams.get("q") }); }\n',
      'app/api/alias/route.ts': "import { handler } from '../../../lib/handlers';\nexport { handler as GET };\n",
    });
    const route = result.routes.find((r) => r.method === 'GET' && r.path === '/api/alias')!;
    expect(route).toBeDefined();
    expect(route.filePath).toBe('lib/handlers.ts');
    expect(route.params).toContainEqual({ name: 'q', in: 'query' });
  });

  it('reads query and body only with literals and without duplicates', () => {
    const result = extractSnippets({
      'app/api/search/route.ts': [
        'export async function POST(req: Request) {',
        "  const { a, b } = await req.json();",
        "  const body = await req.json();",
        "  const fd = await req.formData();",
        "  const x = fd.get('name');",
        "  const sp = new URL(req.url).searchParams;",
        "  const y = sp.get('page') ?? sp.get('page');",
        '  return Response.json({ a, b, x, y, z: body.z, w: body[\'w\'] });',
        '}',
      ].join('\n'),
    });
    const post = result.routes.find((r) => r.method === 'POST')!;
    expect(post.params).toEqual([
      { name: 'a', in: 'body' },
      { name: 'b', in: 'body' },
      { name: 'name', in: 'body' },
      { name: 'page', in: 'query' },
      { name: 'z', in: 'body' },
      { name: 'w', in: 'body' },
    ]);
  });

  it('does not treat the default export of an App Router file as a route', () => {
    const result = extractSnippets({
      'app/api/default/route.ts': 'export default function handler() {}\n',
    });
    expect(result.routes).toHaveLength(0);
  });

  it('reads Pages methods from a switch on req.method', () => {
    const result = extractSnippets({
      'pages/api/switch.ts': [
        'export default function handler(req, res) {',
        '  switch (req.method) {',
        "    case 'GET': return res.end();",
        "    case 'delete': return res.end();",
        "    case 'GET': return res.end();",
        '  }',
        '}',
      ].join('\n'),
    });
    expect(result.routes.map((r) => r.method).sort()).toEqual(['DELETE', 'GET']);
    expect(result.routes.every((r) => r.path === '/api/switch')).toBe(true);
  });

  it('lists an interception route as unresolved and emits no route for it', () => {
    const result = extractSnippets({
      'app/(.)photo/route.ts': 'export async function GET() { return Response.json({}); }\n',
    });
    expect(result.routes).toHaveLength(0);
    expect(result.unresolved).toContainEqual({
      filePath: 'app/(.)photo/route.ts',
      line: 1,
      reason: 'ruta interceptada de Next.js',
    });
  });
});

describe('next.config.* reading', () => {
  let tmp: string;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-next-'));
    fs.mkdirSync(path.join(tmp, 'app', 'api', 'x'), { recursive: true });
    fs.writeFileSync(path.join(tmp, 'app', 'api', 'x', 'route.ts'), 'export async function GET() {}\n');
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  function extractIn(root: string): ExtractionResult {
    const parser = new Parser();
    const file = path.join(root, 'app', 'api', 'x', 'route.ts');
    const parsed = parser.parseFiles([file]);
    return extractNextRoutes({ parsedFiles: parsed, graph: buildImportGraph(parsed), root });
  }

  it('reports a non-literal basePath and emits the routes without it', () => {
    fs.writeFileSync(path.join(tmp, 'next.config.js'), 'module.exports = { basePath: process.env.BASE };\n');
    const result = extractIn(tmp);
    expect([...new Set(result.routes.map((r) => r.path))]).toEqual(['/api/x']);
    expect(result.unresolved).toContainEqual({ filePath: 'next.config.*', line: 1, reason: 'basePath no literal' });
  });

  it('reports rewrites as unresolved', () => {
    fs.writeFileSync(
      path.join(tmp, 'next.config.mjs'),
      "export default { basePath: '/app', async rewrites() { return []; } };\n",
    );
    const result = extractIn(tmp);
    expect([...new Set(result.routes.map((r) => r.path))]).toEqual(['/app/api/x']);
    expect(result.unresolved).toContainEqual({
      filePath: 'next.config.*',
      line: 1,
      reason: 'rewrites de next.config no interpretados',
    });
  });
});

describe('extractNextRoutes (revisión: rutas, métodos y auth)', () => {
  const summary = (files: Record<string, string>) =>
    extractSnippets(files).routes.map((r) => `${r.method} ${r.path}`);
  const GET = 'export async function GET(req: Request) { return Response.json({}); }\n';

  it('maps the root and nested layouts of both routers', () => {
    expect(summary({ 'app/route.ts': GET })).toEqual(['GET /', 'HEAD /']);
    expect(summary({ 'src/app/api/route.ts': GET })).toEqual(['GET /api', 'HEAD /api']);
    const page = 'export default function h(req, res) { res.end(); }\n';
    expect(summary({ 'pages/api/index.ts': page })).toEqual(['GET /api']);
    expect(summary({ 'pages/api/users/index.ts': page })).toEqual(['GET /api/users']);
    expect(summary({ 'pages/api/[id].ts': page })).toEqual(['GET /api/:id']);
    expect(summary({ 'pages/api/[...all].ts': page })).toEqual(['GET /api/:all+']);
  });

  it('ignores files that are not route handlers', () => {
    expect(
      summary({
        'pages/_app.tsx': 'export default function App() { return null; }\n',
        'pages/about.tsx': 'export default function About() { return null; }\n',
        'app/page.tsx': 'export default function Page() { return null; }\n',
        'app/x/route.test.ts': GET,
        'app/x/route.d.ts': 'export declare function GET(): void;\n',
      }),
    ).toEqual([]);
  });

  it('turns %5F into a literal underscore', () => {
    expect(summary({ 'app/%5Fprivate/route.ts': GET })).toEqual(['GET /_private', 'HEAD /_private']);
  });

  it('does not duplicate HEAD, keeps DELETE and ignores lowercase exports', () => {
    const code = [
      'export function get() {}',
      'export function GET() {}',
      'export function HEAD() {}',
      'export async function DELETE() {}',
    ].join('\n');
    expect(summary({ 'app/x/route.ts': code })).toEqual(['GET /x', 'HEAD /x', 'DELETE /x']);
  });

  it('emits the methods of export const { GET, POST } = handlers (Auth.js style)', () => {
    const code = "import { handlers } from './auth';\nexport const { GET, POST } = handlers;\n";
    expect(summary({ 'app/api/auth/route.ts': code })).toEqual(['GET /api/auth', 'HEAD /api/auth', 'POST /api/auth']);
  });

  it('counts the literals of an includes() array on req.method, also negated', () => {
    const code = "export default function h(req, res) { if (!['GET', 'POST'].includes(req.method)) return res.status(405).end(); }\n";
    expect(summary({ 'pages/api/inc.ts': code })).toEqual(['GET /api/inc', 'POST /api/inc']);
  });

  it('reads || chains and defaults to GET when the handler does not compare', () => {
    const chain = "export default function h(req, res) { if (req.method === 'PUT' || req.method === 'PATCH') {} }\n";
    expect(summary({ 'pages/api/chain.ts': chain })).toEqual(['PUT /api/chain', 'PATCH /api/chain']);
    const none = 'export default function h(req, res) { res.end(); }\n';
    expect(summary({ 'pages/api/none.ts': none })).toEqual(['GET /api/none']);
  });

  it('supports export { handler as default } in Pages', () => {
    const code = "function h(req, res) { if (req.method === 'POST') {} }\nexport { h as default };\n";
    expect(summary({ 'pages/api/alias.ts': code })).toEqual(['POST /api/alias']);
  });

  it('does not report a method call on the body as a body field', () => {
    const result = extractSnippets({
      'app/x/route.ts': [
        'export async function POST(req: Request) {',
        '  const body = await req.json();',
        '  body.items.map((i) => i);',
        '  body.hasOwnProperty("z");',
        '  return Response.json(body.name);',
        '}',
      ].join('\n'),
    });
    const post = result.routes.find((r) => r.method === 'POST')!;
    expect(post.params).toEqual([
      { name: 'items', in: 'body' },
      { name: 'name', in: 'body' },
    ]);
  });

  it('reads params from (await params).x with a destructured second argument', () => {
    const result = extractSnippets({
      'app/x/route.ts': [
        'export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {',
        '  const { id } = await params;',
        '  return Response.json((await params).other);',
        '}',
      ].join('\n'),
    });
    const get = result.routes.find((r) => r.method === 'GET')!;
    expect(get.params).toEqual([
      { name: 'id', in: 'path' },
      { name: 'other', in: 'path' },
    ]);
  });

  it('only counts a middleware.ts at the root or under src/', () => {
    const nested = extractSnippets({
      'app/api/x/middleware.ts': 'export {};\n',
      'app/api/x/route.ts': GET,
    });
    expect(nested.routes.every((r) => r.hasAuth === false)).toBe(true);
    const underSrc = extractSnippets({ 'src/middleware.ts': 'export {};\n', 'src/app/api/x/route.ts': GET });
    expect(underSrc.routes.every((r) => r.hasAuth === 'unknown')).toBe(true);
  });

  it('does not take store.getToken() or db.getSession() for auth', () => {
    const code = 'export async function GET() { const t = store.getToken(); const s = db.getSession(); return Response.json({ t, s }); }\n';
    const result = extractSnippets({ 'app/api/x/route.ts': code });
    expect(result.routes.every((r) => r.hasAuth === false)).toBe(true);
  });
});

describe('next.config.* reading (revisión)', () => {
  let tmp: string;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-next-rev-'));
    fs.mkdirSync(path.join(tmp, 'app', 'x'), { recursive: true });
    fs.writeFileSync(path.join(tmp, 'app', 'x', 'route.ts'), 'export async function GET() {}\n');
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  function run(configName: string, config: string): ExtractionResult {
    fs.writeFileSync(path.join(tmp, configName), config);
    const parsed = new Parser().parseFiles([path.join(tmp, 'app', 'x', 'route.ts')]);
    return extractNextRoutes({ parsedFiles: parsed, graph: buildImportGraph(parsed), root: tmp });
  }
  const paths = (r: ExtractionResult) => [...new Set(r.routes.map((x) => x.path))];

  it('ignores basePath inside comments and inside strings of other keys', () => {
    const lineComment = run('next.config.js', "// basePath: '/x'\nmodule.exports = {};\n");
    expect(paths(lineComment)).toEqual(['/x']);
    expect(lineComment.unresolved).toEqual([]);

    const blockComment = run('next.config.js', "/* basePath: '/zz' */\nmodule.exports = {};\n");
    expect(paths(blockComment)).toEqual(['/x']);

    const inString = run('next.config.js', "module.exports = { assetPrefix: \"see basePath: '/zz'\" };\n");
    expect(paths(inString)).toEqual(['/x']);
    expect(inString.unresolved).toEqual([]);
  });

  it('does not report rewrites that only appear in a comment', () => {
    const result = run('next.config.js', "// TODO rewrites later\nmodule.exports = { basePath: '/b' };\n");
    expect(paths(result)).toEqual(['/b/x']);
    expect(result.unresolved).toEqual([]);
  });

  it('reads next.config.ts with export default and normalizes a trailing slash', () => {
    expect(paths(run('next.config.ts', "export default { basePath: '/docs' } satisfies object;\n"))).toEqual(['/docs/x']);
    fs.rmSync(path.join(tmp, 'next.config.ts'));
    expect(paths(run('next.config.mjs', 'export default { basePath: "/docs/" };\n'))).toEqual(['/docs/x']);
  });

  it('sends a shorthand or constant basePath to unresolved instead of guessing', () => {
    const result = run('next.config.js', "const basePath = '/x';\nmodule.exports = {\n  basePath,\n};\n");
    expect(paths(result)).toEqual(['/x']);
    expect(result.unresolved).toContainEqual({ filePath: 'next.config.*', line: 3, reason: 'basePath no literal' });
  });

  it('treats an empty basePath as no basePath without noise', () => {
    const result = run('next.config.js', "module.exports = { basePath: '' };\n");
    expect(paths(result)).toEqual(['/x']);
    expect(result.unresolved).toEqual([]);
  });

  it('survives an unreadable next.config (a directory) and emits routes without basePath', () => {
    fs.mkdirSync(path.join(tmp, 'next.config.js'));
    const parsed = new Parser().parseFiles([path.join(tmp, 'app', 'x', 'route.ts')]);
    const result = extractNextRoutes({ parsedFiles: parsed, graph: buildImportGraph(parsed), root: tmp });
    expect(paths(result)).toEqual(['/x']);
  });
});
