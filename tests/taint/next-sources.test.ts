import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { findSources } from '../../src/taint/source';
import { analyzeFile } from '../../src/taint/engine';
import { Parser } from '../../src/core/parser';
import { createSourceFile } from '../helpers';

const ROUTE = '/virtual/app/app/api/x/route.ts';
const PAGES = '/virtual/app/pages/api/x.ts';
const LIB = '/virtual/app/lib/x.ts';
const FIXTURE = fileURLToPath(new URL('../fixtures/next-src', import.meta.url));

const ROUTE_CODE = `
import { cookies } from 'next/headers';
export async function POST(req: NextRequest, { params }: { params: { id: string } }) {
  const { email } = await req.json();
  const q = req.nextUrl.searchParams.get('q');
  const id = params.id;
  const session = cookies().get('session');
  return null;
}
`;

const LOCAL_COOKIES_CODE = `
function cookies() { return { get: (name: string) => name }; }
export async function GET(req: Request) {
  const session = cookies().get('session');
  return null;
}
`;

const HANDLER_BODY = `
export async function GET(req: Request) {
  const body = await req.json();
  const q = req.nextUrl.searchParams.get('q');
  return null;
}
`;

const PAGES_CODE = `
export default function handler(req, res) {
  const id = req.query.id;
  res.send(id);
}
`;

function kinds(sources: { kind: string }[]): string[] {
  return sources.map((s) => s.kind).filter((k) => k.startsWith('next:'));
}

describe('findNextServerSources through findSources (App Router)', () => {
  const sources = findSources(createSourceFile(ROUTE_CODE, ROUTE), ROUTE_CODE, ['nextjs', 'react']);

  it('marks await req.json() as a variable source', () => {
    const email = sources.find((s) => s.variableName === 'email');
    expect(email).toBeDefined();
    expect(email!.kind).toBe('next:request.json');
  });

  it('marks request.nextUrl.searchParams reads as a search-params source', () => {
    const q = sources.find((s) => s.variableName === 'q');
    expect(q).toBeDefined();
    expect(q!.kind).toBe('next:searchParams');
    expect(q!.expression).toBe("req.nextUrl.searchParams.get('q')");
  });

  it('marks params.id from a destructured second parameter', () => {
    const id = sources.find((s) => s.expression === 'params.id');
    expect(id).toBeDefined();
    expect(id!.kind).toBe('next:params');
    expect(sources.find((s) => s.variableName === 'id')).toBeDefined();
  });

  it('marks cookies() only because it is imported from next/headers', () => {
    const session = sources.find((s) => s.variableName === 'session');
    expect(session).toBeDefined();
    expect(session!.kind).toBe('next:cookies');
  });

  it('keeps line and column 1-based', () => {
    const q = sources.find((s) => s.variableName === 'q')!;
    expect(q.line).toBe(5);
    expect(q.column).toBeGreaterThan(0);
  });

  it('does not mark cookies() when it is a local function', () => {
    const local = findSources(createSourceFile(LOCAL_COOKIES_CODE, ROUTE), LOCAL_COOKIES_CODE, ['nextjs', 'react']);
    expect(kinds(local).filter((k) => k === 'next:cookies')).toHaveLength(0);
  });

  it('does not add sources to a route handler when nextjs is not detected', () => {
    const withoutNext = findSources(createSourceFile(HANDLER_BODY, ROUTE), HANDLER_BODY, ['react']);
    expect(kinds(withoutNext)).toEqual([]);
  });
});

describe('findSources outside route handlers', () => {
  it('returns exactly what it returns without nextjs for a file that is not a route handler', () => {
    const withNext = findSources(createSourceFile(HANDLER_BODY, LIB), HANDLER_BODY, ['nextjs', 'react']);
    const withoutNext = findSources(createSourceFile(HANDLER_BODY, LIB), HANDLER_BODY, ['react']);
    expect(withNext).toEqual(withoutNext);
  });
});

describe('findSources with Express and Next.js together', () => {
  it('reports req.query once for a Pages handler when express is also detected', () => {
    const withNext = findSources(createSourceFile(PAGES_CODE, PAGES), PAGES_CODE, ['nextjs', 'express']);
    const expressOnly = findSources(createSourceFile(PAGES_CODE, PAGES), PAGES_CODE, ['express']);

    const positions = withNext.map((s) => `${s.expression}|${s.line}|${s.column}`);
    expect(new Set(positions).size).toBe(positions.length);
    expect(withNext.filter((s) => s.expression === 'req.query.id')).toEqual(
      expressOnly.filter((s) => s.expression === 'req.query.id'),
    );
  });
});

describe('taint engine with Next.js sources', () => {
  it('links the GET handler of the fixture to the SQL sink', () => {
    const file = path.join(FIXTURE, 'app', 'api', 'users', 'route.ts');
    const [parsed] = new Parser().parseFiles([file]);
    const graph = analyzeFile(parsed, ['nextjs', 'react'], []);

    const sqlFlow = graph.flows.find((f) => f.sink.category === 'sql-injection' && f.source.kind.startsWith('next:'));
    expect(sqlFlow).toBeDefined();
    expect(sqlFlow!.source.variableName).toBe('q');
    expect(sqlFlow!.source.kind).toBe('next:searchParams');
    expect(sqlFlow!.sink.line).toBe(fs.readFileSync(file, 'utf-8').split('\n').findIndex((l) => l.includes('db.query')) + 1);
  });

  it('links await req.json() to a SQL template literal in a POST handler', () => {
    const code = [
      'export async function POST(req) {',
      '  const { email } = await req.json();',
      '  await db.query(`INSERT INTO users (email) VALUES (\'${email}\')`);',
      '  return null;',
      '}',
    ].join('\n');
    const parsed = new Parser().parseContent(ROUTE, code);
    if (!('sourceFile' in parsed)) throw new Error(parsed.error);
    const graph = analyzeFile(parsed, ['nextjs'], []);
    const flow = graph.flows.find((f) => f.source.variableName === 'email');
    expect(flow).toBeDefined();
    expect(flow!.source.kind).toBe('next:request.json');
    expect(flow!.sink.line).toBe(3);
  });
});

describe('Next.js sources: names, exports and propagation (revisión)', () => {
  const sourcesOf = (code: string, file = ROUTE) =>
    findSources(createSourceFile(code, file), code, ['nextjs', 'react']);
  const vars = (code: string, file = ROUTE) =>
    sourcesOf(code, file)
      .filter((s) => s.variableName !== undefined)
      .map((s) => s.variableName);

  it('uses the real parameter names of the handler', () => {
    expect(vars("export async function GET(request) { const a = request.headers.get('a'); }")).toEqual(['a']);
    expect(vars('export async function GET(r: NextRequest) { const u = r.url; }')).toEqual(['u']);
    expect(vars('export async function POST(_req, ctx) { const id = ctx.params.id; const b = await _req.json(); }')).toEqual([
      'id',
      'b',
    ]);
    // `req` no es el parámetro: no hay fuente aunque el nombre coincida con el habitual.
    expect(vars('export async function GET(request) { const a = req.url; }')).toEqual([]);
  });

  it('supports const arrow handlers, export { x as GET } and wrappers', () => {
    expect(vars('export const GET = async (req) => { const b = await req.json(); };')).toEqual(['b']);
    expect(vars('async function h(req) { const b = await req.json(); }\nexport { h as GET };')).toEqual(['b']);
    expect(vars('export const GET = withAuth(async (req) => { const b = await req.json(); });')).toEqual(['b']);
  });

  it('does not mark accesses in a function that is not an exported handler', () => {
    const code = [
      'async function helper(req) { const b = await req.json(); const q = req.nextUrl.searchParams.get("q"); }',
      'export async function GET() { return null; }',
    ].join('\n');
    expect(sourcesOf(code)).toEqual([]);
    const pages = 'function handler(req, res) { const { q } = req.query; }\nexport const config = {};';
    expect(sourcesOf(pages, PAGES)).toEqual([]);
  });

  it('marks export { handler as default } in Pages', () => {
    const code = 'function handler(req, res) { const { q } = req.query; }\nexport { handler as default };';
    expect(vars(code, PAGES)).toEqual(['q']);
  });

  it('marks params read through await in the destructured second parameter', () => {
    const code = [
      'export async function GET(req, { params }) {',
      '  const { slug } = await params;',
      '  const other = (await params).k;',
      '}',
    ].join('\n');
    expect(vars(code)).toEqual(['slug', 'other']);
  });

  it('accepts cookies/headers with an alias from next/headers only', () => {
    const aliased = "import { cookies as c } from 'next/headers';\nexport async function GET(req) { const t = c().get('t'); }";
    expect(vars(aliased)).toEqual(['t']);
    const foreign = "import { cookies } from './mine';\nexport async function GET(req) { const t = cookies().get('t'); }";
    expect(sourcesOf(foreign)).toEqual([]);
    const local = 'const cookies = () => ({ get() {} });\nexport async function GET(req) { const t = cookies().get("t"); }';
    expect(sourcesOf(local)).toEqual([]);
  });

  it('propagates through derived variables but not to unrelated ones', () => {
    const code = [
      'export async function POST(req) {',
      '  const body = await req.json();',
      '  const name = body.name;',
      "  const label = body.name ?? 'x';",
      '  const text = `${body.name}!`;',
      '  const flag = body.count === 1;',
      '  const safe = sanitize(body.name);',
      "  const fixed = 'constant';",
      '  let late;',
      '  late = name;',
      '}',
    ].join('\n');
    expect(vars(code)).toEqual(['body', 'name', 'label', 'text', 'late']);
  });

  it('propagates from a headers() object to values read from it', () => {
    const code = [
      "import { headers } from 'next/headers';",
      'export async function GET(req) {',
      '  const h = await headers();',
      "  const ua = h.get('user-agent');",
      '}',
    ].join('\n');
    expect(vars(code)).toEqual(['h', 'ua']);
  });

  it('marks nested destructuring targets', () => {
    const code = 'export async function POST(req) { const { user: { id }, tags: [first] } = await req.json(); }';
    expect(vars(code)).toEqual(['id', 'first']);
  });

  it('terminates on cyclic assignments', () => {
    const code = 'export async function POST(req) { let a = b; let b = a; a = b; b = a; const c = await req.json(); }';
    expect(vars(code)).toEqual(['c']);
  });

  it('does not link a sink to a same-named variable declared in a later handler', () => {
    const code = [
      'export async function GET(req) {',
      '  const id = "1";',
      '  await db.query(`SELECT * FROM t WHERE id = ${id}`);',
      '}',
      'export async function POST(req) {',
      '  const { id } = await req.json();',
      '  return null;',
      '}',
    ].join('\n');
    const parsed = new Parser().parseContent(ROUTE, code);
    if (!('sourceFile' in parsed)) throw new Error(parsed.error);
    const graph = analyzeFile(parsed, ['nextjs'], []);
    expect(graph.flows.filter((f) => f.source.kind.startsWith('next:'))).toEqual([]);
  });

  it('matches a destructured variable by word, not by substring, in the sink line', () => {
    const code = [
      'export async function POST(req) {',
      '  const { id } = await req.json();',
      '  await db.query("SELECT valid FROM t WHERE ok = 1");',
      '  await db.query(`SELECT * FROM t WHERE k = ${id}`);',
      '}',
    ].join('\n');
    const parsed = new Parser().parseContent(ROUTE, code);
    if (!('sourceFile' in parsed)) throw new Error(parsed.error);
    const flows = analyzeFile(parsed, ['nextjs'], []).flows.filter((f) => f.source.kind.startsWith('next:'));
    expect(flows.map((f) => f.sink.line)).toEqual([4]);
  });
});
