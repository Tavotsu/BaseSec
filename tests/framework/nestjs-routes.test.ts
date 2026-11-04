import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Parser } from '../../src/core/parser';
import { buildImportGraph } from '../../src/core/import-graph';
import { extractNestRoutes } from '../../src/framework/routes/nestjs-routes';
import type { ExtractionResult } from '../../src/framework/routes/types';
import type { ParsedFile } from '../../src/rules/types';

const FIXTURE = fileURLToPath(new URL('../fixtures/nest-src', import.meta.url));
const VIRTUAL_ROOT = path.resolve('/virtual/nest');

function walk(dir: string, out: string[] = []): string[] {
  for (const name of fs.readdirSync(dir)) {
    const full = path.join(dir, name);
    if (fs.statSync(full).isDirectory()) walk(full, out);
    else if (/\.ts$/.test(name)) out.push(full);
  }
  return out;
}

function extractFromFixture(): ExtractionResult {
  const parsed = new Parser().parseFiles(walk(FIXTURE));
  return extractNestRoutes({ parsedFiles: parsed, graph: buildImportGraph(parsed), root: FIXTURE });
}

function extractSnippets(files: Record<string, string>): ExtractionResult {
  const parser = new Parser();
  const parsed: ParsedFile[] = Object.entries(files).map(([rel, code]) => {
    const result = parser.parseContent(path.join(VIRTUAL_ROOT, rel), code);
    if (!('sourceFile' in result)) throw new Error(result.error);
    return result;
  });
  return extractNestRoutes({ parsedFiles: parsed, graph: buildImportGraph(parsed), root: VIRTUAL_ROOT });
}

describe('extractNestRoutes (nest-src fixture)', () => {
  const result = extractFromFixture();
  const find = (method: string, routePath: string) =>
    result.routes.find((r) => r.method === method && r.path === routePath);

  it('applies the global prefix and the controller prefix: GET /v1/users/:id', () => {
    const route = find('GET', '/v1/users/:id');
    expect(route).toBeDefined();
    expect(route!.framework).toBe('nestjs');
    expect(route!.filePath).toBe('users/users.controller.ts');
    expect(route!.params).toContainEqual({ name: 'id', in: 'path' });
  });

  it('reads body params from the DTO class with their types: POST /v1/users', () => {
    const route = find('POST', '/v1/users');
    expect(route).toBeDefined();
    expect(route!.params).toEqual([
      { name: 'email', in: 'body', type: 'string' },
      { name: 'age', in: 'body', type: 'number' },
    ]);
  });

  it('reads @Query with its literal name and type', () => {
    const route = find('GET', '/v1/users/search');
    expect(route!.params).toEqual([{ name: 'page', in: 'query', type: 'number' }]);
  });

  it('marks a route with @UseGuards as authenticated', () => {
    expect(find('DELETE', '/v1/users/:id')!.hasAuth).toBe(true);
  });

  it('supports @Controller({ path }) object form', () => {
    expect(find('GET', '/v1/admin/stats')).toBeDefined();
  });

  it('reports a global prefix that is not a literal', () => {
    const unresolved = extractSnippets({
      'main.ts': `
        const app = await NestFactory.create(AppModule);
        app.setGlobalPrefix(PREFIX);
      `,
      'c.ts': `
        @Controller('x')
        class C { @Get('a') a() {} }
      `,
    });
    expect(unresolved.unresolved).toContainEqual(expect.objectContaining({ reason: 'prefijo global no literal' }));
    expect(unresolved.routes.map((r) => r.path)).toEqual(['/x/a']);
  });
});

describe('extractNestRoutes (snippets)', () => {
  it('marks routes as unknown under a global guard without @UseGuards', () => {
    const result = extractSnippets({
      'main.ts': 'app.useGlobalGuards(new AuthGuard());',
      'c.ts': `
        @Controller('x')
        class C {
          @Get('a') a() {}
          @Get('b') @Public() b() {}
          @Get('c') @UseGuards(RoleGuard) c() {}
        }
      `,
    });
    const byPath = Object.fromEntries(result.routes.map((r) => [r.path, r.hasAuth]));
    expect(byPath['/x/a']).toBe('unknown');
    expect(byPath['/x/b']).toBe(false);
    expect(byPath['/x/c']).toBe(true);
  });

  it('treats a global guard provided through APP_GUARD the same way', () => {
    const result = extractSnippets({
      'app.module.ts': `
        @Module({ providers: [{ provide: APP_GUARD, useClass: AuthGuard }] })
        class AppModule {}
      `,
      'c.ts': `
        @Controller('x')
        class C { @Get('a') a() {} }
      `,
    });
    expect(result.routes[0].hasAuth).toBe('unknown');
  });

  it('reports a controller prefix that is not a literal, for each method', () => {
    const result = extractSnippets({
      'c.ts': `
        @Controller(PREFIX)
        class C {
          @Get('a') a() {}
          @Post('b') b() {}
        }
      `,
    });
    expect(result.routes).toEqual([]);
    expect(result.unresolved.filter((u) => u.reason === 'prefijo de controller no literal')).toHaveLength(2);
  });

  it('reports a route path that is not a literal', () => {
    const result = extractSnippets({
      'c.ts': `
        @Controller('x')
        class C { @Get(SEGMENT) a() {} }
      `,
    });
    expect(result.routes).toEqual([]);
    expect(result.unresolved).toContainEqual(expect.objectContaining({ reason: 'path no literal' }));
  });
});
