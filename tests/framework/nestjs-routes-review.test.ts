import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { Parser } from '../../src/core/parser';
import { buildImportGraph } from '../../src/core/import-graph';
import { extractNestRoutes } from '../../src/framework/routes/nestjs-routes';
import type { ExtractionResult } from '../../src/framework/routes/types';
import type { ParsedFile } from '../../src/rules/types';

const ROOT = path.resolve('/virtual/nest-review');

function extract(files: Record<string, string>): ExtractionResult {
  const parser = new Parser();
  const parsed: ParsedFile[] = Object.entries(files).map(([rel, code]) => {
    const result = parser.parseContent(path.join(ROOT, rel), code);
    if (!('sourceFile' in result)) throw new Error(result.error);
    return result;
  });
  return extractNestRoutes({ parsedFiles: parsed, graph: buildImportGraph(parsed), root: ROOT });
}

const pairs = (r: ExtractionResult): string[] => r.routes.map((x) => `${x.method} ${x.path}`).sort();

describe('Nest controller prefixes and method paths', () => {
  it('multiplies array prefixes by array method paths; @Get() without args is the prefix', () => {
    const r = extract({
      'c.ts': `
        @Controller(['a', 'b'])
        export class C {
          @Get() list() {}
          @Get(['x', 'y']) many() {}
        }
      `,
    });
    expect(pairs(r)).toEqual(['GET /a', 'GET /a/x', 'GET /a/y', 'GET /b', 'GET /b/x', 'GET /b/y']);
  });

  it('ignores version and host in @Controller({ path, version, host })', () => {
    const r = extract({
      'c.ts': `
        @Controller({ path: 'items', version: '2', host: 'api.example.com' })
        export class C {
          @Get(':id') one() {}
        }
      `,
    });
    expect(pairs(r)).toEqual(['GET /items/:id']);
  });

  it('an object @Controller without path is the root, with an array path gives several', () => {
    const r = extract({
      'c.ts': `
        @Controller({ version: '1' })
        export class A { @Get('a') a() {} }
        @Controller({ path: ['p', 'q'] })
        export class B { @Get() b() {} }
      `,
    });
    expect(pairs(r)).toEqual(['GET /a', 'GET /p', 'GET /q']);
  });

  it('sends wildcard paths to unresolved as "path con patrón"', () => {
    const r = extract({
      'c.ts': `
        @Controller('w')
        export class C {
          @All('*') any() {}
          @Get('ab*cd') star() {}
          @Get('ok') ok() {}
        }
      `,
    });
    expect(pairs(r)).toEqual(['GET /w/ok']);
    expect(r.unresolved.filter((u) => u.reason === 'path con patrón')).toHaveLength(2);
  });

  it('does not apply the global prefix to routes in setGlobalPrefix exclude', () => {
    const r = extract({
      'main.ts': `
        app.setGlobalPrefix('api', { exclude: [{ path: 'health', method: RequestMethod.GET }, 'status'] });
      `,
      'c.ts': `
        @Controller()
        export class C {
          @Get('health') h() {}
          @Post('health') p() {}
          @Get('status') s() {}
          @Get('other') o() {}
        }
      `,
    });
    expect(pairs(r)).toEqual(['GET /health', 'GET /status', 'GET /api/other', 'POST /api/health'].sort());
  });
});

describe('Nest auth', () => {
  it('detects a global guard via APP_GUARD in the providers of a module', () => {
    const r = extract({
      'app.module.ts': `
        @Module({
          providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }],
        })
        export class AppModule {}
      `,
      'c.ts': `
        @Controller('u')
        export class C {
          @Get('a') a() {}
          @Public() @Get('b') b() {}
          @UseGuards(Other) @Get('c') c() {}
        }
      `,
    });
    const by = Object.fromEntries(r.routes.map((x) => [x.path, x.hasAuth]));
    expect(by).toEqual({ '/u/a': 'unknown', '/u/b': false, '/u/c': true });
  });

  it('honors @Public() at class level with a global guard, and @UseGuards at class level', () => {
    const r = extract({
      'app.module.ts': `
        @Module({ providers: [{ provide: APP_GUARD, useClass: G }] })
        export class AppModule {}
      `,
      'c.ts': `
        @Public()
        @Controller('pub')
        export class Pub { @Get() a() {} }

        @UseGuards(AuthGuard)
        @Controller('priv')
        export class Priv { @Get() a() {} }
      `,
    });
    const by = Object.fromEntries(r.routes.map((x) => [x.path, x.hasAuth]));
    expect(by).toEqual({ '/pub': false, '/priv': true });
  });

  it('without a global guard unguarded routes are false', () => {
    const r = extract({
      'c.ts': `
        @Controller('z')
        export class C { @Get() a() {} }
      `,
    });
    expect(r.routes[0].hasAuth).toBe(false);
  });
});

describe('Nest DTOs', () => {
  it('includes optional properties and class-validator decorated ones, with simple types', () => {
    const r = extract({
      'dto.ts': `
        export class CreateDto {
          @IsEmail() email: string;
          @IsOptional() @IsInt() age?: number;
          @IsBoolean() active: boolean;
          tags: string[];
          static ignored = 1;
          method() {}
        }
      `,
      'c.ts': `
        @Controller('d')
        export class C {
          @Post() create(@Body() dto: CreateDto) {}
        }
      `,
    });
    expect(r.routes[0].params).toEqual([
      { name: 'email', in: 'body', type: 'string' },
      { name: 'age', in: 'body', type: 'number' },
      { name: 'active', in: 'body', type: 'boolean' },
      { name: 'tags', in: 'body' },
    ]);
  });

  it('adds nothing when two classes share the DTO name', () => {
    const r = extract({
      'a.ts': 'export class Dup { a: string; }',
      'b.ts': 'export class Dup { b: string; }',
      'c.ts': `
        @Controller('d')
        export class C {
          @Post() create(@Body() dto: Dup) {}
          @Get() list(@Query() q: Missing) {}
        }
      `,
    });
    expect(r.routes.every((x) => x.params.length === 0)).toBe(true);
  });

  it('inherits properties from a unique base class and survives inheritance cycles', () => {
    const r = extract({
      'dto.ts': `
        class Base { id: number; }
        export class Child extends Base { name: string; }
        class LoopA extends LoopB { a: string; }
        class LoopB extends LoopA { b: string; }
      `,
      'c.ts': `
        @Controller('d')
        export class C {
          @Post() one(@Body() dto: Child) {}
          @Put() two(@Body() dto: LoopA) {}
        }
      `,
    });
    const post = r.routes.find((x) => x.method === 'POST')!;
    expect(post.params.map((p) => p.name)).toEqual(['name', 'id']);
    const put = r.routes.find((x) => x.method === 'PUT')!;
    expect(put.params.map((p) => p.name).sort()).toEqual(['a', 'b']);
  });
});
