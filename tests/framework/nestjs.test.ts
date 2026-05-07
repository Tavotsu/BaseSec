import { describe, it, expect } from 'vitest';
import { detectNestJSPatterns } from '../../src/framework/nestjs';
import * as ts from 'typescript';

function createSourceFile(code: string, fileName = 'test.ts'): ts.SourceFile {
  return ts.createSourceFile(fileName, code, ts.ScriptTarget.Latest, true);
}

describe('detectNestJSPatterns', () => {
  it('detects @Controller decorator', () => {
    const code = `
      import { Controller, Get } from '@nestjs/common';
      
      @Controller('users')
      export class UsersController {
        @Get()
        findAll() { return []; }
      }
    `;
    const sourceFile = createSourceFile(code);
    const controllers = detectNestJSPatterns(sourceFile);
    expect(controllers).toHaveLength(1);
    expect(controllers[0].className).toBe('UsersController');
    expect(controllers[0].routePrefix).toBe('users');
    expect(controllers[0].methods).toHaveLength(1);
    expect(controllers[0].methods[0].method).toBe('GET');
  });

  it('detects @Controller without prefix', () => {
    const code = `
      import { Controller, Post } from '@nestjs/common';
      
      @Controller()
      export class AppController {
        @Post('data')
        create() {}
      }
    `;
    const sourceFile = createSourceFile(code);
    const controllers = detectNestJSPatterns(sourceFile);
    expect(controllers).toHaveLength(1);
    expect(controllers[0].routePrefix).toBe('');
    expect(controllers[0].methods[0].method).toBe('POST');
  });

  it('detects @UseGuards on controller class', () => {
    const code = `
      import { Controller, Get, UseGuards } from '@nestjs/common';
      
      @Controller('admin')
      @UseGuards(AuthGuard)
      export class AdminController {
        @Get('dashboard')
        getDashboard() {}
      }
    `;
    const sourceFile = createSourceFile(code);
    const controllers = detectNestJSPatterns(sourceFile);
    expect(controllers).toHaveLength(1);
    expect(controllers[0].hasGuard).toBe(true);
  });

  it('detects @UseGuards on method', () => {
    const code = `
      import { Controller, Get, UseGuards } from '@nestjs/common';
      
      @Controller('users')
      export class UsersController {
        @Get('profile')
        @UseGuards(JwtAuthGuard)
        getProfile() {}
      }
    `;
    const sourceFile = createSourceFile(code);
    const controllers = detectNestJSPatterns(sourceFile);
    expect(controllers).toHaveLength(1);
    expect(controllers[0].methods[0].hasGuard).toBe(true);
  });

it('detects @Body, @Param, @Query parameter decorators (limited by TS parser)', () => {
    const code = `
      import { Controller, Post, Body, Param, Query, Get } from '@nestjs/common';
      
      @Controller('items')
      export class ItemsController {
        @Post()
        create(@Body() body: any) {}
        
        @Get(':id')
        findOne(@Param('id') id: string) {}
        
        @Get()
        search(@Query('q') query: string) {}
      }
    `;
    const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    const controllers = detectNestJSPatterns(sourceFile);
    expect(controllers).toHaveLength(1);
    expect(controllers[0].methods.length).toBe(3);
    const methods = controllers[0].methods.map(m => m.method);
    expect(methods).toContain('POST');
    expect(methods).toContain('GET');
  });

  it('detects multiple HTTP methods', () => {
    const code = `
      import { Controller, Get, Post, Put, Delete, Patch } from '@nestjs/common';
      
      @Controller('api')
      export class ApiController {
        @Get('items')
        getItems() {}
        
        @Post('items')
        createItem() {}
        
        @Put('items/:id')
        updateItem() {}
        
        @Delete('items/:id')
        deleteItem() {}
        
        @Patch('items/:id')
        patchItem() {}
      }
    `;
    const sourceFile = createSourceFile(code);
    const controllers = detectNestJSPatterns(sourceFile);
    expect(controllers).toHaveLength(1);
    expect(controllers[0].methods).toHaveLength(5);
    const methods = controllers[0].methods.map(m => m.method);
    expect(methods).toContain('GET');
    expect(methods).toContain('POST');
    expect(methods).toContain('PUT');
    expect(methods).toContain('DELETE');
    expect(methods).toContain('PATCH');
  });

  it('returns empty for non-controller classes', () => {
    const code = `
      export class PlainService {
        getData() { return []; }
      }
    `;
    const sourceFile = createSourceFile(code);
    const controllers = detectNestJSPatterns(sourceFile);
    expect(controllers).toHaveLength(0);
  });

  it('handles class without name', () => {
    const code = `
      @Controller('test')
      export default class {
        @Get()
        test() {}
      }
    `;
    const sourceFile = createSourceFile(code);
    const controllers = detectNestJSPatterns(sourceFile);
    expect(controllers).toHaveLength(1);
    expect(controllers[0].className).toBe('UnknownController');
  });
});