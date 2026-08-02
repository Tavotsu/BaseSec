import { describe, it, expect } from 'vitest';
import { findSources } from '../../src/taint/source';
import { createSourceFile } from '../helpers';

describe('findSources', () => {
  it('detects express sources', () => {
    const code = `
      const x = req.body;
      const y = req.query.id;
      const z = req.params;
    `;
    const sourceFile = createSourceFile(code);
    const sources = findSources(sourceFile, code, ['express']);
    
    expect(sources).toHaveLength(7);
    expect(sources.find(s => s.kind === 'req.body')).toBeDefined();
    expect(sources.find(s => s.kind === 'req.query')).toBeDefined();
    expect(sources.find(s => s.kind === 'req.params')).toBeDefined();
  });

  it('detects fastify sources', () => {
    const code = `
      const x = request.body;
      const y = request.headers;
    `;
    const sourceFile = createSourceFile(code);
    const sources = findSources(sourceFile, code, ['fastify']);
    
    expect(sources).toHaveLength(4);
    expect(sources.find(s => s.kind === 'request.body')).toBeDefined();
    expect(sources.find(s => s.kind === 'request.headers')).toBeDefined();
  });

  it('detects koa sources', () => {
    const code = `
      const x = ctx.request.body;
      const y = ctx.query;
    `;
    const sourceFile = createSourceFile(code);
    const sources = findSources(sourceFile, code, ['koa']);
    
    expect(sources).toHaveLength(4);
    expect(sources.find(s => s.kind === 'ctx.request.body')).toBeDefined();
    expect(sources.find(s => s.kind === 'ctx.query')).toBeDefined();
  });

  it('detects nestjs decorator sources', () => {
    const code = `
      function getUser(@Body() body: any, @Query() query: any) {}
    `;
    const sourceFile = createSourceFile(code);
    const sources = findSources(sourceFile, code, ['nestjs']);
    
    expect(sources).toHaveLength(2);
    expect(sources.find(s => s.variableName === 'body')).toBeDefined();
    expect(sources.find(s => s.variableName === 'query')).toBeDefined();
  });

  it('filters by framework', () => {
    const code = `
      const x = req.body;
      const y = request.body;
    `;
    const sourceFile = createSourceFile(code);
    const expressSources = findSources(sourceFile, code, ['express']);

    expect(expressSources).toHaveLength(2);
    expect(expressSources[0].kind).toBe('req.body');
  });

  it('detects browser-global sources for any framework', () => {
    const code = 'const bio = location.search; const c = document.cookie;';
    const sourceFile = createSourceFile(code);
    const sources = findSources(sourceFile, code, ['react']);
    expect(sources.find(s => s.kind === 'location.search')).toBeDefined();
    expect(sources.find(s => s.kind === 'document.cookie')).toBeDefined();
  });

  it('gates React hook sources to react/nextjs', () => {
    const code = 'const params = useSearchParams();';
    const sourceFile = createSourceFile(code);
    expect(findSources(sourceFile, code, ['react']).find(s => s.variableName === 'params')).toBeDefined();
    expect(findSources(sourceFile, code, ['express']).find(s => s.variableName === 'params')).toBeUndefined();
  });

  it('does not double-register React hooks when nextjs implies react', () => {
    const code = 'const q = useSearchParams().get("q");';
    const sourceFile = createSourceFile(code);
    const react = findSources(sourceFile, code, ['react']);
    const nextjs = findSources(sourceFile, code, ['react', 'nextjs']);
    expect(nextjs).toHaveLength(react.length);
  });

  it('does not add browser sources to a pure backend scan', () => {
    const code = 'const x = req.body;';
    const sourceFile = createSourceFile(code);
    const sources = findSources(sourceFile, code, ['express']);
    expect(sources.every(s => !s.kind.startsWith('location') && !s.kind.startsWith('document'))).toBe(true);
  });
});
