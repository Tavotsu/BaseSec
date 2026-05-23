import { describe, it, expect } from 'vitest';
import { findSinks } from '../../src/taint/sink';
import { createSourceFile } from '../helpers';

describe('findSinks', () => {
  it('detects standalone dangerous functions', () => {
    const code = `
      exec(userInput);
      eval(code);
      spawn('cmd', args);
    `;
    const sourceFile = createSourceFile(code);
    const sinks = findSinks(sourceFile);
    
    expect(sinks).toHaveLength(3);
    expect(sinks.find(s => s.functionName === 'exec')).toBeDefined();
    expect(sinks.find(s => s.functionName === 'eval')).toBeDefined();
    expect(sinks.find(s => s.functionName === 'spawn')).toBeDefined();
  });

  it('detects property access dangerous methods', () => {
    const code = `
      db.query(sql);
      res.send(data);
      res.redirect(url);
      jwt.sign(payload, secret);
    `;
    const sourceFile = createSourceFile(code);
    const sinks = findSinks(sourceFile);
    
    expect(sinks).toHaveLength(4);
    expect(sinks.find(s => s.functionName === 'db.query')).toBeDefined();
    expect(sinks.find(s => s.functionName === 'res.send')).toBeDefined();
    expect(sinks.find(s => s.functionName === 'res.redirect')).toBeDefined();
    expect(sinks.find(s => s.functionName === 'jwt.sign')).toBeDefined();
  });

  it('ignores methods on non-dangerous receivers', () => {
    const code = `
      user.send('hello');
      array.find(x => x);
      url.redirect;
    `;
    const sourceFile = createSourceFile(code);
    const sinks = findSinks(sourceFile);
    
    expect(sinks).toHaveLength(0);
  });

  it('detects fastify and koa response sinks', () => {
    const code = `
      reply.send(data);
      ctx.body = data;
      ctx.redirect(url);
    `;
    const sourceFile = createSourceFile(code);
    const sinks = findSinks(sourceFile);
    
    expect(sinks.find(s => s.functionName === 'reply.send')).toBeDefined();
    expect(sinks.find(s => s.functionName === 'ctx.redirect')).toBeDefined();
  });

  it('detects prisma raw queries', () => {
    const code = `
      prisma.$queryRaw(sql);
      db.$executeRawUnsafe(sql);
    `;
    const sourceFile = createSourceFile(code);
    const sinks = findSinks(sourceFile);
    
    expect(sinks).toHaveLength(2);
    expect(sinks.find(s => s.functionName === 'prisma.$queryRaw')).toBeDefined();
    expect(sinks.find(s => s.functionName === 'db.$executeRawUnsafe')).toBeDefined();
  });
});
