import { describe, it, expect } from 'vitest';
import { isTaintSource, containsSqlKeywords } from '../../src/utils/patterns';

describe('isTaintSource', () => {
  it('detects req.body as taint source', () => {
    expect(isTaintSource('req.body')).toBe(true);
    expect(isTaintSource('req.body.name')).toBe(true);
  });

  it('detects req.params as taint source', () => {
    expect(isTaintSource('req.params.id')).toBe(true);
  });

  it('detects req.query as taint source', () => {
    expect(isTaintSource('req.query.search')).toBe(true);
  });

  it('detects req.headers as taint source', () => {
    expect(isTaintSource('req.headers["x-custom"]')).toBe(true);
  });

  it('detects process.argv as taint source', () => {
    expect(isTaintSource('process.argv[2]')).toBe(true);
  });

  it('does not flag safe expressions', () => {
    expect(isTaintSource('const x = 1')).toBe(false);
    expect(isTaintSource('Math.random()')).toBe(false);
    expect(isTaintSource('"hello"')).toBe(false);
  });
});

describe('containsSqlKeywords', () => {
  it('detects SELECT keyword', () => {
    expect(containsSqlKeywords('"SELECT * FROM users"')).toBe(true);
  });

  it('detects INSERT keyword', () => {
    expect(containsSqlKeywords('"INSERT INTO users"')).toBe(true);
  });

  it('detects WHERE keyword', () => {
    expect(containsSqlKeywords('"WHERE id = 1"')).toBe(true);
  });

  it('does not flag substring matches like "android"', () => {
    expect(containsSqlKeywords('"android"')).toBe(false);
    expect(containsSqlKeywords('"command"')).toBe(false);
  });

  it('does not flag safe strings', () => {
    expect(containsSqlKeywords('"hello world"')).toBe(false);
    expect(containsSqlKeywords('42')).toBe(false);
  });

  it('detects AND as word boundary', () => {
    expect(containsSqlKeywords('"a AND b"')).toBe(true);
    expect(containsSqlKeywords('"android"')).toBe(false);
    expect(containsSqlKeywords('"ANDROID"')).toBe(false);
  });
});