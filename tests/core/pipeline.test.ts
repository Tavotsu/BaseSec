import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Pipeline } from '../../src/core/pipeline';
import * as fs from 'node:fs';
import * as path from 'node:path';

// Note: To test the pipeline fully, we mock filesystem
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return {
    ...actual,
    existsSync: vi.fn(actual.existsSync),
    readFileSync: vi.fn(actual.readFileSync),
    mkdirSync: vi.fn(),
    writeFileSync: vi.fn(),
    statSync: vi.fn(actual.statSync),
    readdirSync: vi.fn(actual.readdirSync),
    unlinkSync: vi.fn(),
  };
});

describe('Pipeline', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('runs successfully on empty directory', async () => {
    const pipeline = new Pipeline([], { noCache: true, workers: 0 });
    const result = await pipeline.run(__dirname, { noDeps: true });
    
    expect(result.findings).toHaveLength(0);
    expect(result.stats).toBeDefined();
    expect(result.stats.rulesRun).toBe(0);
  });

  it('can clear cache', () => {
    const pipeline = new Pipeline();
    expect(() => pipeline.clearCache()).not.toThrow();
  });

  it('can get cache stats', () => {
    const pipeline = new Pipeline();
    const stats = pipeline.getCacheStats();
    expect(stats.entries).toBeDefined();
    expect(stats.sizeBytes).toBeDefined();
  });
});
