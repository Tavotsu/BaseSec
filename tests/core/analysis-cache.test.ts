import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { AnalysisCache, shouldUseCache } from '../../src/core/analysis-cache';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type { Finding, Severity } from '../../src/rules/types';

function createFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'SQLI-001',
    ruleName: 'SQL Injection',
    category: 'sql-injection',
    severity: 'critical' as Severity,
    confidence: 'high',
    filePath: 'test.ts',
    line: 10,
    column: 5,
    endLine: 10,
    endColumn: 30,
    message: 'Potential SQL injection',
    codeSnippet: 'db.query("SELECT * FROM users WHERE id = " + req.params.id)',
    remediation: 'Use parameterized queries',
    references: [],
    ...overrides,
  };
}

describe('AnalysisCache', () => {
  let tmpDir: string;
  let cache: AnalysisCache;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-cache-test-'));
    cache = new AnalysisCache({ cacheDir: tmpDir, enabled: true });
  });

  afterEach(() => {
    cache.clear();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('stores and retrieves findings for same file and config', () => {
    const findings = [createFinding()];
    const configHash = cache.computeConfigHash({ severity: 'low' });

    cache.set('test.ts', 'const x = 1;', configHash, findings);
    const result = cache.get('test.ts', 'const x = 1;', configHash);

    expect(result).not.toBeNull();
    expect(result!.length).toBe(1);
    expect(result![0].ruleId).toBe('SQLI-001');
  });

  it('returns null when file content has changed', () => {
    const findings = [createFinding()];
    const configHash = cache.computeConfigHash({ severity: 'low' });

    cache.set('test.ts', 'const x = 1;', configHash, findings);
    const result = cache.get('test.ts', 'const x = 2;', configHash);

    expect(result).toBeNull();
  });

  it('returns null when config hash has changed', () => {
    const findings = [createFinding()];
    const configHash1 = cache.computeConfigHash({ severity: 'low' });
    const configHash2 = cache.computeConfigHash({ severity: 'critical' });

    cache.set('test.ts', 'const x = 1;', configHash1, findings);
    const result = cache.get('test.ts', 'const x = 1;', configHash2);

    expect(result).toBeNull();
  });

  it('returns null when cache is disabled', () => {
    const disabledCache = new AnalysisCache({ enabled: false });
    const findings = [createFinding()];
    const configHash = disabledCache.computeConfigHash({ severity: 'low' });

    disabledCache.set('test.ts', 'const x = 1;', configHash, findings);
    const result = disabledCache.get('test.ts', 'const x = 1;', configHash);

    expect(result).toBeNull();
  });

  it('does not write to disk when cache is disabled', () => {
    const disabledCache = new AnalysisCache({ enabled: false });
    const findings = [createFinding()];
    const configHash = disabledCache.computeConfigHash({ severity: 'low' });

    disabledCache.set('test.ts', 'const x = 1;', configHash, findings);
    expect(disabledCache.stats.entries).toBe(0);
  });

  it('computes consistent file hashes', () => {
    const hash1 = cache.computeFileHash('const x = 1;');
    const hash2 = cache.computeFileHash('const x = 1;');
    expect(hash1).toBe(hash2);
  });

  it('computes different hashes for different content', () => {
    const hash1 = cache.computeFileHash('const x = 1;');
    const hash2 = cache.computeFileHash('const y = 2;');
    expect(hash1).not.toBe(hash2);
  });

  it('computes consistent config hashes', () => {
    const config = { severity: 'low', framework: 'auto' };
    const hash1 = cache.computeConfigHash(config);
    const hash2 = cache.computeConfigHash(config);
    expect(hash1).toBe(hash2);
  });

  it('computes different hashes for different configs', () => {
    const hash1 = cache.computeConfigHash({ severity: 'low' });
    const hash2 = cache.computeConfigHash({ severity: 'critical' });
    expect(hash1).not.toBe(hash2);
  });

  it('clears all cache entries', () => {
    const configHash = cache.computeConfigHash({ severity: 'low' });
    cache.set('file1.ts', 'content1', configHash, [createFinding()]);
    cache.set('file2.ts', 'content2', configHash, [createFinding()]);

    expect(cache.stats.entries).toBeGreaterThanOrEqual(2);

    cache.clear();

    expect(cache.stats.entries).toBe(0);
    expect(cache.get('file1.ts', 'content1', configHash)).toBeNull();
    expect(cache.get('file2.ts', 'content2', configHash)).toBeNull();
  });

  it('returns correct stats', () => {
    const configHash = cache.computeConfigHash({ severity: 'low' });
    cache.set('test.ts', 'content', configHash, [createFinding()]);

    const stats = cache.stats;
    expect(stats.entries).toBeGreaterThanOrEqual(1);
    expect(stats.sizeBytes).toBeGreaterThan(0);
  });

  it('handles empty findings array', () => {
    const configHash = cache.computeConfigHash({ severity: 'low' });
    cache.set('empty.ts', 'no findings', configHash, []);
    const result = cache.get('empty.ts', 'no findings', configHash);
    expect(result).not.toBeNull();
    expect(result).toEqual([]);
  });

  it('evicts expired entries', async () => {
    const shortCache = new AnalysisCache({
      cacheDir: path.join(tmpDir, 'short'),
      enabled: true,
      maxAgeMs: 1,
    });
    const configHash = shortCache.computeConfigHash({ severity: 'low' });

    shortCache.set('expired.ts', 'old content', configHash, [createFinding()]);

    await new Promise<void>((resolve) => setTimeout(resolve, 10));

    const result = shortCache.get('expired.ts', 'old content', configHash);
    expect(result).toBeNull();
    shortCache.clear();
  });
});

describe('shouldUseCache', () => {
  it('returns correct values', () => {
    expect(shouldUseCache(undefined)).toBe(true);
    expect(shouldUseCache(true)).toBe(false);
  });
});