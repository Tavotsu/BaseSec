import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DEP001 } from '../../src/rules/categories/dependency-check/outdated-deps';
import { DEP002 } from '../../src/rules/categories/dependency-check/vulnerable-deps';
import { DEP003 } from '../../src/rules/categories/dependency-check/unused-deps';
import { DEP004 } from '../../src/rules/categories/dependency-check/lockfile-mismatch';
import { runRule } from '../helpers';
import * as child_process from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

vi.mock('node:child_process');

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return {
    ...actual,
    existsSync: vi.fn(actual.existsSync),
  };
});

describe('DEP001: Outdated Dependencies', () => {
  it('detects outdated packages', () => {
    const code = JSON.stringify({ dependencies: { express: "4.18.0" } }, null, 2);
    const findings = runRule(DEP001, code, 'package.json');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('DEP-001');
  });

  it('ignores safe packages', () => {
    const code = JSON.stringify({ dependencies: { express: "4.20.0" } }, null, 2);
    const findings = runRule(DEP001, code, 'package.json');
    expect(findings.length).toBe(0);
  });

  it('skips non-package.json files', () => {
    const findings = runRule(DEP001, "const x = 1;", 'index.js');
    expect(findings.length).toBe(0);
  });
});

describe('DEP002: Vulnerable Dependencies', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('detects vulnerabilities from pnpm audit', () => {
    vi.spyOn(child_process, 'execSync').mockReturnValue(JSON.stringify({
      advisories: {
        "123": {
          title: "Vuln",
          severity: "high",
          module_name: "test-pkg",
          findings: [{ paths: ["test-pkg"] }],
          url: "http://example.com"
        }
      }
    }));
    
    const code = JSON.stringify({ dependencies: { "test-pkg": "1.0.0" } }, null, 2);
    const findings = runRule(DEP002, code, 'package.json');
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe('DEP-002');
  });

  it('handles audit failures (exit code 1) gracefully', () => {
    const error: any = new Error('Command failed');
    error.status = 1;
    error.stdout = JSON.stringify({
      advisories: {
        "123": {
          title: "Vuln",
          severity: "high",
          module_name: "test-pkg",
          findings: [{ paths: ["test-pkg"] }],
          url: "http://example.com"
        }
      }
    });
    vi.spyOn(child_process, 'execSync').mockImplementation(() => { throw error; });
    
    const code = JSON.stringify({ dependencies: { "test-pkg": "1.0.0" } }, null, 2);
    const findings = runRule(DEP002, code, 'package.json');
    expect(findings.length).toBe(1);
  });
});

describe('DEP003: Unused Dependencies', () => {
  it('detects unused dependencies', () => {
    const code = JSON.stringify({ dependencies: { "unused-pkg": "1.0.0" } }, null, 2);
    // Our check is simplified in tests, it assumes false if the regexes don't match the package.json content
    const findings = runRule(DEP003, code, 'package.json');
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe('DEP-003');
  });
});

describe('DEP004: Lockfile Mismatch', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('detects missing lockfile when none exist', () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);
    
    const code = JSON.stringify({ dependencies: { "pkg": "1.0.0" } }, null, 2);
    const findings = runRule(DEP004, code, 'package.json');
    
    expect(findings.length).toBe(1);
    expect(findings[0].message).toContain('No lockfile found');
    
    vi.mocked(fs.existsSync).mockRestore();
  });

  it('detects out of sync lockfile by catching execSync error', () => {
    vi.mocked(fs.existsSync).mockImplementation((file) => {
        return file.toString().includes('pnpm-lock.yaml');
    });
    
    vi.mocked(child_process.execSync).mockImplementation(() => { 
        throw new Error('sync error'); 
    });
    
    const code = JSON.stringify({ dependencies: { "pkg": "1.0.0" } }, null, 2);
    const findings = runRule(DEP004, code, 'package.json');
    
    expect(findings.length).toBe(1);
    expect(findings[0].message).toContain('out of sync');
    
    vi.mocked(fs.existsSync).mockRestore();
  });
});
