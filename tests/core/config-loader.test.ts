import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { loadConfig } from '../../src/config/loader';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

describe('loadConfig', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-cfg-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('loads JSON config file', () => {
    const configPath = path.join(tmpDir, 'basesec.config.json');
    fs.writeFileSync(configPath, JSON.stringify({
      target: ['./src'],
      severity: 'high',
      taintAnalysis: false,
    }));
    const config = loadConfig(configPath, tmpDir);
    expect(config.severity).toBe('high');
    expect(config.taintAnalysis).toBe(false);
  });

  it('loads JS config file with module.exports', () => {
    const configPath = path.join(tmpDir, 'basesec.config.js');
    fs.writeFileSync(configPath, `module.exports = {
      target: ['./src'],
      severity: 'medium',
    };`);
    const config = loadConfig(configPath, tmpDir);
    expect(config.severity).toBe('medium');
  });

  it('loads TS config file with defineConfig pattern', () => {
    const configPath = path.join(tmpDir, 'basesec.config.ts');
    fs.writeFileSync(configPath, `defineConfig({
  target: ['./src'],
  severity: 'high',
  taintAnalysis: true,
})`);
    const config = loadConfig(configPath, tmpDir);
    expect(config.severity).toBe('high');
  });

  it('loads JS config file with module.exports', () => {
    const configPath = path.join(tmpDir, 'basesec.config.js');
    fs.writeFileSync(configPath, `module.exports = {
      target: ['./src'],
      severity: 'medium',
    };`);
    const config = loadConfig(configPath, tmpDir);
    expect(config.severity).toBe('medium');
  });

  it('loads TS config file with defineConfig', () => {
    const configPath = path.join(tmpDir, 'basesec.config.ts');
    fs.writeFileSync(configPath, `import { defineConfig } from 'basesec/config';
export default defineConfig({
  target: ['./src'],
  severity: 'high',
  taintAnalysis: true,
});`);
    const config = loadConfig(configPath, tmpDir);
    expect(config.severity).toBe('high');
    expect(config.taintAnalysis).toBe(true);
  });

  it('loads config from .basesecrc', () => {
    const configPath = path.join(tmpDir, '.basesecrc');
    fs.writeFileSync(configPath, JSON.stringify({
      target: ['./src'],
      severity: 'low',
    }));
    const config = loadConfig(undefined, tmpDir);
    expect(config.severity).toBe('low');
  });

  it('loads config from package.json basesec key', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      name: 'test-app',
      basesec: {
        severity: 'high',
        taintAnalysis: false,
      },
    }));
    const config = loadConfig(undefined, tmpDir);
    expect(config.severity).toBe('high');
    expect(config.taintAnalysis).toBe(false);
  });

  it('returns empty config when no config files found', () => {
    const config = loadConfig(undefined, tmpDir);
    expect(Object.keys(config).length === 0 || config.severity === undefined).toBe(true);
  });

  it('throws error when explicit config path does not exist', () => {
    expect(() => loadConfig('/nonexistent/config.json', tmpDir)).toThrow();
  });
});