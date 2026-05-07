import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { runInit } from '../../src/cli/commands/init';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

describe('CLI: init command', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('creates basesec.config.ts by default', async () => {
    const originalCwd = process.cwd();
    process.chdir(tmpDir);
    try {
      await runInit('ts');
      const filePath = path.join(tmpDir, 'basesec.config.ts');
      expect(fs.existsSync(filePath)).toBe(true);
      const content = fs.readFileSync(filePath, 'utf-8');
      expect(content).toContain('defineConfig');
      expect(content).toContain("target: ['./src']");
      expect(content).toContain("framework: 'auto'");
    } finally {
      process.chdir(originalCwd);
    }
  });

  it('creates basesec.config.json when format is json', async () => {
    const originalCwd = process.cwd();
    process.chdir(tmpDir);
    try {
      await runInit('json');
      const filePath = path.join(tmpDir, 'basesec.config.json');
      expect(fs.existsSync(filePath)).toBe(true);
      const content = fs.readFileSync(filePath, 'utf-8');
      const parsed = JSON.parse(content);
      expect(parsed.target).toEqual(['./src']);
      expect(parsed.framework).toBe('auto');
    } finally {
      process.chdir(originalCwd);
    }
  });

  it('does not overwrite existing config file', async () => {
    const originalCwd = process.cwd();
    process.chdir(tmpDir);
    try {
      const filePath = path.join(tmpDir, 'basesec.config.ts');
      fs.writeFileSync(filePath, 'existing', 'utf-8');
      await runInit('ts');
      const content = fs.readFileSync(filePath, 'utf-8');
      expect(content).toBe('existing');
    } finally {
      process.chdir(originalCwd);
    }
  });
});