import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { runInit } from '../../../src/cli/commands/init';
import * as fs from 'node:fs';

vi.mock('node:fs');

describe('init command', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('creates basesec.config.ts by default', async () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);
    
    await runInit('ts');
    
    expect(fs.writeFileSync).toHaveBeenCalledWith(
      expect.stringContaining('basesec.config.ts'),
      expect.stringContaining('export default defineConfig'),
      'utf-8'
    );
  });

  it('creates basesec.config.json by default for json', async () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);
    
    await runInit('json');
    
    expect(fs.writeFileSync).toHaveBeenCalledWith(
      expect.stringContaining('basesec.config.json'),
      expect.stringContaining('{'),
      'utf-8'
    );
  });

  it('defaults to ts if unsupported format', async () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);
    await runInit('yaml' as any);
    expect(fs.writeFileSync).toHaveBeenCalledWith(
      expect.stringContaining('basesec.config.ts'),
      expect.any(String),
      'utf-8'
    );
  });

  it('logs instead of throwing if file already exists', async () => {
    vi.mocked(fs.existsSync).mockReturnValue(true);
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    
    await runInit('ts');
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('already exists'));
    expect(fs.writeFileSync).not.toHaveBeenCalled();
    logSpy.mockRestore();
  });
});
