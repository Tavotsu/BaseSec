import { describe, it, expect } from 'vitest';
import { FileCollector } from '../../src/core/file-collector';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

describe('FileCollector', () => {
  let tmpDir: string;

  async function setuptmpDir(structure: Record<string, string>) {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secbase-test-'));
    for (const [relativePath, content] of Object.entries(structure)) {
      const fullPath = path.join(tmpDir, relativePath);
      fs.mkdirSync(path.dirname(fullPath), { recursive: true });
      fs.writeFileSync(fullPath, content);
    }
    return tmpDir;
  }

  function cleanupTmpDir() {
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  describe('collect', () => {
    it('collects .ts and .js files from target directory', () => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secbase-test-'));
      fs.writeFileSync(path.join(tmpDir, 'app.ts'), 'const x = 1;');
      fs.writeFileSync(path.join(tmpDir, 'utils.js'), 'const y = 2;');
      fs.writeFileSync(path.join(tmpDir, 'style.css'), 'body { color: red; }');

      const collector = new FileCollector();
      const result = collector.collect(tmpDir);

      expect(result.files.length).toBeGreaterThanOrEqual(2);
      const basenames = result.files.map((f) => path.basename(f));
      expect(basenames).toContain('app.ts');
      expect(basenames).toContain('utils.js');
      expect(basenames).not.toContain('style.css');
      cleanupTmpDir();
    });

    it('respects ignore patterns for node_modules and dist', () => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secbase-test-'));
      fs.mkdirSync(path.join(tmpDir, 'node_modules'), { recursive: true });
      fs.mkdirSync(path.join(tmpDir, 'dist'), { recursive: true });
      fs.writeFileSync(path.join(tmpDir, 'node_modules', 'lib.ts'), 'export const lib = 1;');
      fs.writeFileSync(path.join(tmpDir, 'dist', 'bundle.js'), 'bundle;');
      fs.writeFileSync(path.join(tmpDir, 'src.ts'), 'const x = 1;');

      const collector = new FileCollector();
      const result = collector.collect(tmpDir);

      const basenames = result.files.map((f) => path.basename(f));
      expect(basenames).toContain('src.ts');
      expect(basenames).not.toContain('lib.ts');
      expect(basenames).not.toContain('bundle.js');
      cleanupTmpDir();
    });

    it('skips files exceeding maxFileSize', () => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secbase-test-'));
      const largeContent = 'x'.repeat(600 * 1024);
      fs.writeFileSync(path.join(tmpDir, 'large.ts'), largeContent);
      fs.writeFileSync(path.join(tmpDir, 'small.ts'), 'const x = 1;');

      const collector = new FileCollector();
      const result = collector.collect(tmpDir, {
        maxFileSize: 500 * 1024,
      });

      const basenames = result.files.map((f) => path.basename(f));
      expect(basenames).toContain('small.ts');
      expect(basenames).not.toContain('large.ts');
      expect(result.skippedBySize).toBe(1);
      cleanupTmpDir();
    });

    it('loads .gitignore patterns', () => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secbase-test-'));
      fs.writeFileSync(path.join(tmpDir, '.gitignore'), 'logs/\n*.bak\n');
      fs.mkdirSync(path.join(tmpDir, 'logs'), { recursive: true });
      fs.writeFileSync(path.join(tmpDir, 'logs', 'app.ts'), 'const x = 1;');
      fs.writeFileSync(path.join(tmpDir, 'backup.bak'), 'backup');
      fs.writeFileSync(path.join(tmpDir, 'main.ts'), 'const y = 2;');

      const collector = new FileCollector();
      const result = collector.collect(tmpDir);

      const basenames = result.files.map((f) => path.basename(f));
      expect(basenames).toContain('main.ts');
      expect(basenames).not.toContain('app.ts');
      cleanupTmpDir();
    });

    it('collects .tsx and .jsx files', () => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secbase-test-'));
      fs.writeFileSync(path.join(tmpDir, 'component.tsx'), 'const X = () => <div/>;');
      fs.writeFileSync(path.join(tmpDir, 'app.jsx'), 'const Y = () => {};');

      const collector = new FileCollector();
      const result = collector.collect(tmpDir);

      const basenames = result.files.map((f) => path.basename(f));
      expect(basenames).toContain('component.tsx');
      expect(basenames).toContain('app.jsx');
      cleanupTmpDir();
    });
  });
});