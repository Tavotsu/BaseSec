import fg from 'fast-glob';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { DEFAULT_EXTENSIONS, DEFAULT_IGNORE_PATTERNS } from '../config/defaults';

export interface CollectOptions {
  extensions: string[];
  ignorePatterns: string[];
  maxFileSize: number;
  maxFiles: number;
}

const DEFAULT_COLLECT_OPTIONS: CollectOptions = {
  extensions: DEFAULT_EXTENSIONS,
  ignorePatterns: DEFAULT_IGNORE_PATTERNS,
  maxFileSize: 500 * 1024,
  maxFiles: 10000,
};

export interface FileCollectorResult {
  files: string[];
  skippedBySize: number;
  skippedByLimit: number;
}

export class FileCollector {
  collect(
    rootPath: string,
    options: Partial<CollectOptions> = {},
  ): FileCollectorResult {
    const opts = { ...DEFAULT_COLLECT_OPTIONS, ...options };
    const absRoot = path.resolve(rootPath);

    const patterns = opts.extensions.map(
      (ext) => `**/*${ext}`,
    );

    const entries = fg.sync(patterns, {
      cwd: absRoot,
      ignore: opts.ignorePatterns,
      absolute: true,
      onlyFiles: true,
      dot: false,
    }) as string[];

    const result: string[] = [];
    let skippedBySize = 0;

    for (const filePath of entries) {
      if (result.length >= opts.maxFiles) {
        break;
      }

      try {
        const stat = fs.statSync(filePath);
        if (stat.size > opts.maxFileSize) {
          skippedBySize++;
          continue;
        }
        result.push(filePath);
      } catch {
        continue;
      }
    }

    return {
      files: result,
      skippedBySize,
      skippedByLimit: Math.max(0, entries.length - result.length),
    };
  }
}