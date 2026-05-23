import fg from 'fast-glob';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { DEFAULT_EXTENSIONS, DEFAULT_IGNORE_PATTERNS, SENSITIVE_FILE_PATTERNS } from '../config/defaults';
import { logger } from '../utils/logger';

export interface CollectOptions {
  extensions: string[];
  ignorePatterns: string[];
  maxFileSize: number;
  maxFiles: number;
  readEnv?: boolean;
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

    const gitignorePatterns = this.loadGitignore(absRoot);
    
    // If readEnv is true, filter out SENSITIVE_FILE_PATTERNS from the mergedIgnore list
    let mergedIgnore = [
      ...opts.ignorePatterns,
      ...gitignorePatterns,
    ];
    
    if (opts.readEnv) {
      mergedIgnore = mergedIgnore.filter(p => !SENSITIVE_FILE_PATTERNS.includes(p));
    }

    const patterns = opts.extensions.map(
      (ext) => `**/*${ext}`,
    );

    if (opts.readEnv) {
      patterns.push('**/.env', '**/.env.*');
    }

    const entries = fg.sync(patterns, {
      cwd: absRoot,
      ignore: mergedIgnore,
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

      if (this.isSensitiveFile(filePath, opts.readEnv)) {
        continue;
      }

      try {
        const stat = fs.statSync(filePath);
        if (stat.size > opts.maxFileSize) {
          skippedBySize++;
          continue;
        }
        result.push(filePath);
      } catch (e) {
        logger.warn(`Failed to stat file ${filePath}`, e);
        continue;
      }
    }

    return {
      files: result,
      skippedBySize,
      skippedByLimit: Math.max(0, entries.length - result.length - skippedBySize),
    };
  }

  private loadGitignore(rootPath: string): string[] {
    const patterns: string[] = [];
    const gitignorePath = path.join(rootPath, '.gitignore');

    try {
      if (!fs.existsSync(gitignorePath)) return patterns;
      const content = fs.readFileSync(gitignorePath, 'utf-8');
      for (const rawLine of content.split('\n')) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) continue;

        const negated = line.startsWith('!');
        const pattern = negated ? line.slice(1) : line;

        if (pattern.startsWith('/')) {
          patterns.push(negated ? `!${pattern}` : pattern);
        } else if (pattern.endsWith('/')) {
          patterns.push(negated ? `!${pattern}**` : `${pattern}**`);
        } else {
          patterns.push(negated ? `!${pattern}` : pattern);
        }
      }
    } catch (e) {
      logger.warn(`Failed to read/parse .gitignore at ${gitignorePath}`, e);
    }

    return patterns;
  }

  private isSensitiveFile(filePath: string, readEnv?: boolean): boolean {
    const basename = path.basename(filePath).toLowerCase();
    const sensitiveNames = ['.env', 'secrets', 'credentials'];
    const sensitiveExts = ['.pem', '.key', '.p12', '.pfx'];

    if (sensitiveExts.some((ext) => basename.endsWith(ext))) {
      return true;
    }

    if (readEnv && (basename.startsWith('.env') || basename === '.env')) {
      return false; // User explicitly allowed scanning .env files
    }

    if (basename.startsWith('.env')) {
      return true;
    }

    if (sensitiveNames.some((name) => basename.startsWith(name + '.') || basename === name)) {
      return true;
    }

    return false;
  }
}