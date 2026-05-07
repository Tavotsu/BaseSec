import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import * as os from 'node:os';

export interface CachedFileResult {
  filePath: string;
  fileHash: string;
  configHash: string;
  timestamp: number;
  findings: import('../rules/types').Finding[];
}

export class AnalysisCache {
  private cacheDir: string;
  private maxAge: number;
  private enabled: boolean;

  constructor(options: { cacheDir?: string; maxAgeMs?: number; enabled?: boolean } = {}) {
    this.enabled = options.enabled !== false;
    this.maxAge = options.maxAgeMs ?? 24 * 60 * 60 * 1000;
    this.cacheDir = options.cacheDir ?? path.join(os.tmpdir(), 'basesec-cache');

    if (this.enabled) {
      try {
        if (!fs.existsSync(this.cacheDir)) {
          fs.mkdirSync(this.cacheDir, { recursive: true });
        }
      } catch {
        this.enabled = false;
      }
    }
  }

  computeFileHash(content: string): string {
    return crypto.createHash('sha256').update(content).digest('hex').substring(0, 16);
  }

  computeConfigHash(config: Record<string, unknown>): string {
    const sorted = JSON.stringify(config, Object.keys(config).sort());
    return crypto.createHash('sha256').update(sorted).digest('hex').substring(0, 16);
  }

  get(
    filePath: string,
    content: string,
    configHash: string,
  ): import('../rules/types').Finding[] | null {
    if (!this.enabled) return null;

    try {
      const fileHash = this.computeFileHash(content);
      const cacheFile = this.getCachePath(filePath, fileHash);

      if (!fs.existsSync(cacheFile)) return null;

      const raw = fs.readFileSync(cacheFile, 'utf-8');
      const cached: CachedFileResult = JSON.parse(raw);

      if (cached.fileHash !== fileHash) return null;
      if (cached.configHash !== configHash) return null;

      const age = Date.now() - cached.timestamp;
      if (age > this.maxAge) {
        this.evict(cacheFile);
        return null;
      }

      return cached.findings.map((f) => ({
        ...f,
        filePath,
      }));
    } catch {
      return null;
    }
  }

  set(
    filePath: string,
    content: string,
    configHash: string,
    findings: import('../rules/types').Finding[],
  ): void {
    if (!this.enabled) return;

    try {
      const fileHash = this.computeFileHash(content);
      const cacheFile = this.getCachePath(filePath, fileHash);
      const cacheDir = path.dirname(cacheFile);

      if (!fs.existsSync(cacheDir)) {
        fs.mkdirSync(cacheDir, { recursive: true });
      }

      const cached: CachedFileResult = {
        filePath,
        fileHash,
        configHash,
        timestamp: Date.now(),
        findings,
      };

      fs.writeFileSync(cacheFile, JSON.stringify(cached));
    } catch {
      // Cache write failures are non-critical
    }
  }

  clear(): void {
    if (!this.enabled) return;

    try {
      if (fs.existsSync(this.cacheDir)) {
        const entries = fs.readdirSync(this.cacheDir, { recursive: true });
        for (const entry of entries) {
          const fullPath = path.join(this.cacheDir, entry.toString());
          try {
            if (fs.statSync(fullPath).isFile()) {
              fs.unlinkSync(fullPath);
            }
          } catch {
            // Skip files we can't delete
          }
        }
      }
    } catch {
      // Clear failures are non-critical
    }
  }

  get stats(): { entries: number; sizeBytes: number } {
    if (!this.enabled) return { entries: 0, sizeBytes: 0 };

    try {
      let entries = 0;
      let sizeBytes = 0;

      if (fs.existsSync(this.cacheDir)) {
        const walk = (dir: string) => {
          for (const entry of fs.readdirSync(dir)) {
            const fullPath = path.join(dir, entry);
            const stat = fs.statSync(fullPath);
            if (stat.isDirectory()) {
              walk(fullPath);
            } else {
              entries++;
              sizeBytes += stat.size;
            }
          }
        };
        walk(this.cacheDir);
      }

      return { entries, sizeBytes };
    } catch {
      return { entries: 0, sizeBytes: 0 };
    }
  }

  private getCachePath(filePath: string, fileHash: string): string {
    const normalized = filePath.replace(/[/:\\]/g, '_');
    return path.join(this.cacheDir, `${normalized}_${fileHash}.json`);
  }

  private evict(cacheFile: string): void {
    try {
      fs.unlinkSync(cacheFile);
    } catch {
      // Ignore eviction errors
    }
  }
}

export function shouldUseCache(cliNoCache: boolean | undefined): boolean {
  return cliNoCache !== true;
}