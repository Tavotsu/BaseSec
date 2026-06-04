import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

export function getBaseSecDir(): string {
  return path.join(os.homedir(), '.basesec');
}

export function ensureBaseSecDir(): string {
  const dir = getBaseSecDir();
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  return dir;
}

export function generateReportFilename(format: string): string {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  return `scan-${timestamp}.${format}`;
}

export function getDefaultReportPath(format: string): string {
  const dir = ensureBaseSecDir();
  const filename = generateReportFilename(format);
  return path.join(dir, filename);
}