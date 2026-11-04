import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFile } from 'node:child_process';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

/**
 * Ejecuta el CLI real (`src/cli/index.ts`) con tsx: así se prueban el parseo de cac (alias cortos) y los exit codes
 * de validación en el punto de entrada, no solo las funciones de los comandos.
 */
const ROOT = path.resolve(__dirname, '..', '..');
const TSX_CLI = path.join(ROOT, 'node_modules', 'tsx', 'dist', 'cli.mjs');
const CLI = path.join(ROOT, 'src', 'cli', 'index.ts');
const FIXTURE = path.join(ROOT, 'tests', 'fixtures', 'express-src');

interface CliRun {
  code: number;
  stdout: string;
  stderr: string;
}

/** Ejecuta `basesec <args>` en `cwd` con HOME dado. Nunca rechaza: devuelve el exit code. */
function runCli(args: string[], cwd: string, home: string): Promise<CliRun> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [TSX_CLI, CLI, ...args],
      { cwd, env: { ...process.env, NO_COLOR: '1', HOME: home } },
      (error, stdout, stderr) => {
        const code = error === null ? 0 : typeof error.code === 'number' ? error.code : 1;
        resolve({ code, stdout: String(stdout), stderr: String(stderr) });
      },
    );
  });
}

// Los tests lanzan tsx: el arranque puede tardar más que el timeout por defecto.
const SLOW = 60_000;

let workDir: string;
let fakeHome: string;

beforeEach(() => {
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-cli-entry-'));
  fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-cli-home-'));
});

afterEach(() => {
  fs.rmSync(workDir, { recursive: true, force: true });
  fs.rmSync(fakeHome, { recursive: true, force: true });
});

describe('CLI: alias cortos (-f, -o, -s, -c, -q)', () => {
  it('-f, -o, -s y -q funcionan en scan y escriben el informe en la ruta indicada', async () => {
    const out = path.join(workDir, 'report.json');
    const run = await runCli(['scan', FIXTURE, '-f', 'json', '-o', out, '-s', 'high', '-q', '--no-banner', '--no-cache'], workDir, fakeHome);

    expect(run.stderr).not.toContain('Unknown option');
    expect(run.code).toBe(0);
    const report = JSON.parse(fs.readFileSync(out, 'utf-8'));
    expect(report.findings.length).toBeGreaterThan(0);
    for (const finding of report.findings) {
      expect(['critical', 'high']).toContain(finding.severity);
    }
  }, SLOW);

  it('-c acepta la ruta de config: un fichero inexistente sale 3 con el mensaje de carga', async () => {
    const run = await runCli(['scan', FIXTURE, '-c', path.join(workDir, 'nope.json'), '--no-banner', '--no-cache'], workDir, fakeHome);

    expect(run.stderr).not.toContain('Unknown option');
    expect(run.code).toBe(3);
    expect(run.stderr).toContain('Could not load config file');
  }, SLOW);

  it('las formas largas siguen funcionando igual que los alias', async () => {
    const out = path.join(workDir, 'long.json');
    const run = await runCli(['scan', FIXTURE, '--format', 'json', '--output', out, '--severity', 'high', '--quiet', '--no-banner', '--no-cache'], workDir, fakeHome);

    expect(run.code).toBe(0);
    expect(JSON.parse(fs.readFileSync(out, 'utf-8')).findings.length).toBeGreaterThan(0);
  }, SLOW);
});

describe('CLI: validación de --format y --severity en dast', () => {
  const TARGET = 'http://127.0.0.1:1';

  it('--format inválido sale 2 (como scan), no 3', async () => {
    const run = await runCli(['dast', TARGET, '--format', 'bad', '--no-banner'], workDir, fakeHome);

    expect(run.code).toBe(2);
    expect(run.stderr).toContain('Invalid format: bad');
  }, SLOW);

  it('--severity inválida sale 2, no 3', async () => {
    const run = await runCli(['dast', TARGET, '--severity', 'nope', '--no-banner'], workDir, fakeHome);

    expect(run.code).toBe(2);
    expect(run.stderr).toContain('Invalid severity: nope');
  }, SLOW);

  it('un --rps inválido sigue siendo error de config: exit 3', async () => {
    const run = await runCli(['dast', TARGET, '--rps', '0', '--no-banner'], workDir, fakeHome);

    expect(run.code).toBe(3);
    expect(run.stderr).toContain('--rps must be a positive integer');
  }, SLOW);

  it('scan con --format inválido sigue en 2', async () => {
    const run = await runCli(['scan', FIXTURE, '--format', 'bad', '--no-banner', '--no-cache'], workDir, fakeHome);

    expect(run.code).toBe(2);
  }, SLOW);
});
