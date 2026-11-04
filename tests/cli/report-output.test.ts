import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { emitReport } from '../../src/cli/report-output';

const JSON_REPORT = '{\n  "findings": []\n}';

let fakeHome: string;
let previousHome: string | undefined;
let workDir: string;

beforeEach(() => {
  // HOME temporal: el informe por defecto (~/.basesec) no puede tocar el del usuario.
  previousHome = process.env.HOME;
  fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-report-home-'));
  process.env.HOME = fakeHome;
  // Dentro del cwd: un --output fuera de él pediría confirmación interactiva.
  workDir = fs.mkdtempSync(path.join(process.cwd(), 'basesec-report-out-'));
  vi.spyOn(console, 'log').mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
  if (previousHome === undefined) delete process.env.HOME;
  else process.env.HOME = previousHome;
  fs.rmSync(fakeHome, { recursive: true, force: true });
  fs.rmSync(workDir, { recursive: true, force: true });
});

function defaultReportFiles(): string[] {
  const dir = path.join(fakeHome, '.basesec');
  return fs.existsSync(dir) ? fs.readdirSync(dir) : [];
}

describe('emitReport: preferStdout (dast y scan --verify)', () => {
  it('sin ruta y con preferStdout, un formato no terminal va a stdout y no escribe fichero', async () => {
    expect(await emitReport(JSON_REPORT, 'json', undefined, true)).toBe(true);

    expect(console.log).toHaveBeenCalledWith(JSON_REPORT);
    expect(defaultReportFiles()).toEqual([]);
  });

  it('sin preferStdout (lo que pasa scan) mantiene el fichero por defecto y el mensaje "Report written to"', async () => {
    expect(await emitReport(JSON_REPORT, 'json')).toBe(true);

    const files = defaultReportFiles();
    expect(files).toHaveLength(1);
    expect(files[0]).toMatch(/^scan-.*\.json$/);
    expect(fs.readFileSync(path.join(fakeHome, '.basesec', files[0]), 'utf-8')).toBe(JSON_REPORT);
    const logged = vi.mocked(console.log).mock.calls.flat().join('\n');
    expect(logged).toContain('Report written to');
    expect(logged).not.toContain(JSON_REPORT);
  });

  it('con ruta, preferStdout no cambia nada: escribe a la ruta y no a stdout', async () => {
    const outputPath = path.join(workDir, 'report.json');

    expect(await emitReport(JSON_REPORT, 'json', outputPath, true)).toBe(true);

    expect(fs.readFileSync(outputPath, 'utf-8')).toBe(JSON_REPORT);
    expect(vi.mocked(console.log).mock.calls.flat().join('\n')).not.toContain(JSON_REPORT);
    expect(defaultReportFiles()).toEqual([]);
  });

  it('un formato terminal va a stdout con o sin preferStdout', async () => {
    expect(await emitReport('TABLE', 'terminal')).toBe(true);
    expect(console.log).toHaveBeenCalledWith('TABLE');
    expect(defaultReportFiles()).toEqual([]);
  });
});
