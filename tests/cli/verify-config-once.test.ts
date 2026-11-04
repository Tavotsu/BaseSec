import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// Cuenta las llamadas reales a loadConfig sin cambiar su comportamiento.
vi.mock('../../src/config/loader', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../src/config/loader')>();
  return { ...original, loadConfig: vi.fn(original.loadConfig) };
});

import { loadConfig } from '../../src/config/loader';
import { runVerify } from '../../src/cli/commands/verify';
import { runScan } from '../../src/cli/commands/scan';
import type { CliOptions } from '../../src/rules/types';

let dirs: string[] = [];
let previousHome: string | undefined;

beforeEach(() => {
  // HOME temporal: `scan` escribe su informe en ~/.basesec y no debe tocar el real.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-verify-cfg-home-'));
  dirs.push(home);
  previousHome = process.env.HOME;
  process.env.HOME = home;
});

afterEach(() => {
  if (previousHome === undefined) delete process.env.HOME;
  else process.env.HOME = previousHome;
  for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true });
  dirs = [];
  vi.mocked(loadConfig).mockClear();
});

function options(overrides: Partial<CliOptions>): CliOptions {
  return {
    format: 'json',
    severity: 'low',
    ignore: [],
    noTaint: false,
    quiet: true,
    strict: false,
    framework: 'auto',
    noColor: true,
    noBanner: true,
    noCache: true,
    noDeps: true,
    verify: true,
    ...overrides,
  };
}

describe('scan --verify: lectura única de la config', () => {
  it('la sección dast y el escaneo SAST comparten una sola lectura del fichero', async () => {
    const project = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-verify-cfg-'));
    dirs.push(project);
    fs.writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'x', private: true }));
    fs.writeFileSync(path.join(project, 'basesec.config.json'), JSON.stringify({ dast: { rps: 50 } }));
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    try {
      // Referencia: lecturas de `scan` sobre el mismo proyecto (el Pipeline lee la suya, ajena al CLI).
      expect(await runScan(project, options({ verify: false }))).toBe(0);
      const scanReads = vi.mocked(loadConfig).mock.calls.length;
      vi.mocked(loadConfig).mockClear();

      // Sin rutas no hay ataque (0); el análisis SAST sí se ejecuta. `verify` no lee más veces que `scan`.
      const code = await runVerify(project, options({ target: 'http://127.0.0.1:1', verifyDast: { evidence: false } }));
      expect(code).toBe(0);
      expect(vi.mocked(loadConfig).mock.calls.length).toBe(scanReads);
    } finally {
      errSpy.mockRestore();
      logSpy.mockRestore();
    }
  });

  it('con --config que no carga: 3 antes de escanear, una sola lectura fallida', async () => {
    const project = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-verify-cfg-'));
    dirs.push(project);
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      const code = await runVerify(project, options({ config: 'missing.json', target: 'http://127.0.0.1:1' }));
      expect(code).toBe(3);
    } finally {
      errSpy.mockRestore();
    }
    expect(vi.mocked(loadConfig)).toHaveBeenCalledTimes(1);
  });
});
