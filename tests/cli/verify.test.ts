import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import type { AddressInfo } from 'node:net';
import { runScan } from '../../src/cli/commands/scan';
import { runVerify } from '../../src/cli/commands/verify';
import { validateVerifyOptions } from '../../src/cli/validation';
import { Pipeline } from '../../src/core/pipeline';
import { Guard } from '../../src/dast/guard';
import { GuardError } from '../../src/dast/types';
import type { CliOptions, ScanResult } from '../../src/rules/types';

/** Servidor que imita una SQLi: una comilla devuelve la firma de error de pg. Cuenta las peticiones recibidas. */
let target: http.Server;
let targetUrl: string;
let requests = 0;

let project: string;
let fakeHome: string;
let previousHome: string | undefined;

const PROJECT_SOURCE = [
  "const express = require('express');",
  "const { Pool } = require('pg');",
  '',
  'const app = express();',
  'const pool = new Pool();',
  '',
  "app.get('/users/:id', async (req, res) => {",
  '  const rows = await pool.query("SELECT id, name FROM users WHERE id = " + req.params.id);',
  '  res.json(rows.rows);',
  '});',
  '',
  'app.listen(3000);',
  '',
].join('\n');

function baseOptions(overrides: Partial<CliOptions> = {}): CliOptions {
  return {
    format: 'terminal',
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
    ...overrides,
  };
}

function captureConsole(): { out: () => string; err: () => string; restore: () => void } {
  const outLines: string[] = [];
  const errLines: string[] = [];
  const logSpy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    outLines.push(args.map(String).join(' '));
  });
  const errSpy = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    errLines.push(args.map(String).join(' '));
  });
  return {
    out: () => outLines.join('\n'),
    err: () => errLines.join('\n'),
    restore: () => {
      logSpy.mockRestore();
      errSpy.mockRestore();
    },
  };
}

/** Ejecuta `scan --verify` en JSON. Sin --output el informe va a stdout (como `dast`), no a un fichero. */
async function verifyJson(overrides: Partial<CliOptions> = {}): Promise<{ code: number; report: ScanResult & { target: string } }> {
  const io = captureConsole();
  try {
    const code = await runVerify(project, baseOptions({ format: 'json', verify: true, target: targetUrl, ...overrides }));
    return { code, report: JSON.parse(io.out()) };
  } finally {
    io.restore();
  }
}

beforeAll(async () => {
  target = http.createServer((req, res) => {
    requests++;
    const match = /^\/users\/([^/?]*)/.exec(req.url ?? '');
    if (match) {
      const id = decodeURIComponent(match[1]);
      if (id.includes("'")) {
        res.writeHead(500, { 'content-type': 'text/plain' });
        res.end('error: syntax error at or near "\'"');
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify([{ id: 1, name: 'alice' }]));
      return;
    }
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  });
  await new Promise<void>((resolve) => target.listen(0, '127.0.0.1', resolve));
  targetUrl = `http://127.0.0.1:${(target.address() as AddressInfo).port}`;
});

afterAll(async () => {
  target.closeAllConnections();
  await new Promise<void>((resolve) => target.close(() => resolve()));
});

beforeEach(() => {
  requests = 0;
  project = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-verify-project-'));
  fs.writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'verify-fixture', private: true }));
  fs.mkdirSync(path.join(project, 'src'));
  fs.writeFileSync(path.join(project, 'src', 'app.js'), PROJECT_SOURCE);
  // HOME temporal: el informe por defecto y la evidencia no tocan el ~/.basesec real.
  fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-verify-home-'));
  previousHome = process.env.HOME;
  process.env.HOME = fakeHome;
});

afterEach(() => {
  vi.restoreAllMocks();
  if (previousHome === undefined) delete process.env.HOME;
  else process.env.HOME = previousHome;
  fs.rmSync(project, { recursive: true, force: true });
  fs.rmSync(fakeHome, { recursive: true, force: true });
});

describe('scan --verify: correlación', () => {
  it('el SQLi estático aparece una vez, verificado con evidencia, y no hay DAST-101 aparte', async () => {
    const { code, report } = await verifyJson({ verifyDast: { evidence: false } });

    expect(code).toBe(0);
    const sqli = report.findings.filter((f) => f.ruleId === 'SQLI-001');
    expect(sqli).toHaveLength(1);
    expect(sqli[0].verified).toBe(true);
    expect(sqli[0].source).toBeUndefined();
    expect(sqli[0].evidence?.correlation).toBe('handler');
    // El payload SQLi lleva el canario en un comentario inocuo (`'/*BS…*/`) para que el agente lo vea en el sink.
    expect(sqli[0].evidence?.payload).toMatch(/^'\/\*BS[0-9a-f]{8}\*\/$/);
    expect(sqli[0].evidence?.oracle).toBe('sql-error');
    expect(report.findings.some((f) => f.ruleId === 'DAST-101')).toBe(false);
    expect(report.stats).toMatchObject({ dast: { target: targetUrl, mode: 'full' } });
  });

  it('la salida de terminal muestra el badge, el enlace, el resumen y la nota de no confirmado', async () => {
    const io = captureConsole();
    let code: number;
    try {
      code = await runVerify(project, baseOptions({ verify: true, target: targetUrl, verifyDast: { evidence: false } }));
    } finally {
      io.restore();
    }
    const text = io.out();

    expect(code).toBe(0);
    expect(text).toContain('✓ VERIFIED (runtime)');
    expect(text).toContain('Link: handler');
    expect(text).toMatch(/Verified at runtime: [1-9]\d* of \d+ static findings; \d+ runtime-only findings\./);
    expect(text).toContain('Findings not verified are "not confirmed at runtime", which is not the same as "not vulnerable".');
    expect(text).not.toMatch(/Verified at runtime:.*\b(safe|secure)\b/i);
  });

  it('sin --strict devuelve 0 aunque haya hallazgos; con --strict devuelve 1', async () => {
    const io = captureConsole();
    try {
      expect(await runVerify(project, baseOptions({ verify: true, target: targetUrl, verifyDast: { evidence: false } }))).toBe(0);
      expect(await runVerify(project, baseOptions({ verify: true, target: targetUrl, strict: true, verifyDast: { evidence: false } }))).toBe(1);
    } finally {
      io.restore();
    }
  });

  it('target caído: exit 2', async () => {
    const closed = http.createServer();
    await new Promise<void>((resolve) => closed.listen(0, '127.0.0.1', resolve));
    const port = (closed.address() as AddressInfo).port;
    await new Promise<void>((resolve) => closed.close(() => resolve()));

    const io = captureConsole();
    try {
      const code = await runVerify(project, baseOptions({ verify: true, target: `http://127.0.0.1:${port}`, verifyDast: { evidence: false } }));
      expect(code).toBe(2);
      expect(io.err()).toContain('Is the application running?');
    } finally {
      io.restore();
    }
  });

  it('suelo de Node: exit 3 y ninguna petición al target', async () => {
    vi.spyOn(Guard.prototype, 'assertNodeSupported').mockImplementation(() => {
      throw new GuardError('node-vulnerable', 'Node is below the patched floor');
    });
    const io = captureConsole();
    try {
      const code = await runVerify(project, baseOptions({ verify: true, target: targetUrl, verifyDast: { evidence: false } }));
      expect(code).toBe(3);
      expect(io.err()).toContain('Node is below the patched floor');
    } finally {
      io.restore();
    }
    expect(requests).toBe(0);
  });

  it('sin rutas extraídas no ataca: avisa y reporta solo el SAST', async () => {
    fs.writeFileSync(path.join(project, 'src', 'app.js'), "const { Pool } = require('pg');\nconst pool = new Pool();\nconst id = process.argv[2];\nmodule.exports = () => pool.query(\"SELECT 1 WHERE id = \" + id);\n");
    const io = captureConsole();
    let code: number;
    try {
      code = await runVerify(project, baseOptions({ verify: true, target: targetUrl, verifyDast: { evidence: false } }));
    } finally {
      io.restore();
    }
    expect(code).toBe(0);
    expect(io.err()).toContain('No routes extracted');
    expect(io.out()).not.toContain('Verified at runtime');
    expect(requests).toBe(0);
  });
});

describe('scan --verify: barandillas y fugas', () => {
  it('Node por debajo del suelo real: exit 3 antes de analizar o pedir nada; --dast-allow-vulnerable-node lo salta', async () => {
    const original = process.versions.node;
    Object.defineProperty(process.versions, 'node', { value: '20.0.0', configurable: true });
    const io = captureConsole();
    try {
      const blocked = await runVerify(project, baseOptions({ verify: true, target: targetUrl, verifyDast: { evidence: false } }));
      expect(blocked).toBe(3);
      expect(requests).toBe(0);
      const skipped = await runVerify(
        project,
        baseOptions({ verify: true, target: targetUrl, verifyDast: { evidence: false, allowVulnerableNode: true } }),
      );
      expect(skipped).toBe(0);
      expect(requests).toBeGreaterThan(0);
    } finally {
      Object.defineProperty(process.versions, 'node', { value: original, configurable: true });
      io.restore();
    }
  });

  it('host remoto sin --dast-allow-remote: exit 3 y ninguna petición', async () => {
    const io = captureConsole();
    try {
      const code = await runVerify(project, baseOptions({ verify: true, target: 'http://example.com', verifyDast: { evidence: false } }));
      expect(code).toBe(3);
      expect(io.err()).toContain('Remote host blocked');
      expect(io.err()).toContain('--dast-allow-remote');
    } finally {
      io.restore();
    }
    expect(requests).toBe(0);
  });

  it('host remoto con --dast-allow-remote pero sin terminal ni BASESEC_ALLOW_REMOTE: exit 3', async () => {
    const previousEnv = process.env.BASESEC_ALLOW_REMOTE;
    delete process.env.BASESEC_ALLOW_REMOTE;
    const stdin = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
    Object.defineProperty(process.stdin, 'isTTY', { value: false, configurable: true });
    const io = captureConsole();
    try {
      const code = await runVerify(
        project,
        baseOptions({ verify: true, target: 'http://example.com', verifyDast: { evidence: false, allowRemote: true } }),
      );
      expect(code).toBe(3);
      expect(io.err()).toContain('BASESEC_ALLOW_REMOTE=1');
    } finally {
      io.restore();
      if (stdin) Object.defineProperty(process.stdin, 'isTTY', stdin);
      else delete (process.stdin as { isTTY?: boolean }).isTTY;
      if (previousEnv !== undefined) process.env.BASESEC_ALLOW_REMOTE = previousEnv;
    }
    expect(requests).toBe(0);
  });

  it('validación antes del escaneo: --dast-rps, host remoto y --dast-max-requests inválidos salen 3 sin ejecutar el pipeline SAST', async () => {
    // Espía sobre Pipeline.run: si la validación fuera después, el escaneo se ejecutaría antes de fallar.
    const run = vi.spyOn(Pipeline.prototype, 'run');
    const io = captureConsole();
    let codes: number[] = [];
    try {
      codes = [
        await runVerify(project, baseOptions({ verify: true, target: targetUrl, verifyDast: { rps: 'abc', evidence: false } })),
        await runVerify(project, baseOptions({ verify: true, target: 'http://example.com', verifyDast: { evidence: false } })),
        await runVerify(project, baseOptions({ verify: true, target: targetUrl, verifyDast: { maxRequests: 0, evidence: false } })),
      ];
      expect(run).not.toHaveBeenCalled();

      // Control: con entrada válida sí se escanea (el espía observa la llamada real).
      expect(await runVerify(project, baseOptions({ verify: true, target: targetUrl, verifyDast: { evidence: false } }))).toBe(0);
      expect(run).toHaveBeenCalledTimes(1);
    } finally {
      io.restore();
    }
    expect(codes).toEqual([3, 3, 3]);
    expect(requests).toBeGreaterThan(0);
  });

  it('números inválidos y cabecera mal formada: exit 3 sin peticiones', async () => {
    const io = captureConsole();
    try {
      expect(await runVerify(project, baseOptions({ verify: true, target: targetUrl, verifyDast: { rps: 'abc' } }))).toBe(3);
      expect(await runVerify(project, baseOptions({ verify: true, target: targetUrl, verifyDast: { maxRequests: 0 } }))).toBe(3);
      expect(await runVerify(project, baseOptions({ verify: true, target: targetUrl, verifyDast: { headers: ['sin-dos-puntos'] } }))).toBe(3);
      expect(await runVerify(project, baseOptions({ verify: true, target: 'no es una url' }))).toBe(3);
    } finally {
      io.restore();
    }
    expect(requests).toBe(0);
  });

  it('ni las credenciales de la URL ni las de --dast-header aparecen en el informe, la evidencia o stderr', async () => {
    const authority = targetUrl.replace('http://', 'http://alice:hunter2@');
    const evidenceDir = path.join(fakeHome, 'evidence');
    const io = captureConsole();
    let code: number;
    let text = '';
    let stdout = '';
    try {
      code = await runVerify(
        project,
        baseOptions({
          format: 'json',
          verify: true,
          target: authority,
          quiet: false,
          verifyDast: { evidenceDir, headers: ['Authorization: Bearer SECRETTOKEN123', 'X-Api-Key: KEY987654'] },
        }),
      );
      stdout = io.out();
      text = `${stdout}\n${io.err()}`;
    } finally {
      io.restore();
    }
    expect(code).toBe(0);
    // El informe JSON va a stdout: debe ser JSON válido, y ya está en `text`, así que sus credenciales se comprueban.
    expect(() => JSON.parse(stdout)).not.toThrow();
    const files: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else files.push(full);
      }
    };
    walk(evidenceDir);
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) text += `\n${fs.readFileSync(file, 'utf-8')}`;
    for (const secret of ['hunter2', 'alice:', 'SECRETTOKEN123', 'KEY987654']) {
      expect(text).not.toContain(secret);
    }
  });
});

describe('scan sin --verify', () => {
  it('no envía ninguna petición HTTP', async () => {
    const io = captureConsole();
    try {
      await runScan(project, baseOptions({ format: 'terminal' }));
    } finally {
      io.restore();
    }
    expect(requests).toBe(0);
  });

  it('no añade el resumen ni la nota de verify', async () => {
    const io = captureConsole();
    try {
      await runScan(project, baseOptions({ format: 'terminal' }));
    } finally {
      io.restore();
    }
    expect(io.out()).toContain('SQLI-001');
    expect(io.out()).not.toContain('Verified at runtime');
    expect(io.out()).not.toContain('not confirmed at runtime');
    expect(io.out()).not.toContain('VERIFIED');
  });
});

describe('validación de flags de scan --verify', () => {
  it('exige --target', () => {
    expect(validateVerifyOptions({ verify: true, emitRoutes: false, ai: false, dastFlags: [] })).toBe('--verify requires --target <url>.');
  });

  it('es incompatible con --emit-routes y con --ai', () => {
    expect(validateVerifyOptions({ verify: true, target: 'http://x', emitRoutes: true, ai: false, dastFlags: [] })).toContain('--emit-routes');
    expect(validateVerifyOptions({ verify: true, target: 'http://x', emitRoutes: false, ai: true, dastFlags: [] })).toContain('--ai');
  });

  it('rechaza --target y --dast-* sin --verify', () => {
    expect(validateVerifyOptions({ verify: false, emitRoutes: false, ai: false, dastFlags: ['--target', '--dast-rps'] })).toBe(
      '--target, --dast-rps require --verify.',
    );
    expect(validateVerifyOptions({ verify: false, emitRoutes: false, ai: false, dastFlags: [] })).toBeUndefined();
  });

  it('acepta --verify con --target', () => {
    expect(validateVerifyOptions({ verify: true, target: targetUrl, emitRoutes: false, ai: false, dastFlags: ['--dast-rps'] })).toBeUndefined();
  });
});
