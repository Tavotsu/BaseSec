import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import type { AddressInfo } from 'node:net';
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import prompts from 'prompts';
import { runDastCommand } from '../../src/cli/commands/dast';

vi.mock('prompts', () => ({ default: vi.fn() }));

let server: http.Server;
let url: string;
let workDir: string;
let fakeHome: string;
let previousHome: string | undefined;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'x-powered-by': 'Express',
      'set-cookie': 'sid=abc123; Path=/',
    });
    res.end('<html><body>hello</body></html>');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(() => {
  // Un directorio dentro del cwd: así la salida no pide confirmación y se limpia al terminar.
  workDir = fs.mkdtempSync(path.join(process.cwd(), 'basesec-dast-cli-'));
  // HOME temporal: el artefacto de rutas por defecto (~/.basesec/routes) del repo no puede cambiar el modo de estos tests.
  previousHome = process.env.HOME;
  fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-dast-home-'));
  process.env.HOME = fakeHome;
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(console, 'log').mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
  if (previousHome === undefined) delete process.env.HOME;
  else process.env.HOME = previousHome;
  fs.rmSync(fakeHome, { recursive: true, force: true });
  fs.rmSync(workDir, { recursive: true, force: true });
});

function evidenceDir(): string {
  return path.join(workDir, 'evidence');
}

function baseOptions(overrides: Record<string, unknown> = {}): Parameters<typeof runDastCommand>[1] {
  return { quiet: true, evidenceDir: evidenceDir(), ...overrides } as Parameters<typeof runDastCommand>[1];
}

describe('basesec dast command', () => {
  it('exits 0 and writes JSON with stats.dast', async () => {
    const output = path.join(workDir, 'report.json');
    const code = await runDastCommand(url, baseOptions({ format: 'json', output }));

    expect(code).toBe(0);
    const report = JSON.parse(fs.readFileSync(output, 'utf-8'));
    expect(report.stats.dast.mode).toBe('no-source');
    expect(report.stats.dast.target).toBe(url);
    expect(report.findings.length).toBeGreaterThan(0);
  });

  it('exits 1 with --strict when there are findings', async () => {
    const output = path.join(workDir, 'strict.json');
    const code = await runDastCommand(url, baseOptions({ format: 'json', output, strict: true }));
    expect(code).toBe(1);
  });

  it('exits 3 for rps 0', async () => {
    expect(await runDastCommand(url, baseOptions({ rps: 0 }))).toBe(3);
  });

  it('exits 3 for a non-integer request budget given as text', async () => {
    expect(await runDastCommand(url, baseOptions({ maxRequests: '12abc' }))).toBe(3);
  });

  it('exits 3 for a public host without a terminal and without BASESEC_ALLOW_REMOTE', async () => {
    const previous = process.env.BASESEC_ALLOW_REMOTE;
    delete process.env.BASESEC_ALLOW_REMOTE;
    try {
      const code = await runDastCommand('http://203.0.113.10:9/', baseOptions({ allowRemote: false }));
      expect(code).toBe(3);
    } finally {
      if (previous !== undefined) process.env.BASESEC_ALLOW_REMOTE = previous;
    }
  });

  it('exits 2 when the target does not answer', async () => {
    const closed = http.createServer();
    await new Promise<void>((resolve) => closed.listen(0, '127.0.0.1', resolve));
    const port = (closed.address() as AddressInfo).port;
    await new Promise<void>((resolve) => closed.close(() => resolve()));

    expect(await runDastCommand(`http://127.0.0.1:${port}`, baseOptions())).toBe(2);
  });

  it('exits 3 for a $env: header whose variable does not exist', async () => {
    delete process.env.BASESEC_CLI_TEST_MISSING_VAR;
    const code = await runDastCommand(
      url,
      baseOptions({ header: ['Authorization: Bearer $env:BASESEC_CLI_TEST_MISSING_VAR'] }),
    );
    expect(code).toBe(3);
  });

  it('exits 3 for a malformed --header', async () => {
    expect(await runDastCommand(url, baseOptions({ header: ['no-colon-here'] }))).toBe(3);
  });
});

function closedPort(): Promise<number> {
  return new Promise((resolve) => {
    const closed = http.createServer();
    closed.listen(0, '127.0.0.1', () => {
      const port = (closed.address() as AddressInfo).port;
      closed.close(() => resolve(port));
    });
  });
}

function writeConfig(dast: Record<string, unknown>): string {
  const file = path.join(workDir, 'basesec.config.json');
  fs.writeFileSync(file, JSON.stringify({ dast }));
  return file;
}

describe('basesec dast command review hardening', () => {
  const promptsMock = vi.mocked(prompts);
  const stdinTty = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
  let previousEnv: string | undefined;

  beforeEach(() => {
    promptsMock.mockReset();
    previousEnv = process.env.BASESEC_ALLOW_REMOTE;
    delete process.env.BASESEC_ALLOW_REMOTE;
  });

  afterEach(() => {
    if (stdinTty) Object.defineProperty(process.stdin, 'isTTY', stdinTty);
    else delete (process.stdin as { isTTY?: boolean }).isTTY;
    if (previousEnv !== undefined) process.env.BASESEC_ALLOW_REMOTE = previousEnv;
  });

  function setTty(value: boolean): void {
    Object.defineProperty(process.stdin, 'isTTY', { value, configurable: true });
  }

  it('exits 3 without requests when the user cancels the remote confirmation (Ctrl-C)', async () => {
    setTty(true);
    promptsMock.mockResolvedValue({});
    const code = await runDastCommand('http://203.0.113.10:9/', baseOptions({ allowRemote: true }));
    expect(code).toBe(3);
    expect(promptsMock).toHaveBeenCalledTimes(1);
    // El prompt no puede ensuciar stdout (JSON).
    expect(promptsMock.mock.calls[0][0]).toMatchObject({ type: 'text', stdout: process.stderr });
  });

  it('exits 3 before the remote probe or the confirmation when Node is vulnerable', async () => {
    setTty(true);
    promptsMock.mockResolvedValue({ value: '203.0.113.10' });
    const original = process.versions.node;
    Object.defineProperty(process.versions, 'node', { value: '20.0.0', configurable: true });
    try {
      expect(await runDastCommand('http://203.0.113.10:9/', baseOptions({ allowRemote: true }))).toBe(3);
    } finally {
      Object.defineProperty(process.versions, 'node', { value: original, configurable: true });
    }
    expect(promptsMock).not.toHaveBeenCalled();
  });

  it('allowVulnerableNode skips the Node check on a vulnerable Node', async () => {
    const original = process.versions.node;
    const output = path.join(workDir, 'vulnerable-node.json');
    Object.defineProperty(process.versions, 'node', { value: '20.0.0', configurable: true });
    try {
      const code = await runDastCommand(
        url,
        baseOptions({ allowVulnerableNode: true, format: 'json', output }),
      );
      expect(code).toBe(0);
    } finally {
      Object.defineProperty(process.versions, 'node', { value: original, configurable: true });
    }
    expect(fs.existsSync(output)).toBe(true);
  });

  it('exits 3 when the typed host does not match the hostname', async () => {
    setTty(true);
    promptsMock.mockResolvedValue({ value: '203.0.113.11' });
    expect(await runDastCommand('http://203.0.113.10:9/', baseOptions({ allowRemote: true }))).toBe(3);
  });

  it('allowRemote in the config file does not skip the confirmation or the non-TTY requirement', async () => {
    const config = writeConfig({ allowRemote: true });
    setTty(false);
    expect(await runDastCommand('http://203.0.113.10:9/', baseOptions({ config }))).toBe(3);
    expect(promptsMock).not.toHaveBeenCalled();

    setTty(true);
    promptsMock.mockResolvedValue({ value: 'nope' });
    expect(await runDastCommand('http://203.0.113.10:9/', baseOptions({ config }))).toBe(3);
    expect(promptsMock).toHaveBeenCalledTimes(1);
  });

  it('config evidence:false is honoured unless --evidence is explicit', async () => {
    const config = writeConfig({ evidence: false });
    const noFlag = await runDastCommand(url, baseOptions({ config, format: 'json', output: path.join(workDir, 'a.json') }));
    expect(noFlag).toBe(0);
    expect(fs.existsSync(evidenceDir())).toBe(false);

    const explicit = await runDastCommand(
      url,
      baseOptions({ config, evidence: true, format: 'json', output: path.join(workDir, 'b.json') }),
    );
    expect(explicit).toBe(0);
    expect(fs.existsSync(evidenceDir())).toBe(true);

    fs.rmSync(evidenceDir(), { recursive: true, force: true });
    await runDastCommand(url, baseOptions({ evidence: false, format: 'json', output: path.join(workDir, 'c.json') }));
    expect(fs.existsSync(evidenceDir())).toBe(false);
  });

  it('exits 3 when --evidence-dir points to a file, and resolves relative paths with ..', async () => {
    const file = path.join(workDir, 'a-file');
    fs.writeFileSync(file, 'x');
    expect(await runDastCommand(url, baseOptions({ evidenceDir: file }))).toBe(3);
    expect(await runDastCommand(url, baseOptions({ evidenceDir: path.join(file, 'sub') }))).toBe(3);

    const relative = path.join(path.relative(process.cwd(), workDir), 'x', '..', 'ev');
    const output = path.join(workDir, 'rel.json');
    expect(await runDastCommand(url, baseOptions({ evidenceDir: relative, format: 'json', output }))).toBe(0);
    const report = JSON.parse(fs.readFileSync(output, 'utf-8'));
    expect(path.isAbsolute(report.stats.dast.evidenceDir)).toBe(true);
    expect(report.stats.dast.evidenceDir).not.toContain('..');
  });

  it('con -f json y sin --output el informe va a stdout y no se escribe en ~/.basesec', async () => {
    const code = await runDastCommand(url, baseOptions({ format: 'json' }));

    expect(code).toBe(0);
    const logged = vi.mocked(console.log).mock.calls.flat().join('\n');
    expect(() => JSON.parse(logged)).not.toThrow();
    expect(fs.existsSync(path.join(fakeHome, '.basesec'))).toBe(false);
  });

  it('keeps credentials and header values out of stdout, stderr, the report and the error messages', async () => {
    const PASS = 'zq9-userpass-UNIQUE';
    const TOKEN = 'zq9-token-UNIQUE-4411';
    const stderrChunks: string[] = [];
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
      stderrChunks.push(String(chunk));
      return true;
    });
    const withCreds = url.replace('http://', `http://bob:${PASS}@`);
    const output = path.join(workDir, 'creds.json');

    const code = await runDastCommand(
      withCreds,
      baseOptions({ quiet: false, format: 'json', output, header: [`Authorization: Bearer ${TOKEN}`] }),
    );
    expect(code).toBe(0);

    const port = await closedPort();
    const unreachable = await runDastCommand(
      `http://bob:${PASS}@127.0.0.1:${port}`,
      baseOptions({ quiet: false, header: [`X-Api-Key: ${TOKEN}`] }),
    );
    expect(unreachable).toBe(2);

    const logged = [
      ...stderrChunks,
      ...vi.mocked(console.error).mock.calls.flat(),
      ...vi.mocked(console.log).mock.calls.flat(),
    ].join('\n');
    const report = fs.readFileSync(output, 'utf-8');
    const evidenceFiles = fs.readdirSync(evidenceDir(), { recursive: true, encoding: 'utf-8' })
      .map((entry) => path.join(evidenceDir(), entry))
      .filter((entry) => fs.statSync(entry).isFile())
      .map((file) => fs.readFileSync(file, 'utf-8'))
      .join('\n');

    for (const text of [logged, report, evidenceFiles]) {
      expect(text).not.toContain(PASS);
      expect(text).not.toContain(TOKEN);
    }
    expect(JSON.parse(report).stats.dast.target).toBe(url);
    expect(logged).toContain('Target unreachable');
  });

  it('writes progress to stderr only', async () => {
    const stderrChunks: string[] = [];
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
      stderrChunks.push(String(chunk));
      return true;
    });
    const output = path.join(workDir, 'progress.json');
    await runDastCommand(url, baseOptions({ quiet: false, format: 'json', output }));

    expect(stderrChunks.join('')).toMatch(/\[\d+\/\d+\]/);
    const stdout = vi.mocked(console.log).mock.calls.flat().join('\n');
    expect(stdout).not.toMatch(/\[\d+\/\d+\]/);
  });

  it('does not change the exit code of an incomplete analysis', async () => {
    const output = path.join(workDir, 'incomplete.json');
    const code = await runDastCommand(url, baseOptions({ maxRequests: 1, format: 'json', output }));
    expect(code).toBe(0);
    expect(JSON.parse(fs.readFileSync(output, 'utf-8')).stats.dast.incomplete).toBe('budget');
  });
});

describe('basesec dast --probe-rate-limit', () => {
  it('the flag activates DAST-010 in the JSON report', async () => {
    const output = path.join(workDir, 'probe.json');
    const code = await runDastCommand(url, baseOptions({ format: 'json', output, probeRateLimit: true }));

    expect(code).toBe(0);
    const report = JSON.parse(fs.readFileSync(output, 'utf-8'));
    const ids = report.findings.map((finding: { ruleId: string }) => finding.ruleId);
    expect(ids).toContain('DAST-010');
  });

  it('without the flag DAST-010 is not in the report', async () => {
    const output = path.join(workDir, 'no-probe.json');
    await runDastCommand(url, baseOptions({ format: 'json', output }));

    const report = JSON.parse(fs.readFileSync(output, 'utf-8'));
    const ids = report.findings.map((finding: { ruleId: string }) => finding.ruleId);
    expect(ids).not.toContain('DAST-010');
  });
});
