import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createVulnerableApp } from '../fixtures/vulnerable-app/server.mjs';
import { runDast } from '../../src/dast/runner';
import type { AgentEventSource } from '../../src/dast/agent-client';
import { linkAgentEvents } from '../../src/dast/agent-link';
import { buildPayloads } from '../../src/dast/payloads';
import { correlate } from '../../src/dast/correlate';
import type { RouteArtifact } from '../../src/framework/routes/types';
import { dynamicFinding } from '../../src/dast/probe';
import type { InjectionTrace } from '../../src/dast/inject';
import type { SinkEvent } from '../../src/dast/agent/channel';
import type { Finding } from '../../src/rules/types';
import type { ExtractedRoute } from '../../src/framework/routes/types';
import type { HttpResponse } from '../../src/dast/types';

const CANARY = 'BS0a1b2c3d';
const ROOT = '/proj';

const route: ExtractedRoute = {
  method: 'GET',
  path: '/ping',
  framework: 'express',
  filePath: 'src/routes.ts',
  line: 3,
  endLine: 9,
  hasAuth: false,
  params: [{ name: 'host', in: 'query' }],
  reachableFiles: [],
  staticFindings: [],
};

const response: HttpResponse = {
  status: 200,
  headers: {},
  body: 'ok',
  contentEncoding: null,
  bodyDecoded: true,
  url: 'http://127.0.0.1:3000/ping',
  redirects: [],
  timedOut: false,
  elapsedMs: 5,
};

function trace(canary: string, cls: InjectionTrace['cls']): InjectionTrace {
  return {
    canary,
    cls,
    endpoint: 'GET /ping',
    route,
    param: { name: 'host', in: 'query' },
    method: 'GET',
    url: `http://127.0.0.1:3000/ping?host=${canary}`,
    payloadText: `; echo ${canary}`,
    response,
  };
}

function sinkEvent(canary: string, stack: SinkEvent['stack'], sink = 'child_process.execFileSync'): SinkEvent {
  return { canary, sink, snippet: `echo ${canary}`, stack };
}

/** Hallazgo black-box (inyección sin agente) para GET /ping, como lo deja inject.ts. */
function blackBoxFinding(): Finding {
  return dynamicFinding({
    rule: { id: 'DAST-103', name: 'Command injection', category: 'command-injection', severity: 'critical', once: false },
    confidence: 'medium',
    endpoint: 'GET /ping',
    message: 'Parameter "host" (query) of GET /ping: the payload delays the response.',
    remediation: 'Do not pass request data to a shell.',
    references: [],
    codeSnippet: 'query parameter "host"',
    observation: { endpoint: 'GET /ping', url: 'http://127.0.0.1:3000/ping', method: 'GET', response, route, artifactTarget: ROOT },
    knownSecrets: [],
    payload: '; sleep 2',
    oracle: 'timing',
  });
}

const stack = [{ file: `${ROOT}/src/app.ts`, line: 17 }];

describe('linkAgentEvents', () => {
  it('raises an existing black-box injection to high and adds the sink location', () => {
    const findings = [blackBoxFinding()];
    const traces = new Map([[CANARY, trace(CANARY, 'cmdi')]]);
    linkAgentEvents(findings, [sinkEvent(CANARY, stack)], { trace: traces, knownSecrets: [], artifactTarget: ROOT });

    expect(findings).toHaveLength(1);
    const finding = findings[0];
    expect(finding.confidence).toBe('high');
    expect(finding.evidence?.correlation).toBe('agent');
    expect(finding.evidence?.sink).toEqual({ fn: 'child_process.execFileSync', filePath: 'src/app.ts', line: 17 });
    expect(finding.message).toContain('reached child_process.execFileSync at src/app.ts:17');
  });

  it('emits the DAST-1xx finding with high when the canary reaches a sink without a black-box hit', () => {
    const findings: Finding[] = [];
    const traces = new Map([[CANARY, trace(CANARY, 'sqli')]]);
    linkAgentEvents(findings, [sinkEvent(CANARY, stack, 'pg.Client.query')], {
      trace: traces,
      knownSecrets: [],
      artifactTarget: ROOT,
    });

    expect(findings).toHaveLength(1);
    const [finding] = findings;
    expect(finding.ruleId).toBe('DAST-101');
    expect(finding.confidence).toBe('high');
    expect(finding.evidence?.oracle).toBe('agent');
    expect(finding.evidence?.correlation).toBe('agent');
    expect(finding.evidence?.payload).toContain(CANARY);
    expect(finding.endpoint).toBe('GET /ping');
  });

  it('raises a black-box SQLi finding to high when a real sql-error payload carries its canary to pg.query', () => {
    const [sqlPayload] = buildPayloads('sqli', CANARY, 1).filter((p) => p.oracle === 'sql-error');
    expect(sqlPayload.text).toContain(CANARY);

    const blackBox = dynamicFinding({
      rule: { id: 'DAST-101', name: 'SQL injection', category: 'sql-injection', severity: 'critical', once: false },
      confidence: 'medium',
      endpoint: 'GET /ping',
      message: 'Parameter "host" (query) of GET /ping: SQL driver error signature.',
      remediation: 'Use parameterized queries.',
      references: [],
      codeSnippet: 'query parameter "host"',
      observation: { endpoint: 'GET /ping', url: 'http://127.0.0.1:3000/ping', method: 'GET', response, route, artifactTarget: ROOT },
      knownSecrets: [],
      payload: sqlPayload.text,
      oracle: 'sql-error',
    });
    const findings = [blackBox];
    const traces = new Map([[CANARY, { ...trace(CANARY, 'sqli'), payloadText: sqlPayload.text }]]);
    linkAgentEvents(findings, [sinkEvent(CANARY, stack, 'pg.query')], { trace: traces, knownSecrets: [], artifactTarget: ROOT });

    expect(findings).toHaveLength(1);
    const [finding] = findings;
    expect(finding.ruleId).toBe('DAST-101');
    expect(finding.confidence).toBe('high');
    expect(finding.evidence?.correlation).toBe('agent');
    expect(finding.evidence?.sink).toEqual({ fn: 'pg.query', filePath: 'src/app.ts', line: 17 });
    expect(finding.message).toContain('reached pg.query at src/app.ts:17');
  });

  it('ignores events whose canary is not from this run', () => {
    const findings: Finding[] = [];
    linkAgentEvents(findings, [sinkEvent('BSffffffff', stack)], {
      trace: new Map([[CANARY, trace(CANARY, 'cmdi')]]),
      knownSecrets: [],
    });
    expect(findings).toEqual([]);
  });

  it('keeps one change per (class, endpoint) when several sinks report', () => {
    const second = 'BS1111aaaa';
    const findings: Finding[] = [];
    const traces = new Map([
      [CANARY, trace(CANARY, 'sqli')],
      [second, trace(second, 'sqli')],
    ]);
    linkAgentEvents(findings, [sinkEvent(CANARY, stack, 'pg.Pool.query'), sinkEvent(second, stack, 'mysql2.Connection.query')], {
      trace: traces,
      knownSecrets: [],
      artifactTarget: ROOT,
    });
    expect(findings.filter((finding) => finding.ruleId === 'DAST-101')).toHaveLength(1);
  });

  it('does not confirm a class when the canary reaches a sink of another family', () => {
    const findings: Finding[] = [];
    const traces = new Map([
      [CANARY, trace(CANARY, 'xss')],
      ['BS2222bbbb', trace('BS2222bbbb', 'sqli')],
    ]);
    const events = [
      // XSS no tiene sink instrumentado: un canario de XSS en una consulta SQL no es un XSS.
      sinkEvent(CANARY, stack, 'pg.Client.query'),
      // Un canario de SQLi en un comando del sistema no es una inyección SQL.
      sinkEvent('BS2222bbbb', stack, 'child_process.exec'),
    ];
    linkAgentEvents(findings, events, { trace: traces, knownSecrets: [], artifactTarget: ROOT });
    expect(findings).toEqual([]);

    const black = [blackBoxFinding()];
    linkAgentEvents(black, [sinkEvent(CANARY, stack, 'mongodb.Collection.find')], {
      trace: new Map([[CANARY, trace(CANARY, 'cmdi')]]),
      knownSecrets: [],
    });
    expect(black[0].confidence).toBe('medium');
    expect(black[0].evidence?.sink).toBeUndefined();
  });

  it('confirms without a sink location when the event has no user frames', () => {
    const findings: Finding[] = [];
    linkAgentEvents(findings, [sinkEvent(CANARY, [])], {
      trace: new Map([[CANARY, trace(CANARY, 'cmdi')]]),
      knownSecrets: [],
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].confidence).toBe('high');
    expect(findings[0].evidence?.sink).toBeUndefined();
    expect(findings[0].message).toContain('reached child_process.execFileSync.');
  });
});

describe('correlate with an agent sink', () => {
  const artifact: RouteArtifact = {
    version: 1,
    generatedAt: '2026-08-02T10:00:00.000Z',
    target: ROOT,
    frameworks: ['express'],
    routes: [],
    unresolved: [],
  };

  function staticSql(filePath: string, line: number): Finding {
    return {
      ruleId: 'SQLI-001',
      ruleName: 'SQL injection',
      category: 'sql-injection',
      severity: 'high',
      filePath,
      line,
      column: 1,
      endLine: line,
      endColumn: 1,
      message: 'static',
      codeSnippet: '',
      remediation: '',
      references: [],
      confidence: 'medium',
    };
  }

  it('links the dynamic injection to the static finding at the sink line (+-2) by agent', () => {
    const dynamic = dynamicFinding({
      rule: { id: 'DAST-101', name: 'SQLi', category: 'sql-injection', severity: 'critical', once: false },
      confidence: 'high',
      endpoint: 'GET /users',
      message: 'confirmed',
      remediation: '',
      references: [],
      codeSnippet: '',
      observation: { endpoint: 'GET /users', url: 'http://127.0.0.1:3000/users', method: 'GET', response },
      knownSecrets: [],
      payload: `' OR ${CANARY}`,
      oracle: 'agent',
    });
    dynamic.evidence = { ...dynamic.evidence!, correlation: 'agent', sink: { fn: 'pg.query', filePath: 'src/db.ts', line: 18 } };

    const statics = [staticSql(`${ROOT}/src/other.ts`, 4), staticSql(`${ROOT}/src/db.ts`, 17), staticSql(`${ROOT}/src/db.ts`, 60)];
    const result = correlate(statics, [dynamic], artifact);

    const linked = result.findings.filter((finding) => finding.verified === true);
    expect(linked.map((finding) => finding.line)).toEqual([17]);
    expect(linked[0].evidence?.correlation).toBe('agent');
    expect(linked[0].confidence).toBe('high');
    expect(result.stats.dynamicOnly).toBe(0);
  });
});

describe('runDast with an agent source', () => {
  const app = createVulnerableApp();
  let origin: string;
  const surface = {
    source: 'routes-file' as const,
    stale: false,
    artifact: {
      version: 1 as const,
      generatedAt: '2026-08-02T10:00:00.000Z',
      target: path.join(os.tmpdir(), 'basesec-runner-agent-app'),
      frameworks: ['express'],
      routes: [{ ...route, path: '/items', filePath: 'src/items.ts', params: [{ name: 'role', in: 'query' as const }] }],
      unresolved: [],
    },
  };

  beforeAll(async () => {
    origin = await app.start();
  });
  afterAll(async () => {
    await app.stop();
  });

  /** Agente simulado: ve el canario del payload NoSQL que llegó al servidor y lo "recibe" en un sink de MongoDB. */
  function fakeAgent(sink: string): AgentEventSource {
    return {
      async collect() {
        const canaries = app.requests
          .filter((request) => request.includes('/items?role'))
          .flatMap((request) => decodeURIComponent(request).match(/BS[0-9a-f]{8}/g) ?? []);
        return canaries.map((canary) => ({
          canary,
          sink,
          snippet: canary,
          stack: [{ file: `${surface.artifact.target}/src/items.ts`, line: 12 }],
        }));
      },
      close(): void {
        return;
      },
    };
  }

  it('raises the black-box NoSQL finding to high with the sink and marks the run as agent', async () => {
    const plain = await runDast({ url: origin, surface, rules: ['DAST-102'], evidence: false, injectionDelaySeconds: 1 });
    const baseline = plain.findings.find((f) => f.ruleId === 'DAST-102');
    expect(baseline?.confidence).not.toBe('high');
    expect(baseline?.evidence?.sink).toBeUndefined();
    expect(plain.stats.dast?.agent).toBe(false);

    app.requests.length = 0;
    const result = await runDast({
      url: origin,
      surface,
      rules: ['DAST-102'],
      evidence: false,
      injectionDelaySeconds: 1,
      agent: fakeAgent('mongodb.Collection.find'),
    });
    const finding = result.findings.find((f) => f.ruleId === 'DAST-102');
    expect(finding?.confidence).toBe('high');
    expect(finding?.evidence?.correlation).toBe('agent');
    expect(finding?.evidence?.sink).toEqual({ fn: 'mongodb.Collection.find', filePath: 'src/items.ts', line: 12 });
    expect(result.findings.filter((f) => f.ruleId === 'DAST-102')).toHaveLength(1);
    expect(result.stats.dast?.agent).toBe(true);
  }, 60000);

  it('ignores a canary that reached a sink of another family', async () => {
    app.requests.length = 0;
    const result = await runDast({
      url: origin,
      surface,
      rules: ['DAST-102'],
      evidence: false,
      injectionDelaySeconds: 1,
      agent: fakeAgent('child_process.exec'),
    });
    const finding = result.findings.find((f) => f.ruleId === 'DAST-102');
    expect(finding?.evidence?.sink).toBeUndefined();
  }, 60000);
});
