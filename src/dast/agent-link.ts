import * as path from 'node:path';
import type { SinkEvent } from './agent/channel';
import type { Finding } from '../rules/types';
import type { DastObservation } from './types';
import { dynamicFinding, observationOf, stripControl } from './probe';
import { CLASS_META } from './inject';
import type { InjectionTrace } from './inject';
import type { InjectionClass } from './payloads';

export interface AgentLinkContext {
  /** Canario -> envío que lo llevó (solo los de esta ejecución). */
  trace: ReadonlyMap<string, InjectionTrace>;
  knownSecrets: string[];
  /** Raíz del artefacto: las rutas del sink se muestran relativas a ella cuando caen dentro. */
  artifactTarget?: string;
}

interface SinkLocation {
  filePath: string;
  line: number;
}

/**
 * Sinks que confirman cada clase (prefijo del nombre del sink). Un canario que llega a un sink de otra familia no
 * confirma la clase: un payload XSS que acaba en una consulta SQL es una inyección SQL, no un XSS. XSS y redirección
 * abierta no tienen sink instrumentado, así que el agente no puede confirmarlas.
 */
const SINK_FAMILIES: Record<InjectionClass, readonly string[]> = {
  sqli: ['pg.', 'mysql2.'],
  nosqli: ['mongodb.'],
  cmdi: ['child_process.'],
  'path-traversal': ['fs.', 'fs/promises.'],
  xss: [],
  'open-redirect': [],
};

function sinkMatchesClass(sink: string, cls: InjectionClass): boolean {
  return SINK_FAMILIES[cls].some((prefix) => sink.startsWith(prefix));
}

function sinkLocation(event: SinkEvent, root: string | undefined): SinkLocation | undefined {
  const frame = event.stack[0];
  if (frame === undefined) return undefined;
  if (root !== undefined) {
    const relative = path.relative(root, frame.file);
    if (relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative)) {
      return { filePath: relative, line: frame.line };
    }
  }
  return { filePath: frame.file, line: frame.line };
}

/**
 * Enlaza los eventos del agente con los intentos de inyección (plan §4, §7.8). Un canario que llega a un sink confirma
 * la clase para ese endpoint: si ya había hallazgo black-box, sube a `high` con su sink; si no, se emite el DAST-1xx
 * con `high`. Muta `findings` (añade los nuevos al final). Un solo cambio por (clase, endpoint).
 */
export function linkAgentEvents(findings: Finding[], events: SinkEvent[], ctx: AgentLinkContext): void {
  const handled = new Set<string>();
  for (const event of events) {
    const entry = ctx.trace.get(event.canary);
    if (entry === undefined || !sinkMatchesClass(event.sink, entry.cls)) continue;
    const meta = CLASS_META[entry.cls];
    const key = `${meta.id} ${entry.endpoint}`;
    if (handled.has(key)) continue;
    handled.add(key);

    const location = sinkLocation(event, ctx.artifactTarget);
    const reached = stripControl(
      location !== undefined ? `${event.sink} at ${location.filePath}:${location.line}` : event.sink,
      true,
    );
    const sink =
      location !== undefined ? { fn: stripControl(event.sink, true), filePath: location.filePath, line: location.line } : undefined;

    const existing = findings.find(
      (finding) => finding.ruleId === meta.id && observationOf(finding)?.endpoint === entry.endpoint,
    );
    if (existing !== undefined) {
      existing.confidence = 'high';
      existing.message = `${existing.message} The payload reached ${reached}.`;
      if (existing.evidence !== undefined) {
        existing.evidence.correlation = 'agent';
        if (sink !== undefined) existing.evidence.sink = sink;
      }
      continue;
    }

    const observation: DastObservation = {
      endpoint: entry.endpoint,
      url: entry.url,
      method: entry.method,
      response: entry.response,
      route: entry.route,
      ...(ctx.artifactTarget !== undefined ? { artifactTarget: ctx.artifactTarget } : {}),
    };
    const finding = dynamicFinding({
      rule: { id: meta.id, name: meta.name, category: meta.category, severity: meta.severity, once: false },
      confidence: 'high',
      endpoint: entry.endpoint,
      message: `Parameter "${entry.param.name}" (${entry.param.in}) of ${entry.endpoint}: the payload reached ${reached}.`,
      remediation: meta.remediation,
      references: meta.references,
      codeSnippet: `${entry.param.in} parameter "${entry.param.name}"`,
      observation,
      knownSecrets: ctx.knownSecrets,
      payload: entry.payloadText,
      oracle: 'agent',
    });
    if (finding.evidence !== undefined) {
      finding.evidence.correlation = 'agent';
      if (sink !== undefined) finding.evidence.sink = sink;
    }
    findings.push(finding);
  }
}
