import type { Finding } from '../../rules/types';
import type { DastRule } from '../types';
import { dynamicFinding } from '../probe';
import { logger } from '../../utils/logger';
import { usableObservations } from './helpers';

/** Ubicación de un frame: ruta absoluta, node: o file:// seguida de :línea:columna. Anclada y lineal. */
const FRAME_LOCATION = /^(?:\/|[A-Za-z]:\\|node:|file:\/\/)[^\n]*:\d+:\d+$/;
/** Acota el trabajo de las regex ante bodies hostiles. */
const SCAN_LIMIT_CHARS = 262144;
const LINE_LIMIT_CHARS = 1000;
const SNIPPET_LIMIT_CHARS = 200;
/** Secuencias ANSI CSI (ESC [ ... letra) y OSC (ESC ] ... BEL o ESC \). Lineales: clases de caracteres disjuntas. */
const ANSI_CSI = /\u001b\[[0-9;?]*[ -/]*[@-~]/g;
const ANSI_OSC = /\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)/g;
/** Controles C0 y C1 sueltos. Conserva \t (U+0009), \n (U+000A) y \r (U+000D). */
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;

/**
 * Normaliza formas habituales de incrustar un stack: el handler por defecto de Express usa "<br>" y "&nbsp;"
 * en una sola línea, y las respuestas JSON llevan los saltos como "\n" literal.
 * Antes de partir en líneas se eliminan secuencias ANSI completas y controles sueltos, para que un
 * "\u001b[2J" o un "\u0000" delante de "at" no oculte un frame. El límite de tamaño va primero.
 */
function normalizeBody(body: string): string {
  return body
    .slice(0, SCAN_LIMIT_CHARS)
    .replace(ANSI_CSI, '')
    .replace(ANSI_OSC, '')
    .replace(CONTROL_CHARS, '')
    .replace(/<br\s{0,8}\/?>/gi, '\n')
    .replace(/&nbsp;/g, ' ')
    .replace(/(?:\\r)?\\n/g, '\n');
}

/** true si la línea es un frame de stack de Node: "at fn (/ruta/x.js:10:5)" o "at /ruta/x.js:10:5". */
function isStackFrame(rawLine: string): boolean {
  const line = rawLine.slice(0, LINE_LIMIT_CHARS).trim().replace(/[\s"',}\]]+$/, '');
  if (!/^at\s/.test(line)) return false;
  const rest = line.slice(3).trim();
  if (rest.endsWith(')')) {
    const open = rest.lastIndexOf('(');
    return open !== -1 && FRAME_LOCATION.test(rest.slice(open + 1, -1).trim());
  }
  return FRAME_LOCATION.test(rest);
}

/** Primera línea de stack del body, recortada. undefined si no hay stack. */
function firstStackFrame(body: string): string | undefined {
  for (const raw of normalizeBody(body).split(/\r?\n/)) {
    if (isStackFrame(raw)) return raw.slice(0, LINE_LIMIT_CHARS).trim().slice(0, SNIPPET_LIMIT_CHARS);
  }
  return undefined;
}

export const DAST006: DastRule = {
  id: 'DAST-006',
  name: 'Stack trace exposed',
  description: 'A 5xx response body contains a Node.js stack trace with internal file paths.',
  category: 'error-handling',
  severity: 'high',
  once: false,
  async probe(ctx) {
    try {
      const findings: Finding[] = [];
      for (const observation of usableObservations(ctx.observations)) {
        const { response } = observation;
        if (response.status < 500 || !response.bodyDecoded) continue;
        const frame = firstStackFrame(response.body);
        if (frame === undefined) continue;

        findings.push(
          dynamicFinding({
            rule: DAST006,
            confidence: 'high',
            endpoint: observation.endpoint,
            message: `Server responded HTTP ${response.status} with a stack trace exposing internal file paths.`,
            remediation:
              'Do not return error stacks to clients. Use a generic error handler that logs the stack server-side and responds with a generic message. In Express, use a final error middleware and set NODE_ENV=production.',
            references: [
              'https://cwe.mitre.org/data/definitions/209.html',
              'https://owasp.org/www-community/Improper_Error_Handling',
            ],
            codeSnippet: frame,
            observation,
            knownSecrets: ctx.knownSecrets,
          }),
        );
      }
      return findings;
    } catch (e) {
      logger.warn('DAST-006 no pudo evaluarse', e);
      return [];
    }
  },
};
