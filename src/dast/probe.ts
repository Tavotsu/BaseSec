import type { Confidence, Finding, Severity } from '../rules/types';
import type { DastObservation, DastRule } from './types';
import { maskKnownSecrets, redactHeaders, redactHttp } from './redact-http';

export interface DynamicFindingArgs {
  rule: Pick<DastRule, 'id' | 'name' | 'category' | 'severity'>;
  /** Sobreescribe la severidad de la regla (DAST-004 medium para `*` con credentials). */
  severity?: Severity;
  confidence: Confidence;
  /** Origen (target) o "GET /path". */
  endpoint: string;
  message: string;
  remediation: string;
  references: string[];
  /** Línea de cabecera relevante; se redacta antes de guardarla. */
  codeSnippet: string;
  /** Observación de la que sale la evidencia. */
  observation: DastObservation;
  knownSecrets: string[];
}

/** C0 (salvo \t y \n) y C1. Se usa en textos multilínea. */
const CONTROL_CHARS = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g;
/** Igual que CONTROL_CHARS pero también elimina \n (y \r): para textos de una sola línea. */
const CONTROL_CHARS_SINGLE_LINE = /[\u0000-\u0008\u000A-\u001F\u007F-\u009F]/g;

/**
 * Elimina caracteres de control que podrían manipular la terminal al imprimir un hallazgo
 * (secuencias ANSI/OSC procedentes de un body hostil). Conserva \t y, salvo singleLine, \n.
 */
export function stripControl(text: string, singleLine = false): string {
  return text.replace(singleLine ? CONTROL_CHARS_SINGLE_LINE : CONTROL_CHARS, '');
}

/** Observación de la que sale cada hallazgo dinámico: enlace exacto, sin comparar textos. */
const FINDING_OBSERVATION = new WeakMap<Finding, DastObservation>();

/** Observación (intercambio HTTP) que originó un hallazgo creado con dynamicFinding. */
export function observationOf(finding: Finding): DastObservation | undefined {
  return FINDING_OBSERVATION.get(finding);
}

/** Construye un Finding dinámico a nivel de target o de endpoint. Todas las reglas DAST pasan por aquí. */
export function dynamicFinding(args: DynamicFindingArgs): Finding {
  const { rule, observation, knownSecrets } = args;
  const redactOptions = { knownSecrets };
  const scrub = (text: string): string => redactHttp(maskKnownSecrets(text, knownSecrets), redactOptions);

  const headerLines: string[] = [];
  for (const [name, value] of Object.entries(redactHeaders(observation.response.headers))) {
    for (const item of Array.isArray(value) ? value : [value]) {
      headerLines.push(`${name}: ${item}`);
    }
  }
  const response = [`HTTP ${observation.response.status}`, ...headerLines].join('\n');

  const finding: Finding = {
    ruleId: rule.id,
    ruleName: rule.name,
    category: rule.category,
    severity: args.severity ?? rule.severity,
    filePath: '',
    line: 0,
    column: 0,
    endLine: 0,
    endColumn: 0,
    message: stripControl(scrub(args.message)),
    codeSnippet: stripControl(scrub(args.codeSnippet), true),
    remediation: args.remediation,
    references: args.references,
    confidence: args.confidence,
    source: 'dynamic',
    verified: true,
    endpoint: stripControl(args.endpoint, true),
    evidence: {
      request: stripControl(scrub(`${observation.method} ${observation.url}`)),
      response: stripControl(scrub(response)),
      payload: '',
      oracle: 'header',
    },
  };
  FINDING_OBSERVATION.set(finding, observation);
  return finding;
}
