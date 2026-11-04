import * as crypto from 'node:crypto';
import { logger } from '../utils/logger';

/**
 * Catálogo de payloads de la inyección activa (plan §7.5). POLÍTICA NO DESTRUCTIVA (innegociable): ningún
 * payload modifica ni destruye estado. Solo lecturas, condiciones siempre verdaderas, delays acotados,
 * lectura de ficheros de solo lectura conocidos y canarios. `findForbiddenFragment` la materializa y
 * tests/dast/payloads.test.ts la verifica sobre todo el catálogo.
 */

export type InjectionClass = 'sqli' | 'nosqli' | 'cmdi' | 'path-traversal' | 'xss' | 'open-redirect';

export type PayloadOracle = 'reflection' | 'sql-error' | 'timing' | 'diff' | 'redirect';

export interface Payload {
  class: InjectionClass;
  /** Plantilla; {{canary}} se sustituye por BS<hex>, {{delay}} por los segundos de delay. */
  template: string;
  /** Oráculo que evalúa la respuesta a este payload. */
  oracle: PayloadOracle;
  /** Para query usa notación de corchetes (NoSQL): el nombre efectivo del parámetro se deriva. */
  bracket?: string;
  /** true si necesita una petición de control (timing). */
  timing?: boolean;
}

export interface ConcretePayload {
  class: InjectionClass;
  oracle: PayloadOracle;
  /** Valor final con canario y delay sustituidos: es lo que viaja en la petición. */
  text: string;
  /** Canario embebido en `text` (o el de la llamada). */
  canary: string;
  bracket?: string;
  timing?: boolean;
}

/** Delay máximo de cualquier payload (§0: como mucho 2 s). */
export const MAX_DELAY_SECONDS = 2;

export const PAYLOAD_CLASSES: InjectionClass[] = ['sqli', 'nosqli', 'cmdi', 'path-traversal', 'xss', 'open-redirect'];

/**
 * Fragmentos prohibidos (§0), comparados sin distinguir mayúsculas. `>` cubre `>>`. Es una red de seguridad
 * además de la lista blanca de tests/dast/payloads.test.ts: si alguien añade un payload nuevo, el test exige
 * dar de alta su forma exacta.
 */
export const FORBIDDEN_FRAGMENTS: readonly string[] = [
  'drop ',
  'delete ',
  'truncate',
  'update ',
  'insert ',
  'alter ',
  'create ',
  'rm ',
  'mkfs',
  '>',
  'shutdown',
  'reboot',
  '; rm',
  // Un backtick ejecuta lo que lleve dentro: ningún payload lo usa, así que se prohíbe entero.
  '`',
  'xp_cmdshell',
  'outfile',
  'dumpfile',
  '/dev/tcp',
];

/**
 * Verbos que modifican estado, ejecutan, abren canales o escriben, como palabra completa. Se aplican sobre el
 * texto normalizado (decodificado, sin comentarios SQL y con los blancos colapsados), de modo que
 * `drop/**` + `/table`, `DROP%09TABLE` o `rm%20-rf` no se cuelan por no llevar un espacio literal.
 */
const FORBIDDEN_WORDS =
  /\b(?:drop|delete|truncate|update|insert|alter|create|replace|rename|merge|grant|revoke|into|exec|execute|call|eval|system|passthru|kill|pkill|shutdown|reboot|halt|poweroff|mkfs|rm|rmdir|unlink|mv|dd|chmod|chown|mkdir|touch|tee|wget|curl|nc|ncat|netcat|sudo|copy|attach|detach|vacuum|pragma|format|del|erase)\b/;

const MAX_DECODE_ROUNDS = 3;

function decodeOnce(text: string): string {
  try {
    return decodeURIComponent(text.replace(/\+/g, ' '));
  } catch (e) {
    // Una secuencia % mal formada no es codificación: se analiza tal cual.
    logger.warn('Payload con una secuencia % no decodificable', e);
    return text;
  }
}

/** Forma canónica para la política: decodifica hasta MAX_DECODE_ROUNDS veces, quita comentarios SQL y colapsa blancos. */
function normalizeForPolicy(text: string): string {
  let out = text;
  for (let round = 0; round < MAX_DECODE_ROUNDS; round++) {
    const decoded = decodeOnce(out);
    if (decoded === out) break;
    out = decoded;
  }
  return out
    .replace(/\0/g, '')
    .replace(/\/\*[^*]*\*\//g, ' ')
    .toLowerCase()
    .replace(/\s+/g, ' ');
}

/**
 * Plantillas. Ninguna contiene `>` (prohibido en §0), así que las XSS usan etiquetas sin cerrar; el `>` lo
 * pone el propio HTML de la página que refleja el payload. Los delays van de 0 a 2 s.
 */
export const PAYLOAD_TEMPLATES: readonly Payload[] = [
  // El canario va en un comentario inocuo (SQL `/* */`, shell `#`) para que llegue como texto al sink del agente.
  { class: 'sqli', template: "'/*{{canary}}*/", oracle: 'sql-error' },
  { class: 'sqli', template: "' OR '1'='1/*{{canary}}*/", oracle: 'sql-error' },
  { class: 'sqli', template: "1' OR '1'='1'/*{{canary}}*/--", oracle: 'sql-error' },
  { class: 'sqli', template: "1' AND SLEEP({{delay}})/*{{canary}}*/-- -", oracle: 'timing', timing: true },
  { class: 'sqli', template: "1'; SELECT pg_sleep({{delay}})/*{{canary}}*/-- -", oracle: 'timing', timing: true },
  { class: 'nosqli', template: '{{canary}}', oracle: 'diff', bracket: '[$ne]' },
  { class: 'nosqli', template: '', oracle: 'diff', bracket: '[$gt]' },
  { class: 'cmdi', template: '; sleep {{delay}} #{{canary}}', oracle: 'timing', timing: true },
  { class: 'cmdi', template: '| sleep {{delay}} #{{canary}}', oracle: 'timing', timing: true },
  { class: 'cmdi', template: '$(sleep {{delay}}) #{{canary}}', oracle: 'timing', timing: true },
  { class: 'cmdi', template: '; echo {{canary}}', oracle: 'reflection' },
  { class: 'cmdi', template: '$(echo {{canary}})', oracle: 'reflection' },
  { class: 'path-traversal', template: '../../../../etc/passwd', oracle: 'reflection' },
  { class: 'path-traversal', template: '..\\..\\..\\..\\windows\\win.ini', oracle: 'reflection' },
  { class: 'path-traversal', template: '....//....//etc/passwd', oracle: 'reflection' },
  { class: 'xss', template: '"<img src=x onerror=alert({{canary}})', oracle: 'reflection' },
  { class: 'xss', template: "'\"<i{{canary}}", oracle: 'reflection' },
  { class: 'open-redirect', template: 'https://bs-{{canary}}.example.net', oracle: 'redirect' },
  { class: 'open-redirect', template: '//bs-{{canary}}.example.net', oracle: 'redirect' },
];

const CANARY_PATTERN = /^BS[0-9a-f]{8}$/;

/** Canario único por envío: BS + 8 hex de crypto.randomBytes(4) (plan §7.5; no randomUUID ni randomInt). */
export function newCanary(): string {
  return `BS${crypto.randomBytes(4).toString('hex')}`;
}

/**
 * Devuelve el primer fragmento prohibido que contiene `text` (tal cual, decodificado de la URL o con los blancos
 * normalizados), o undefined si es admisible. Sirve igual para una plantilla, un payload concreto o la URL con la
 * que viaja.
 */
export function findForbiddenFragment(text: string): string | undefined {
  const forms = [text.toLowerCase(), normalizeForPolicy(text)];
  for (const form of forms) {
    const literal = FORBIDDEN_FRAGMENTS.find((fragment) => form.includes(fragment));
    if (literal !== undefined) return literal;
    const word = FORBIDDEN_WORDS.exec(form);
    if (word !== null) return word[0];
  }
  return undefined;
}

/**
 * Segundos de delay efectivos para un valor pedido por el usuario o por un test: entero entre 1 y MAX_DELAY_SECONDS.
 * Un valor ausente o no finito da el máximo; uno alto se topa en vez de provocar un fallo a mitad de análisis.
 */
export function clampDelaySeconds(requested: number | undefined): number {
  if (requested === undefined || !Number.isFinite(requested)) return MAX_DELAY_SECONDS;
  return Math.min(MAX_DELAY_SECONDS, Math.max(1, Math.floor(requested)));
}

/**
 * Payloads concretos de una clase: sustituye {{canary}} y {{delay}}. El orden es el del catálogo, así que el
 * índice de un payload es el mismo para cualquier canario o delay.
 */
export function buildPayloads(cls: InjectionClass, canary: string, delaySeconds: number): ConcretePayload[] {
  if (!CANARY_PATTERN.test(canary)) throw new RangeError('El canario debe tener la forma BS<8 hex>');
  if (!Number.isInteger(delaySeconds) || delaySeconds < 0 || delaySeconds > MAX_DELAY_SECONDS) {
    throw new RangeError(`El delay debe ser un entero entre 0 y ${MAX_DELAY_SECONDS} segundos`);
  }
  return PAYLOAD_TEMPLATES.filter((payload) => payload.class === cls).map((payload) => {
    const text = payload.template
      .split('{{canary}}')
      .join(canary)
      .split('{{delay}}')
      .join(String(delaySeconds));
    return {
      class: payload.class,
      oracle: payload.oracle,
      text,
      canary,
      ...(payload.bracket !== undefined ? { bracket: payload.bracket } : {}),
      ...(payload.timing === true ? { timing: true } : {}),
    };
  });
}
