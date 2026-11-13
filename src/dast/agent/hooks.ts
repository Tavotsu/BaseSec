import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { agentWarn } from './channel';
import type { SinkEvent, StackFrame } from './channel';

type Report = (event: SinkEvent) => void;
type AnyFunction = (...args: unknown[]) => unknown;
type Exports = Record<string, unknown>;

/**
 * Parcheo de sinks (plan §7.9). Cada envoltorio observa los argumentos indicados, y SIEMPRE llama al original con los
 * mismos argumentos y devuelve su resultado. Ningún fallo del agente debe verse en la app: por eso cada paso va en su
 * propio try/catch y los errores solo se anuncian por stderr.
 *
 * `require` (no `import * as`) para los builtins: en el bundle CJS un namespace import es una copia y el parche no
 * llegaría al módulo real.
 */

const CANARY = /BS[0-9a-f]{8}/;
const CANARY_LENGTH = 10;
const MAX_TEXT_LENGTH = 64 * 1024;
const MAX_ITEMS = 100;
const SNIPPET_CONTEXT = 95;
const MAX_FRAMES = 20;
const PATCHED = Symbol.for('basesec.agent.patched');
const PROMISIFY_CUSTOM = Symbol.for('nodejs.util.promisify.custom');
/** El custom de promisify se define aparte (envuelto); copiarlo tal cual choca con su descriptor no configurable. */
const SKIPPED_KEYS: ReadonlySet<PropertyKey> = new Set(['prototype', 'arguments', 'caller', PATCHED, PROMISIFY_CUSTOM]);
/** Ruta de un frame: absoluta, con file:// opcional, seguida de línea y columna. */
const FRAME = /\(?((?:file:\/\/)?\/[^()]*?|[A-Za-z]:\\[^()]*?):(\d+):\d+\)?$/;

/** Este mismo fichero (el bundle): sus frames no son del usuario. */
const SELF = typeof __filename === 'string' ? __filename : '';

/**
 * true mientras corre un sink instrumentado. Node llama internamente a otros sinks (exec llama a
 * module.exports.execFile, pg.Pool.query a Client.query): solo el más externo informa, para no duplicar el evento.
 */
let active = false;

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

const MAX_DEPTH = 4;
const MAX_NODES = 500;

/**
 * Texto de un objeto literal o un array, recorrido SIN ejecutar código de la app: solo propiedades de datos propias
 * (nunca getters, toJSON ni constructores de subclases) y con tope de profundidad, nodos y tamaño. Solo se mira lo que
 * puede contener un canario: cadenas y las claves que las acompañan.
 */
function collectText(value: unknown, depth: number, budget: { nodes: number; chars: number }, out: string[]): void {
  if (budget.nodes <= 0 || budget.chars <= 0) return;
  budget.nodes -= 1;
  if (typeof value === 'string') {
    const text = value.slice(0, budget.chars);
    budget.chars -= text.length;
    out.push(JSON.stringify(text));
    return;
  }
  if (depth >= MAX_DEPTH || value === null || typeof value !== 'object') return;
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype === Array.prototype) {
    const items = value as unknown[];
    const length = Math.min(items.length, MAX_ITEMS);
    for (let index = 0; index < length; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(items, index);
      if (descriptor !== undefined && 'value' in descriptor) collectText(descriptor.value, depth + 1, budget, out);
    }
  } else if (prototype === Object.prototype || prototype === null) {
    for (const key of Object.keys(value).slice(0, MAX_ITEMS)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !('value' in descriptor)) continue;
      out.push(JSON.stringify(key.slice(0, 200)));
      collectText(descriptor.value, depth + 1, budget, out);
    }
  }
}

/**
 * Texto de un argumento, acotado. undefined si el tipo no puede contener un canario. Los objetos literales (consultas
 * de pg `{text}`, filtros de MongoDB) solo se miran en el primer argumento: en el resto son opciones.
 */
function toText(value: unknown, allowObject: boolean): string | undefined {
  if (typeof value === 'string') return value.slice(0, MAX_TEXT_LENGTH);
  if (Buffer.isBuffer(value)) return value.subarray(0, MAX_TEXT_LENGTH).toString('utf8');
  if (value instanceof URL) return value.href;
  if (value === null || typeof value !== 'object') return undefined;
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype === Array.prototype) {
    const out: string[] = [];
    collectText(value, 0, { nodes: MAX_NODES, chars: MAX_TEXT_LENGTH }, out);
    return out.join(' ');
  }
  if (allowObject && prototype === Object.prototype) {
    const text = Object.getOwnPropertyDescriptor(value, 'text');
    if (text !== undefined && typeof text.value === 'string') return (text.value as string).slice(0, MAX_TEXT_LENGTH);
    const out: string[] = [];
    collectText(value, 0, { nodes: MAX_NODES, chars: MAX_TEXT_LENGTH }, out);
    return out.join(' ');
  }
  return undefined;
}

function snippetAround(text: string, index: number): string {
  const start = Math.max(0, index - SNIPPET_CONTEXT);
  const end = Math.min(text.length, index + CANARY_LENGTH + SNIPPET_CONTEXT);
  return text.slice(start, end);
}

function parseFrame(line: string): StackFrame | undefined {
  const match = FRAME.exec(line.trim());
  if (match === null) return undefined;
  let file = match[1];
  if (file.startsWith('file://')) {
    try {
      file = fileURLToPath(file);
    } catch (error) {
      void error;
      return undefined;
    }
  }
  if (!path.isAbsolute(file) || file === SELF) return undefined;
  if (/[\\/]node_modules[\\/]/.test(file)) return undefined;
  // Los frames internos de Node salen con rutas que no son ficheros (p. ej. /modules/esm/module_job): solo cuentan los existentes.
  if (!fs.existsSync(file)) return undefined;
  return { file, line: Number(match[2]) };
}

/** Frames con fichero del usuario (sin node:, sin node_modules y sin el propio agente), los más cercanos primero. */
function userFrames(): StackFrame[] {
  const previous = Error.stackTraceLimit;
  let raw = '';
  try {
    Error.stackTraceLimit = 100;
    const stack: unknown = new Error().stack;
    // Un Error.prepareStackTrace de la app puede devolver algo que no es texto.
    if (typeof stack === 'string') raw = stack;
  } finally {
    Error.stackTraceLimit = previous;
  }
  const frames: StackFrame[] = [];
  for (const line of raw.split('\n')) {
    const frame = parseFrame(line);
    if (frame !== undefined) frames.push(frame);
    if (frames.length >= MAX_FRAMES) break;
  }
  return frames;
}

/** Observa los argumentos `picks` del sink. Reporta una sola vez, y solo si hay un canario. */
function observe(sink: string, args: unknown[], picks: readonly number[], report: Report): void {
  for (const index of picks) {
    if (index >= args.length) continue;
    const text = toText(args[index], index === 0);
    if (text === undefined) continue;
    const match = CANARY.exec(text);
    if (match === null) continue;
    report({ canary: match[0], sink, snippet: snippetAround(text, match.index), stack: userFrames() });
    return;
  }
}

function copyOwnProperties(from: object, to: object): void {
  for (const key of Reflect.ownKeys(from)) {
    if (SKIPPED_KEYS.has(key)) continue;
    try {
      const descriptor = Object.getOwnPropertyDescriptor(from, key);
      if (descriptor !== undefined) Object.defineProperty(to, key, descriptor);
    } catch (error) {
      void error;
    }
  }
}

/**
 * Envoltorio que conserva las propiedades del original (p. ej. util.promisify.custom de exec, que sin copiar cambiaría
 * el resultado de util.promisify(exec)). El custom también se envuelve, para que la forma promisificada se observe.
 */
function wrap(original: AnyFunction, sink: string, picks: readonly number[], report: Report): AnyFunction {
  const wrapper = function (this: unknown, ...args: unknown[]): unknown {
    const outermost = !active;
    if (outermost) {
      active = true;
      try {
        observe(sink, args, picks, report);
      } catch (error) {
        agentWarn(`hook ${sink} failed: ${describe(error)}`);
      }
    }
    try {
      return Reflect.apply(original, this, args);
    } finally {
      if (outermost) active = false;
    }
  };
  copyOwnProperties(original, wrapper);
  const custom = (original as unknown as Record<symbol, unknown>)[PROMISIFY_CUSTOM];
  if (typeof custom === 'function') {
    Object.defineProperty(wrapper, PROMISIFY_CUSTOM, {
      value: wrap(custom as AnyFunction, sink, picks, report),
      configurable: true,
      writable: true,
    });
  }
  Object.defineProperty(wrapper, PATCHED, { value: true });
  return wrapper;
}

/** Sustituye owner[name] por su envoltorio. No parchea dos veces. */
function patch(owner: unknown, name: string, sink: string, picks: readonly number[], report: Report): void {
  if (owner === null || typeof owner !== 'object') return;
  const target = owner as Record<string, unknown>;
  const original = target[name];
  if (typeof original !== 'function' || (original as unknown as Record<symbol, unknown>)[PATCHED] === true) return;
  target[name] = wrap(original as AnyFunction, sink, picks, report);
}

function patchEach(owner: unknown, names: readonly string[], sinkPrefix: string, picks: readonly number[], report: Report): void {
  for (const name of names) {
    try {
      patch(owner, name, `${sinkPrefix}.${name}`, picks, report);
    } catch (error) {
      agentWarn(`could not instrument ${sinkPrefix}.${name}: ${describe(error)}`);
    }
  }
}

/** Builtins: se parchean los objetos que `require` devuelve, que son los mismos que ven los imports de la app. */
const BUILTIN_SINKS: ReadonlyArray<{ module: string; names: readonly string[]; picks: readonly number[] }> = [
  { module: 'child_process', names: ['exec', 'execSync'], picks: [0] },
  { module: 'child_process', names: ['execFile', 'execFileSync', 'spawn', 'spawnSync'], picks: [0, 1] },
  { module: 'fs', names: ['readFile', 'readFileSync', 'createReadStream', 'open', 'writeFile', 'unlink'], picks: [0] },
  { module: 'fs/promises', names: ['readFile', 'open', 'writeFile', 'unlink'], picks: [0] },
  { module: 'vm', names: ['runInNewContext'], picks: [0] },
];

/**
 * Drivers de terceros: se resuelven desde la raíz de la app (BASESEC_AGENT_ROOT o el cwd), así que es la misma
 * instancia que importa la app. Si el driver no está instalado, se omite en silencio.
 */
function loadDriver(name: string): Exports | undefined {
  try {
    const root = process.env.BASESEC_AGENT_ROOT || process.cwd();
    const load = createRequire(path.join(root, 'package.json'));
    return load(name) as Exports;
  } catch (error) {
    const missing = (error as { code?: unknown } | null)?.code === 'MODULE_NOT_FOUND';
    if (!missing) agentWarn(`driver ${name} not instrumented: ${describe(error)}`);
    return undefined;
  }
}

function prototypeOf(owner: Exports | undefined, className: string): unknown {
  const klass = owner?.[className] as { prototype?: unknown } | undefined;
  return klass?.prototype;
}

function patchDrivers(report: Report): void {
  const pg = loadDriver('pg');
  if (pg !== undefined) {
    patchEach(prototypeOf(pg, 'Client'), ['query'], 'pg.Client', [0], report);
    patchEach(prototypeOf(pg, 'Pool'), ['query'], 'pg.Pool', [0], report);
  }

  const mysql = loadDriver('mysql2');
  const mysqlConnection = prototypeOf(mysql, 'Connection');
  if (mysqlConnection !== undefined) {
    patchEach(mysqlConnection, ['query', 'execute'], 'mysql2.Connection', [0], report);
  }

  const mongo = loadDriver('mongodb');
  const collection = prototypeOf(mongo, 'Collection');
  if (collection !== undefined) {
    patchEach(collection, ['find', 'findOne', 'updateOne', 'deleteOne', 'aggregate'], 'mongodb.Collection', [0], report);
  }
}

/**
 * Instala todos los parches. Idempotente. eval y Function no se instrumentan: reasignar el global eval convierte
 * cada eval directo de la app en indirecto (pierde su ámbito local) y Function cambia de identidad; ambas cosas
 * alterarían la app.
 */
export function installHooks(report: Report): void {
  for (const entry of BUILTIN_SINKS) {
    try {
      const builtin = require(entry.module) as unknown;
      patchEach(builtin, entry.names, entry.module, entry.picks, report);
    } catch (error) {
      agentWarn(`could not instrument ${entry.module}: ${describe(error)}`);
    }
  }

  try {
    patchDrivers(report);
  } catch (error) {
    agentWarn(`could not instrument drivers: ${describe(error)}`);
  }

  try {
    require('node:module').syncBuiltinESMExports();
  } catch (error) {
    agentWarn(`could not sync ESM builtins: ${describe(error)}`);
  }
}
