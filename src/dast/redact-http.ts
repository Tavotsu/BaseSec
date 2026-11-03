import { SECRET_VALUE_PATTERNS } from '../utils/patterns';
import { redactSecret } from '../utils/redact';

export interface RedactHttpOptions {
  /** Valores conocidos a redactar donde aparezcan (los --header del usuario). */
  knownSecrets?: string[];
  /** Límite del body en bytes. default 8192. */
  maxBodyBytes?: number;
}

const REDACTED = '[REDACTED]';
const DEFAULT_MAX_BODY_BYTES = 8192;
const SENSITIVE_HEADER_NAMES = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
]);
const SENSITIVE_HEADER_PATTERN = /token|secret|session|api[-_]?key|password/i;
const HEADER_LINE = /^([ \t]*)([A-Za-z0-9_-]+)([ \t]*:[ \t]*)([^\r\n]*)$/gm;
const QUERY_SECRET = /([?&](?:access_token|token|apikey|key|password|secret|session|signature|sig)=)[^&\s#"'<>]*/gi;

function unanchored(pattern: RegExp): RegExp {
  const source = pattern.source.replace(/^\^/, '').replace(/\$$/, '');
  return new RegExp(source, `${pattern.flags.replace('g', '')}g`);
}

const TOKEN_PATTERNS: Array<{ regex: RegExp; replacement: string }> = [
  ...SECRET_VALUE_PATTERNS.filter(({ name }) => name !== 'Possible Hex Secret').map(({ pattern }) => ({
    regex: unanchored(pattern),
    replacement: REDACTED,
  })),
  { regex: /eyJ[\w-]+\.[\w-]+\.[\w-]+/g, replacement: REDACTED },
  { regex: /Bearer \S+/g, replacement: `Bearer ${REDACTED}` },
];

function isSensitiveHeader(name: string): boolean {
  const lower = name.toLowerCase();
  return SENSITIVE_HEADER_NAMES.has(lower) || SENSITIVE_HEADER_PATTERN.test(lower);
}

function redactCookiePair(pair: string): string {
  const eq = pair.indexOf('=');
  if (eq === -1) {
    const leading = /^\s*/.exec(pair)?.[0] ?? '';
    return pair.trim() === '' ? pair : `${leading}${REDACTED}`;
  }
  return `${pair.slice(0, eq + 1)}${REDACTED}`;
}

function redactHeaderValue(name: string, value: string): string {
  const lower = name.toLowerCase();
  if (lower === 'cookie') {
    return value.split(';').map(redactCookiePair).join(';');
  }
  if (lower === 'set-cookie') {
    const [first, ...flags] = value.split(';');
    return [redactCookiePair(first), ...flags].join(';');
  }
  return REDACTED;
}

function truncateBody(text: string, maxBodyBytes: number): string {
  const separator = /\r?\n\r?\n/.exec(text);
  const headEnd = separator ? separator.index + separator[0].length : 0;
  const head = text.slice(0, headEnd);
  const body = text.slice(headEnd);
  if (Buffer.byteLength(body, 'utf8') <= maxBodyBytes) return text;
  const cut = Buffer.from(body, 'utf8').subarray(0, maxBodyBytes).toString('utf8');
  return `${head}${cut} …[truncado]`;
}

/** Redacta una petición o respuesta en texto para la evidencia. */
export function redactHttp(text: string, opts: RedactHttpOptions = {}): string {
  let out = text.replace(HEADER_LINE, (line: string, indent: string, name: string, sep: string, value: string) =>
    isSensitiveHeader(name) ? `${indent}${name}${sep}${redactHeaderValue(name, value)}` : line,
  );
  for (const secret of opts.knownSecrets ?? []) {
    out = redactSecret(out, secret);
  }
  out = out.replace(QUERY_SECRET, (_match, prefix: string) => `${prefix}${REDACTED}`);
  for (const { regex, replacement } of TOKEN_PATTERNS) {
    out = out.replace(regex, replacement);
  }
  return truncateBody(out, opts.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES);
}

/** Redacta solo un mapa de headers (para la evidencia estructurada). */
export function redactHeaders(
  headers: Record<string, string | string[]>,
): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (!isSensitiveHeader(name)) {
      out[name] = value;
    } else {
      out[name] = Array.isArray(value)
        ? value.map((item) => redactHeaderValue(name, item))
        : redactHeaderValue(name, value);
    }
  }
  return out;
}
