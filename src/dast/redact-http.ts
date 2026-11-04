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
// Nombres de la lista del plan (token, key, sig...) más cualquier nombre que case con la regla de cabeceras
// (api_key, refresh_token, client_secret...). El valor llega hasta el siguiente separador.
const QUERY_SECRET =
  /([?&](?:[\w.-]*(?:token|secret|session|api[-_]?key|password)[\w.-]*|key|sig|signature)=)[^&\s#"'<>]*/gi;
const URL_USERINFO = /(\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:)[^\s/@]+(?=@)/gi;
/** Margen sobre el límite del body que se procesa: acota el coste de las regex ante cuerpos hostiles. */
const REDACTION_MARGIN_BYTES = 4096;
const MAX_HEAD_CHARS = 65536;

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
  { regex: /Bearer\s+\S+/gi, replacement: `Bearer ${REDACTED}` },
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

/** Corta a `maxBytes` bytes UTF-8 sin partir un carácter multibyte. */
function cutUtf8(text: string, maxBytes: number): string {
  const buf = Buffer.from(text, 'utf8');
  if (buf.length <= maxBytes) return text;
  let end = maxBytes;
  while (end > 0 && (buf[end] & 0xc0) === 0x80) end--;
  return buf.subarray(0, end).toString('utf8');
}

function splitHead(text: string): { head: string; body: string } {
  const separator = /\r?\n\r?\n/.exec(text);
  const headEnd = separator ? separator.index + separator[0].length : 0;
  return { head: text.slice(0, headEnd), body: text.slice(headEnd) };
}

function applyRedactions(text: string, knownSecrets: string[]): string {
  let out = text.replace(HEADER_LINE, (line: string, indent: string, name: string, sep: string, value: string) =>
    isSensitiveHeader(name) ? `${indent}${name}${sep}${redactHeaderValue(name, value)}` : line,
  );
  // Los más largos primero: si un secreto contiene a otro, redactar el corto antes dejaría restos del largo.
  const secrets = [...new Set(knownSecrets)].sort((a, b) => b.length - a.length);
  for (const secret of secrets) {
    out = redactSecret(out, secret);
  }
  out = out.replace(QUERY_SECRET, (_match, prefix: string) => `${prefix}${REDACTED}`);
  out = out.replace(URL_USERINFO, `$1${REDACTED}`);
  for (const { regex, replacement } of TOKEN_PATTERNS) {
    out = out.replace(regex, replacement);
  }
  return out;
}

/** Redacta una petición o respuesta en texto para la evidencia. */
export function redactHttp(text: string, opts: RedactHttpOptions = {}): string {
  const requested = opts.maxBodyBytes;
  const maxBodyBytes = requested !== undefined && requested >= 0 ? requested : DEFAULT_MAX_BODY_BYTES;
  const { head, body } = splitHead(text);
  // Se acota la entrada ANTES de aplicar las regex (un cuerpo de MB hostil podría disparar su coste);
  // el margen extra evita que un token justo en el corte quede sin redactar dentro de la parte visible.
  const boundedHead = head.length > MAX_HEAD_CHARS ? `${head.slice(0, MAX_HEAD_CHARS)} …[truncado]\n\n` : head;
  const bodyBytes = Buffer.byteLength(body, 'utf8');
  const boundedBody = bodyBytes > maxBodyBytes + REDACTION_MARGIN_BYTES
    ? cutUtf8(body, maxBodyBytes + REDACTION_MARGIN_BYTES)
    : body;
  const redacted = applyRedactions(`${boundedHead}${boundedBody}`, opts.knownSecrets ?? []);
  const redactedHead = splitHead(redacted);
  if (Buffer.byteLength(redactedHead.body, 'utf8') <= maxBodyBytes && bodyBytes <= maxBodyBytes) return redacted;
  return `${redactedHead.head}${cutUtf8(redactedHead.body, maxBodyBytes)} …[truncado]`;
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

/**
 * Sustituye por completo cada secreto conocido (sin dejar el prefijo visible que deja redactSecret).
 * Los más largos primero; los valores de menos de 3 caracteres se ignoran, como en redactHttp.
 */
export function maskKnownSecrets(text: string, knownSecrets: string[]): string {
  let out = text;
  const secrets = [...new Set(knownSecrets)].filter((secret) => secret.length >= 3).sort((a, b) => b.length - a.length);
  for (const secret of secrets) {
    out = out.replaceAll(secret, REDACTED);
  }
  return out;
}
