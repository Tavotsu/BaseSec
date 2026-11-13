import type { HttpResponse } from '../types';
import { header } from '../rules/helpers';
import { detected, notDetected, scanBody } from './types';
import type { OracleInput, OracleResult } from './types';

function isHtml(response: HttpResponse): boolean {
  const contentType = (header(response, 'content-type') ?? '').trim().toLowerCase();
  return contentType.startsWith('text/html') || contentType.startsWith('application/xhtml+xml');
}

/**
 * Parte del payload XSS que abre la etiqueta (desde el primer `<`). Es lo que tiene que llegar intacto: unas
 * comillas escapadas delante no impiden que `<img ...` se interprete en un contexto de texto, pero sin el `<` no
 * hay etiqueta aunque el canario esté en la página.
 */
function tagPart(payloadText: string): string {
  const open = payloadText.indexOf('<');
  return open === -1 ? payloadText : payloadText.slice(open);
}

/** Antes del canario hay un `echo` (con blancos, comillas o sus codificaciones): es el eco del propio payload. */
const ECHO_BEFORE = /echo(?:\s|%20|\+|&nbsp;|&#0*32;|&#x0*20;)*['"]?$/i;
const ECHO_LOOKBEHIND = 32;

/** true si alguna aparición del canario NO viene precedida de `echo`: puede ser la salida de un comando. */
function hasCommandOutput(body: string, canary: string): boolean {
  let from = 0;
  for (;;) {
    const index = body.indexOf(canary, from);
    if (index === -1) return false;
    const before = body.slice(Math.max(0, index - ECHO_LOOKBEHIND), index);
    if (!ECHO_BEFORE.test(before)) return true;
    from = index + canary.length;
  }
}

/**
 * Reflejo de canario.
 * - `xss`: exige HTML y que la parte del payload que abre la etiqueta aparezca TAL CUAL. Un valor escapado
 *   (`&lt;img`), recortado (se quitan `<` y comillas y queda el canario suelto) o servido como JSON no cuenta.
 * - `echo` (salida de comando): el canario debe aparecer en algún sitio donde NO lo precede `echo`. Si solo
 *   aparece como `echo BS…`, la página está repitiendo el payload (p. ej. quitándole `;` y `$()`), no ejecutándolo.
 */
export function reflectionOracle(input: OracleInput, mode: 'xss' | 'echo'): OracleResult {
  const { attack, canary, payloadText } = input;
  const body = scanBody(attack);
  if (!body.includes(canary)) return notDetected('the canary is not in the response');

  if (mode === 'echo') {
    if (!hasCommandOutput(body, canary)) return notDetected('the canary only appears as the echoed payload, not as command output');
    return detected('the canary appears in the response output', 'medium');
  }

  if (!isHtml(attack)) return notDetected('the response is not HTML');
  if (!body.includes(tagPart(payloadText))) return notDetected('the payload does not arrive intact (escaped or stripped)');
  return detected('the payload is reflected unescaped in an HTML response', 'medium');
}

/** Firmas de ficheros de solo lectura conocidos. Cada entrada exige TODAS sus cadenas. */
const FILE_SIGNATURES: Array<{ all: string[]; label: string }> = [
  { all: ['root:x:0:0:'], label: '/etc/passwd' },
  { all: ['[fonts]', '[extensions]'], label: 'win.ini' },
  { all: ['; for 16-bit app support'], label: 'win.ini' },
];

/**
 * Path traversal: la firma de un fichero de solo lectura conocido aparece en el ataque y no en la benigna. win.ini
 * exige dos secciones (o su comentario de cabecera): `[fonts]` suelto aparece en documentación y en otros .ini.
 */
export function signatureOracle(input: OracleInput): OracleResult {
  const { baseline, attack } = input;
  const attackBody = scanBody(attack);
  const baselineBody = scanBody(baseline);
  for (const { all, label } of FILE_SIGNATURES) {
    const inAttack = all.every((signature) => attackBody.includes(signature));
    const inBaseline = all.some((signature) => baselineBody.includes(signature));
    if (inAttack && !inBaseline) return detected(`the response contains the contents of ${label}`, 'high');
  }
  return notDetected('no system file signature in the response');
}
