import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Finding } from '../rules/types';
import type { DastObservation } from './types';
import { maskKnownSecrets, redactHeaders, redactHttp } from './redact-http';
import { stripControl } from './probe';
import { ensureBaseSecDir, getBaseSecDir } from '../utils/basesec-dir';
import { logger } from '../utils/logger';

const BODY_LIMIT_BYTES = 8 * 1024;
/** Margen sobre el límite del body para que un token que cruce el corte quede redactado. */
const BODY_MARGIN_BYTES = 4096;

export interface EvidenceWriter {
  /** Escribe la evidencia del hallazgo y devuelve la ruta. No lanza: si falla, logger.warn y devuelve undefined. */
  write(finding: Finding, observation: DastObservation, knownSecrets: string[]): string | undefined;
  readonly dir: string;
}

function cutUtf8(text: string, maxBytes: number): string {
  const buf = Buffer.from(text, 'utf8');
  if (buf.length <= maxBytes) return text;
  let end = maxBytes;
  while (end > 0 && (buf[end] & 0xc0) === 0x80) end--;
  return buf.subarray(0, end).toString('utf8');
}

function headerLines(headers: Record<string, string | string[]>): string[] {
  return Object.entries(headers).flatMap(([name, value]) =>
    (Array.isArray(value) ? value : [value]).map((item) => `${name}: ${item}`),
  );
}

/** Cabeceras de la petición: las que llevan un secreto conocido se ocultan enteras (no solo por nombre). */
function requestHeaderLines(headers: Record<string, string>, knownSecrets: string[]): string[] {
  const hasSecret = (value: string): boolean =>
    knownSecrets.some((secret) => secret !== '' && (value === secret || (secret.length >= 3 && value.includes(secret))));
  const masked = Object.fromEntries(
    Object.entries(headers).map(([name, value]) => [name, hasSecret(value) ? '[REDACTED]' : value]),
  );
  return headerLines(redactHeaders(masked));
}

/** Contenido del fichero .http: petición, respuesta y body, todo redactado y sin caracteres de control. */
function buildContent(finding: Finding, observation: DastObservation, knownSecrets: string[]): string {
  const { response } = observation;
  const redactOptions = { knownSecrets };
  const requestLines = requestHeaderLines(observation.requestHeaders ?? {}, knownSecrets);
  const responseLines = headerLines(redactHeaders(response.headers));

  const head = [
    `### ${finding.ruleId} — ${observation.endpoint}`,
    `${observation.method} ${observation.url} HTTP/1.1`,
    ...requestLines,
    '',
    `HTTP/1.1 ${response.status}`,
    ...responseLines,
  ].join('\n');
  const redactedHead = redactHttp(maskKnownSecrets(head, knownSecrets), redactOptions);

  // El body se redacta completo (con margen) y solo después se corta: así un token en el corte no queda a medias.
  let bodyPart = '';
  if (response.bodyDecoded && response.body !== '') {
    const redactedBody = redactHttp(maskKnownSecrets(cutUtf8(response.body, BODY_LIMIT_BYTES + BODY_MARGIN_BYTES), knownSecrets), {
      knownSecrets,
      maxBodyBytes: Number.POSITIVE_INFINITY,
    });
    const cut = cutUtf8(redactedBody, BODY_LIMIT_BYTES);
    bodyPart = cut === redactedBody ? redactedBody : `${cut} …[truncado]`;
  }

  const text = bodyPart === '' ? `${redactedHead}\n` : `${redactedHead}\n\n${bodyPart}\n`;
  return stripControl(text).replace(/\t/g, '  ');
}

function fileDigest(finding: Finding): string {
  return crypto
    .createHash('sha256')
    .update(`${finding.ruleId}${finding.endpoint ?? ''}${finding.codeSnippet}`)
    .digest('hex')
    .slice(0, 8);
}

const MAX_NAME_ATTEMPTS = 1000;

/**
 * Crea `dir` (0700) o, si ya existe, comprueba que es un directorio real (no un symlink plantado) y
 * propio, y le fuerza 0700. Avisa si tenía permisos más laxos.
 */
export function prepareDir(baseDir: string, dir: string): void {
  fs.mkdirSync(baseDir, { recursive: true, mode: 0o700 });
  try {
    fs.mkdirSync(dir, { mode: 0o700 });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
    const info = fs.lstatSync(dir);
    if (!info.isDirectory()) throw new Error(`${dir} existe y no es un directorio`);
    if (typeof process.getuid === 'function' && info.uid !== process.getuid()) {
      throw new Error(`${dir} pertenece a otro usuario`);
    }
    if ((info.mode & 0o077) !== 0) {
      logger.warn(`El directorio de evidencia ${dir} tenía permisos laxos; se restringe a 0700`);
    }
  }
  fs.chmodSync(dir, 0o700);
}

/**
 * Escribe un .http por hallazgo. El directorio `dast-<timestamp>` se crea solo con el primer write,
 * con permisos 0700 (también si ya existía); los ficheros son 0600, se crean con O_EXCL (no siguen
 * symlinks ni sobrescriben) y nunca se reutiliza un nombre.
 */
export function createEvidenceWriter(baseDir?: string): EvidenceWriter {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const base = path.resolve(baseDir ?? getBaseSecDir());
  const dir = path.join(base, `dast-${timestamp}`);
  let dirReady = false;

  return {
    dir,
    write(finding, observation, knownSecrets) {
      try {
        if (!dirReady) {
          if (baseDir === undefined) ensureBaseSecDir();
          prepareDir(base, dir);
          dirReady = true;
        }
        const ruleSlug = finding.ruleId.replace(/[^A-Za-z0-9-]/g, '_');
        const stem = `${ruleSlug}-${fileDigest(finding)}`;
        const content = buildContent(finding, observation, knownSecrets);
        for (let attempt = 1; attempt <= MAX_NAME_ATTEMPTS; attempt++) {
          const filePath = path.join(dir, attempt === 1 ? `${stem}.http` : `${stem}-${attempt}.http`);
          try {
            fs.writeFileSync(filePath, content, { encoding: 'utf-8', mode: 0o600, flag: 'wx' });
            return filePath;
          } catch (e) {
            if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
          }
        }
        throw new Error('demasiados ficheros con el mismo nombre');
      } catch (e) {
        logger.warn(`No se pudo escribir la evidencia de ${finding.ruleId}`, e);
        return undefined;
      }
    },
  };
}
