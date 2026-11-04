import * as http from 'node:http';
import * as https from 'node:https';
import * as zlib from 'node:zlib';
import type { Transform } from 'node:stream';
import type { Guard } from './guard';
import { isNodeSupported } from './guard';
import { BudgetExceededError, GuardError } from './types';
import type { HttpClientOptions, HttpRequestOptions, HttpResponse } from './types';
import { logger } from '../utils/logger';

const MAX_BODY_BYTES = 8 * 1024 * 1024;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

interface Hop {
  status: number;
  headers: Record<string, string | string[]>;
  raw: Buffer;
  /** true si se dejó de leer al llegar al tope de bytes (el body está incompleto). */
  rawTruncated: boolean;
  timedOut: boolean;
  /** Tiempo en la red de este salto, sin la espera del rate limiter ni de la cola de concurrencia. */
  networkMs: number;
}

/** Cabeceras inocuas que sí se reenvían a otro origen en un redirect. El resto (auth, cookies, claves) no. */
const CROSS_ORIGIN_SAFE_HEADERS = new Set(['accept', 'accept-encoding', 'accept-language', 'user-agent']);
const BODY_HEADERS = ['content-length', 'content-type', 'content-encoding', 'transfer-encoding'];
const MAX_COOKIES_PER_HOST = 128;
const COOKIE_TOKEN = /^[\x21-\x7e]+$/;

interface Codec {
  sync: (buf: Buffer, opts: { maxOutputLength: number }) => Buffer;
  stream: () => Transform;
}

const CODECS: Record<string, Codec> = {
  gzip: { sync: zlib.gunzipSync, stream: zlib.createGunzip },
  'x-gzip': { sync: zlib.gunzipSync, stream: zlib.createGunzip },
  deflate: { sync: zlib.inflateSync, stream: zlib.createInflate },
  br: { sync: zlib.brotliDecompressSync, stream: zlib.createBrotliDecompress },
};

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeHeaders(raw: http.IncomingHttpHeaders): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [name, value] of Object.entries(raw)) {
    if (value !== undefined && name.toLowerCase() !== '__proto__') out[name.toLowerCase()] = value;
  }
  return out;
}

function singleHeader(headers: Record<string, string | string[]>, name: string): string | undefined {
  const value = headers[name];
  return Array.isArray(value) ? value[0] : value;
}

function isBufferTooLarge(e: unknown): boolean {
  return e instanceof RangeError && (e as { code?: string }).code === 'ERR_BUFFER_TOO_LARGE';
}

/** Descomprime en streaming hasta el límite. Se usa solo cuando la versión síncrona excede el tope. */
function collectPrefix(raw: Buffer, decoder: Transform): Promise<Buffer> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let total = 0;
    const finish = (): void => {
      resolve(Buffer.concat(chunks).subarray(0, MAX_BODY_BYTES));
    };
    decoder.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
      total += chunk.length;
      if (total >= MAX_BODY_BYTES) {
        decoder.destroy();
        finish();
      }
    });
    decoder.on('end', finish);
    decoder.on('error', (e: unknown) => {
      logger.warn('Cuerpo comprimido truncado o no decodificable', e);
      finish();
    });
    decoder.end(raw);
  });
}

async function decodeBody(hop: Hop): Promise<Pick<HttpResponse, 'body' | 'bodyDecoded' | 'contentEncoding'>> {
  const encoding = singleHeader(hop.headers, 'content-encoding')?.trim().toLowerCase() || null;
  if (hop.timedOut) {
    return { body: '', bodyDecoded: false, contentEncoding: encoding };
  }
  if (hop.raw.length === 0) {
    // HEAD, 204, 304...: no hay nada que decodificar aunque la cabecera declare un encoding.
    return { body: '', bodyDecoded: true, contentEncoding: encoding };
  }
  if (encoding === null || encoding === 'identity') {
    let raw = hop.raw;
    if (raw.length > MAX_BODY_BYTES || hop.rawTruncated) {
      logger.warn(`Body sin comprimir truncado a ${MAX_BODY_BYTES} bytes`);
      raw = raw.subarray(0, MAX_BODY_BYTES);
    }
    return { body: raw.toString('utf8'), bodyDecoded: true, contentEncoding: encoding };
  }
  if (encoding === 'br' && !isNodeSupported()) {
    logger.warn('Body Brotli sin decodificar: esta versión de Node no tiene los parches de seguridad');
    return { body: '', bodyDecoded: false, contentEncoding: encoding };
  }
  const codec = CODECS[encoding];
  if (!codec) {
    return { body: '', bodyDecoded: false, contentEncoding: encoding };
  }
  try {
    let decoded: Buffer;
    if (hop.rawTruncated) {
      // Flujo comprimido cortado por el tope de lectura: se aprovecha el prefijo decodificable.
      logger.warn(`Body ${encoding} supera ${MAX_BODY_BYTES} bytes comprimidos; truncado`);
      decoded = await collectPrefix(hop.raw, codec.stream());
    } else {
      try {
        decoded = codec.sync(hop.raw, { maxOutputLength: MAX_BODY_BYTES });
      } catch (e) {
        if (!isBufferTooLarge(e)) throw e;
        logger.warn(`Body ${encoding} supera ${MAX_BODY_BYTES} bytes descomprimidos; truncado`);
        decoded = await collectPrefix(hop.raw, codec.stream());
      }
    }
    return { body: decoded.toString('utf8'), bodyDecoded: true, contentEncoding: encoding };
  } catch (e) {
    logger.warn(`No se pudo decodificar el body ${encoding}`, e);
    return { body: '', bodyDecoded: false, contentEncoding: encoding };
  }
}

export class HttpClient {
  private readonly guard: Guard;
  private readonly rps: number;
  private readonly concurrency: number;
  private readonly maxRequests: number;
  private readonly requestTimeout: number;
  private readonly defaultHeaders: Record<string, string>;
  private readonly maxRedirects: number;
  private readonly minIntervalMs: number;
  private readonly jar = new Map<string, Map<string, string>>();
  private count = 0;
  private inFlight = 0;
  private readonly waiters: Array<() => void> = [];
  // Agentes propios y sin keep-alive: no heredan NODE_USE_ENV_PROXY (que saltaría el hook lookup)
  // ni dejan sockets ociosos manteniendo vivo el proceso.
  private readonly httpAgent = new http.Agent({ keepAlive: false });
  private readonly httpsAgent = new https.Agent({ keepAlive: false });
  private nextSlotAt = 0;

  constructor(options: HttpClientOptions) {
    this.guard = options.guard;
    this.rps = options.rps ?? 20;
    this.concurrency = options.concurrency ?? 5;
    this.maxRequests = options.maxRequests ?? 5000;
    this.requestTimeout = options.requestTimeout ?? 10000;
    this.defaultHeaders = { ...(options.defaultHeaders ?? {}) };
    this.maxRedirects = options.maxRedirects ?? 3;
    if (!(this.rps > 0)) throw new RangeError('rps debe ser mayor que 0');
    if (!(this.concurrency >= 1)) throw new RangeError('concurrency debe ser al menos 1');
    this.minIntervalMs = 1000 / this.rps;
  }

  /** Peticiones HTTP reales emitidas hasta ahora (incluidos saltos de redirect). */
  get requestCount(): number {
    return this.count;
  }

  async request(method: string, url: string, opts: HttpRequestOptions = {}): Promise<HttpResponse> {
    let networkMs = 0;
    const followRedirects = opts.followRedirects !== false;
    let headers = this.buildHeaders(opts.headers);
    const redirects: string[] = [];
    let verb = method.toUpperCase();
    let payload = opts.body;
    let current = url;
    let hop: Hop;

    for (;;) {
      hop = await this.sendHop(verb, current, headers, payload);
      networkMs += hop.networkMs;
      const location = singleHeader(hop.headers, 'location');
      if (
        hop.timedOut ||
        !followRedirects ||
        !REDIRECT_STATUSES.has(hop.status) ||
        location === undefined ||
        redirects.length >= this.maxRedirects
      ) {
        break;
      }
      if (!(await this.guard.canFollowRedirect(location, current))) break;
      let next: URL;
      try {
        next = new URL(location.replace(/[\t\n\r]/g, '').trim(), current);
      } catch (e) {
        logger.warn(`Location no válido, redirect no seguido: ${location}`, e);
        break;
      }
      const crossOrigin = next.origin !== new URL(current).origin;
      const keepsBody = hop.status >= 307;
      if (crossOrigin && keepsBody && payload !== undefined) {
        // 307/308 exigen reenviar el body: no se reenvía a otro origen.
        logger.warn(`Redirect ${hop.status} con body hacia otro origen no seguido: ${next.origin}`);
        break;
      }
      if (crossOrigin) {
        headers = Object.fromEntries(
          Object.entries(headers).filter(([name]) => CROSS_ORIGIN_SAFE_HEADERS.has(name)),
        );
      }
      if (!keepsBody && verb !== 'GET' && verb !== 'HEAD') {
        verb = 'GET';
        payload = undefined;
      }
      if (payload === undefined) {
        headers = Object.fromEntries(Object.entries(headers).filter(([name]) => !BODY_HEADERS.includes(name)));
      }
      redirects.push(location);
      current = next.href;
    }

    const decoded = await decodeBody(hop);
    return {
      status: hop.status,
      headers: hop.headers,
      body: decoded.body,
      contentEncoding: decoded.contentEncoding,
      bodyDecoded: decoded.bodyDecoded,
      url: current,
      redirects,
      timedOut: hop.timedOut,
      // Tiempo de red (sin la espera del rate limiter): los oráculos de retardo comparan estas medidas.
      elapsedMs: networkMs,
    };
  }

  /** Cookies actuales del jar para un host, en formato de cabecera cookie. */
  getCookies(host: string): string {
    const jar = this.jar.get(host.toLowerCase());
    if (!jar) return '';
    return [...jar].map(([name, value]) => `${name}=${value}`).join('; ');
  }

  private buildHeaders(requestHeaders: Record<string, string> = {}): Record<string, string> {
    const merged: Record<string, string> = {};
    for (const [name, value] of Object.entries({ ...this.defaultHeaders, ...requestHeaders })) {
      merged[name.toLowerCase()] = value;
    }
    for (const [name, value] of Object.entries(requestHeaders)) {
      merged[name.toLowerCase()] = value;
    }
    if (!('accept-encoding' in merged)) merged['accept-encoding'] = 'gzip, deflate';
    return merged;
  }

  private async sendHop(
    verb: string,
    url: string,
    headers: Record<string, string>,
    body: string | Buffer | undefined,
  ): Promise<Hop> {
    if (!this.guard.isMethodAllowed(verb)) {
      throw new GuardError('method-blocked', `Método ${verb} no permitido sin --allow-mutations`);
    }
    if (this.count >= this.maxRequests) {
      throw new BudgetExceededError(this.maxRequests);
    }
    await this.guard.assertTargetAllowed(url);
    const target = new URL(url);

    const hopHeaders = { ...headers };
    if (body !== undefined && !('content-length' in hopHeaders)) {
      hopHeaders['content-length'] = String(Buffer.byteLength(body));
    }
    const jarCookies = this.getCookies(target.hostname);
    if (jarCookies) {
      hopHeaders.cookie = [hopHeaders.cookie, jarCookies].filter(Boolean).join('; ');
    }

    await this.acquire();
    try {
      if (this.count >= this.maxRequests) {
        throw new BudgetExceededError(this.maxRequests);
      }
      this.count++;
      const sentAt = Date.now();
      const hop = await this.transmit(verb, target, hopHeaders, body);
      hop.networkMs = Date.now() - sentAt;
      if (!hop.timedOut) this.storeCookies(target.hostname, hop.headers);
      return hop;
    } finally {
      this.release();
    }
  }

  private transmit(
    verb: string,
    target: URL,
    headers: Record<string, string>,
    body: string | Buffer | undefined,
  ): Promise<Hop> {
    const transport = target.protocol === 'https:' ? https : http;
    const signal = AbortSignal.timeout(this.requestTimeout);
    return new Promise<Hop>((resolve, reject) => {
      let settled = false;
      const settle = (action: () => void): void => {
        if (!settled) {
          settled = true;
          action();
        }
      };
      const onFailure = (err: unknown): void =>
        settle(() => {
          if (signal.aborted) {
            resolve({ status: 0, headers: {}, raw: Buffer.alloc(0), rawTruncated: false, timedOut: true, networkMs: 0 });
          } else {
            reject(err);
          }
        });

      const req = transport.request(
        target,
        {
          method: verb,
          headers,
          signal,
          agent: target.protocol === 'https:' ? this.httpsAgent : this.httpAgent,
          lookup: this.guard.lookup.bind(this.guard),
        },
        (res) => {
          const chunks: Buffer[] = [];
          let total = 0;
          const finish = (rawTruncated: boolean): void =>
            settle(() =>
              resolve({
                status: res.statusCode ?? 0,
                headers: normalizeHeaders(res.headers),
                raw: Buffer.concat(chunks),
                rawTruncated,
                timedOut: false,
                networkMs: 0,
              }),
            );
          res.on('data', (chunk: Buffer) => {
            chunks.push(chunk);
            total += chunk.length;
            if (total > MAX_BODY_BYTES) {
              // Tope de lectura: un servidor hostil no puede hacernos acumular un body ilimitado.
              finish(true);
              res.destroy();
              req.destroy();
            }
          });
          res.on('end', () => finish(false));
          res.on('error', onFailure);
          res.on('close', () => onFailure(new Error('Conexión cerrada antes de completar la respuesta')));
        },
      );
      req.on('error', onFailure);
      if (body !== undefined) req.write(body);
      req.end();
    });
  }

  private storeCookies(host: string, headers: Record<string, string | string[]>): void {
    const setCookie = headers['set-cookie'];
    if (setCookie === undefined) return;
    const lines = Array.isArray(setCookie) ? setCookie : [setCookie];
    for (const line of lines) {
      const [pair, ...attributes] = line.split(';');
      const eq = pair.indexOf('=');
      if (eq <= 0) continue;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      // Un servidor hostil no debe poder envenenar el jar con caracteres que rompan la cabecera cookie.
      if (!COOKIE_TOKEN.test(name) || /[=;,]/.test(name) || (value !== '' && !COOKIE_TOKEN.test(value)) || /[;,]/.test(value)) {
        continue;
      }
      const expired = attributes.some((attribute) => {
        const maxAge = /^\s*max-age\s*=\s*(-?\d+)\s*$/i.exec(attribute);
        return maxAge !== null && Number(maxAge[1]) <= 0;
      });
      let jar = this.jar.get(host);
      if (!jar) {
        jar = new Map<string, string>();
        this.jar.set(host, jar);
      }
      if (expired) {
        jar.delete(name);
      } else if (jar.has(name) || jar.size < MAX_COOKIES_PER_HOST) {
        jar.set(name, value);
      }
    }
  }

  private async acquire(): Promise<void> {
    if (this.inFlight < this.concurrency) {
      this.inFlight++;
    } else {
      await new Promise<void>((resolve) => this.waiters.push(resolve));
    }
    const now = Date.now();
    const startAt = Math.max(now, this.nextSlotAt);
    this.nextSlotAt = startAt + this.minIntervalMs;
    if (startAt > now) await sleep(startAt - now);
  }

  private release(): void {
    const next = this.waiters.shift();
    if (next) {
      next();
    } else {
      this.inFlight--;
    }
  }
}
