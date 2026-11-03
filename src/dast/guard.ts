import * as dns from 'node:dns';
import { isIP } from 'node:net';
import { GuardError } from './types';
import { logger } from '../utils/logger';

/** Rango semver de Node con los parches de seguridad obligatorios (§1, Node2Shell). */
export const NODE_FLOOR = '^22.23.4 || ^24.22.1 || >=26.12.1';
/** Las versiones mínimas por línea, para el mensaje y la comprobación. */
export const NODE_FLOOR_VERSIONS = { 22: '22.23.4', 24: '24.22.1', 26: '26.12.1' } as const;

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

type IpClass = 'loopback' | 'private' | 'link-local' | 'public';

export interface GuardConfig {
  allowRemote?: boolean;
  allowRemoteEnv?: boolean;
  allowMutations?: boolean;
  allowVulnerableNode?: boolean;
  /** Para inyectar en tests en vez de dns real. Resuelve a lista de IPs. */
  resolver?: (hostname: string) => Promise<string[]>;
}

function parseVersion(version: string): [number, number, number] | null {
  const match = /^v?(\d+)\.(\d+)\.(\d+)/.exec(version.trim());
  return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
}

/** true si la versión de Node (por defecto la actual) tiene los parches obligatorios. */
export function isNodeSupported(version: string = process.versions.node): boolean {
  const current = parseVersion(version);
  if (!current) return false;
  const [major, minor, patch] = current;
  if (major > 26) return true;
  const floorText = (NODE_FLOOR_VERSIONS as Partial<Record<number, string>>)[major];
  const floor = floorText ? parseVersion(floorText) : null;
  if (!floor) return false;
  return minor > floor[1] || (minor === floor[1] && patch >= floor[2]);
}

function canonicalIPv4(text: string): number[] | null {
  if (!/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(text)) return null;
  const octets = text.split('.').map(Number);
  return octets.every((octet) => octet <= 255) ? octets : null;
}

function classifyOctets([a, b, c, d]: number[]): IpClass {
  if (a === 127 || (a === 0 && b === 0 && c === 0 && d === 0)) return 'loopback';
  if (a === 169 && b === 254) return 'link-local';
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'private';
  return 'public';
}

function parseIPv6(ip: string): number[] | null {
  let text = ip;
  const lastColon = text.lastIndexOf(':');
  const tail = text.slice(lastColon + 1);
  if (tail.includes('.')) {
    const octets = canonicalIPv4(tail);
    if (!octets) return null;
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    text = `${text.slice(0, lastColon + 1)}${high}:${low}`;
  }
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const parseGroups = (part: string): number[] =>
    part === '' ? [] : part.split(':').map((group) => (/^[0-9a-f]{1,4}$/i.test(group) ? parseInt(group, 16) : NaN));
  const head = parseGroups(halves[0]);
  const rest = halves.length === 2 ? parseGroups(halves[1]) : [];
  if (head.some(Number.isNaN) || rest.some(Number.isNaN)) return null;
  if (halves.length === 2) {
    const fill = 8 - head.length - rest.length;
    if (fill < 0) return null;
    return [...head, ...new Array<number>(fill).fill(0), ...rest];
  }
  return head.length === 8 ? head : null;
}

/** Clasifica una IP. Lo que no se puede interpretar se trata como pública (cierre por defecto). */
function classifyIp(ip: string): IpClass {
  const v4 = canonicalIPv4(ip);
  if (v4) return classifyOctets(v4);
  if (!ip.includes(':')) return 'public';
  const groups = parseIPv6(ip);
  if (!groups) return 'public';
  const isMapped = groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff;
  if (isMapped) {
    return classifyOctets([groups[6] >> 8, groups[6] & 0xff, groups[7] >> 8, groups[7] & 0xff]);
  }
  if (groups.every((group) => group === 0)) return 'loopback';
  if (groups.slice(0, 7).every((group) => group === 0) && groups[7] === 1) return 'loopback';
  if ((groups[0] & 0xffc0) === 0xfe80) return 'link-local';
  if ((groups[0] & 0xfe00) === 0xfc00) return 'private';
  return 'public';
}

/** Host tal como aparece en el texto de la URL, antes de que el parser lo normalice. */
function extractRawHost(url: string): string | null {
  const match = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/?#]*@)?(\[[^\]]*\]|[^/?#:]*)/i.exec(url);
  return match ? match[1] : null;
}

function isNumericLikeHost(host: string): boolean {
  if (host === '') return false;
  return host
    .replace(/\.$/, '')
    .split('.')
    .every((part) => /^(?:0x[0-9a-f]*|\d+)$/i.test(part));
}

function isHttpProtocol(protocol: string): boolean {
  return protocol === 'http:' || protocol === 'https:';
}

export class Guard {
  private readonly config: GuardConfig;

  constructor(config: GuardConfig = {}) {
    this.config = { ...config };
  }

  /** Lanza GuardError('node-vulnerable') si Node < suelo y no allowVulnerableNode. */
  assertNodeSupported(): void {
    if (this.config.allowVulnerableNode || isNodeSupported()) return;
    const lines = Object.values(NODE_FLOOR_VERSIONS).join(', ');
    throw new GuardError(
      'node-vulnerable',
      `Node ${process.versions.node} no tiene los parches de seguridad obligatorios. Actualiza a ${lines} (${NODE_FLOOR}).`,
    );
  }

  /**
   * Valida la URL de destino ANTES de cualquier petición.
   * Devuelve las IPs resueltas si pasa.
   */
  async assertTargetAllowed(url: string, opts: { isTTY?: boolean } = {}): Promise<string[]> {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new GuardError('invalid-url', `URL inválida: ${url}`);
    }
    if (!isHttpProtocol(parsed.protocol)) {
      throw new GuardError('invalid-url', `Protocolo no soportado: ${parsed.protocol}`);
    }
    const rawHost = extractRawHost(url);
    if (rawHost !== null && isNumericLikeHost(rawHost) && !canonicalIPv4(rawHost)) {
      throw new GuardError('non-canonical-ip', `IPv4 no canónica en la URL: ${rawHost}`);
    }
    const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
    const ips = await this.resolveHost(hostname);
    return this.checkIps(hostname, ips, opts.isTTY);
  }

  /**
   * Hook `lookup` para http.request: resuelve, valida rangos y entrega al socket.
   * Si alguna IP no está permitida, llama cb(GuardError) y el socket no se abre.
   */
  // Node llama al hook con la forma (hostname, options, callback) y options puede ser número u objeto.
  lookup(hostname: string, options: any, callback: (...a: any[]) => void): void {
    const wantAll = typeof options === 'object' && options !== null && options.all === true;
    this.resolveHost(hostname)
      .then((ips) => {
        const allowed = this.checkIps(hostname, ips);
        if (wantAll) {
          callback(null, allowed.map((address) => ({ address, family: isIP(address) })));
        } else {
          callback(null, allowed[0], isIP(allowed[0]));
        }
      })
      .catch((err: unknown) => callback(err));
  }

  /** true si el método está permitido (GET/HEAD/OPTIONS siempre; el resto solo con allowMutations). */
  isMethodAllowed(method: string): boolean {
    return SAFE_METHODS.has(method.toUpperCase()) || this.config.allowMutations === true;
  }

  /** Valida un Location de redirect. Devuelve false sin lanzar si no debe seguirse. */
  async canFollowRedirect(location: string, baseUrl: string): Promise<boolean> {
    try {
      const base = new URL(baseUrl);
      const isAbsolute = /^[a-z][a-z0-9+.-]*:/i.test(location);
      const isProtocolRelative = /^[\\/]{2}/.test(location);
      if (!isAbsolute && !isProtocolRelative) {
        return true;
      }
      const raw = isAbsolute ? location : `${base.protocol}//${location.replace(/^[\\/]{2}/, '')}`;
      await this.assertTargetAllowed(raw);
      return true;
    } catch (e) {
      logger.warn(`Redirect no seguido hacia ${location}`, e);
      return false;
    }
  }

  private async resolveHost(hostname: string): Promise<string[]> {
    if (isIP(hostname)) return [hostname];
    try {
      const ips = this.config.resolver
        ? await this.config.resolver(hostname)
        : (await dns.promises.lookup(hostname, { all: true })).map((entry) => entry.address);
      if (ips.length === 0) {
        throw new GuardError('dns', `El host no resuelve: ${hostname}`);
      }
      return ips;
    } catch (e) {
      if (e instanceof GuardError) throw e;
      logger.warn(`Fallo al resolver ${hostname}`, e);
      throw new GuardError('dns', `El host no resuelve: ${hostname}`);
    }
  }

  private checkIps(hostname: string, ips: string[], isTTY?: boolean): string[] {
    const classes = ips.map(classifyIp);
    if (classes.includes('link-local')) {
      throw new GuardError('link-local', `${hostname} apunta a una dirección link-local/metadata; bloqueado siempre.`);
    }
    if (classes.includes('public')) {
      const interactive = isTTY ?? process.stdin.isTTY === true;
      const allowed = this.config.allowRemote === true && (interactive || this.config.allowRemoteEnv === true);
      if (!allowed) {
        throw new GuardError(
          'remote-blocked',
          `Host remoto bloqueado: ${hostname}. Usa --allow-remote si tienes autorización.`,
        );
      }
    }
    return ips;
  }
}
