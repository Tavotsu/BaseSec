/** Error de configuración DAST (exit 3). Los mensajes nunca incluyen valores de secretos. */
export class DastConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DastConfigError';
  }
}

const ENV_REFERENCE = /\$env:([A-Za-z_][A-Za-z0-9_]*)/g;
/** Token RFC 7230 para nombres de cabecera. */
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
/** Valores de cabecera: TAB, ASCII imprimible y latin1 (Node no envía otra cosa). Rechaza CR, LF y controles. */
const HEADER_VALUE_FORBIDDEN = /[^\t\u0020-\u007E\u0080-\u00FF]/;

function assertHeader(name: string, value: string): void {
  if (!HEADER_NAME.test(name)) {
    throw new DastConfigError('Invalid header name: it must be an HTTP token (letters, digits and !#$%&\'*+.^_`|~-)');
  }
  if (HEADER_VALUE_FORBIDDEN.test(value)) {
    throw new DastConfigError(`Invalid value for header "${name}": control characters (CR, LF) and non-Latin-1 characters are not allowed`);
  }
}

/**
 * Sustituye "$env:NOMBRE" en los valores de cabeceras por el valor de la variable de entorno.
 * Lanza DastConfigError si la variable no existe o está vacía (solo se nombra la variable).
 */
export function expandEnvHeaders(
  headers: Record<string, string>,
  env: NodeJS.ProcessEnv = process.env,
): Record<string, string> {
  const expanded: Record<string, string> = {};
  for (const [name, rawValue] of Object.entries(headers)) {
    const value = rawValue.replace(ENV_REFERENCE, (_match, variable: string) => {
      const resolved = env[variable];
      if (resolved === undefined || resolved === '') {
        throw new DastConfigError(
          `Environment variable ${variable} is not set or empty (used in header "${name}")`,
        );
      }
      return resolved;
    });
    assertHeader(name, value);
    expanded[name] = value;
  }
  return expanded;
}

/** Parsea "Nombre: valor" (de --header). Lanza DastConfigError si no hay ':' o el nombre no es válido. */
export function parseHeaderFlag(raw: string): [string, string] {
  const colon = raw.indexOf(':');
  if (colon === -1) {
    throw new DastConfigError('Invalid --header value: expected the form "Name: value"');
  }
  const name = raw.slice(0, colon).trim();
  const value = raw.slice(colon + 1).trim();
  assertHeader(name, value);
  return [name, value];
}
