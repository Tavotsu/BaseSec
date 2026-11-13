export type NextRouteFileKind = 'app-route' | 'pages-api';

export interface NextRouteFile {
  kind: NextRouteFileKind;
  /**
   * Carpetas entre `app/` (o `pages/`) y el fichero. En Pages incluye el nombre sin extensión
   * y se quita `index`. Las carpetas `api` cuentan: forman parte de la URL.
   */
  segments: string[];
}

const APP_ROUTE_FILE = /^route\.(ts|js|mjs|cjs)$/;
const PAGES_EXTENSION = /^(.+)\.(ts|tsx|js|jsx|mjs|cjs)$/;
const EXCLUDED_NAME = /\.(test|spec)\.[^/\\]+$|\.d\.ts$/;

/**
 * Clasifica un fichero del proyecto como route handler de Next.js (plan §5.7).
 * App Router: `app/**\/route.{ts,js,mjs,cjs}` o `src/app/**`. Pages Router: `pages/api/**` o
 * `src/pages/api/**` con cualquier extensión de script. Lo demás, incluidos los tests, es null.
 */
export function classifyNextFile(relPath: string): NextRouteFile | null {
  const parts = relPath.split('/').filter((p) => p !== '' && p !== '.');
  const name = parts[parts.length - 1];
  if (name === undefined || EXCLUDED_NAME.test(name)) return null;

  const rest = parts[0] === 'src' ? parts.slice(1) : parts;

  if (rest[0] === 'app' && rest.length >= 2 && APP_ROUTE_FILE.test(name)) {
    return { kind: 'app-route', segments: rest.slice(1, -1) };
  }

  if (rest[0] === 'pages' && rest[1] === 'api' && rest.length >= 3) {
    const match = PAGES_EXTENSION.exec(name);
    if (match === null) return null;
    // Relativos a `pages/`: `api` forma parte de la URL, igual que `app/api` en el App Router.
    const segments = [...rest.slice(1, -1), match[1]];
    if (segments[segments.length - 1] === 'index') segments.pop();
    return { kind: 'pages-api', segments };
  }

  return null;
}

/**
 * Versión para rutas absolutas que usa el taint, que no puede leer disco. Regla: la ruta tiene
 * un directorio `app` y el fichero es `route.{ts,js,mjs,cjs}` (se mira el último `app`), o tiene
 * los segmentos consecutivos `pages/api` y una extensión de script del Pages Router.
 *
 * Riesgo aceptado: un `app/` anidado que no sea de Next también casa. Por eso el taint solo
 * llama a esta función cuando `nextjs` está entre los frameworks detectados.
 */
export function nextRouteFileKindOfPath(absPath: string): NextRouteFileKind | undefined {
  const segments = absPath.split(/[\\/]+/).filter((s) => s !== '');
  const name = segments[segments.length - 1];
  if (name === undefined || EXCLUDED_NAME.test(name)) return undefined;
  const dirs = segments.slice(0, -1);

  if (APP_ROUTE_FILE.test(name) && dirs.includes('app')) return 'app-route';

  const match = PAGES_EXTENSION.exec(name);
  if (match !== null) {
    for (let i = 0; i + 1 < dirs.length; i++) {
      if (dirs[i] === 'pages' && dirs[i + 1] === 'api') return 'pages-api';
    }
  }
  return undefined;
}

export function isNextRouteHandlerPath(absPath: string): boolean {
  return nextRouteFileKindOfPath(absPath) !== undefined;
}
