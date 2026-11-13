import type { ParsedFile } from '../../rules/types';
import type { ImportGraph } from '../../core/import-graph';

export type RouteParamLocation = 'path' | 'query' | 'body';

export interface RouteParam {
  name: string;
  in: RouteParamLocation;
  type?: string;
}

export interface StaticFindingRef {
  ruleId: string;
  /** Relativa a la raíz del proyecto, con `/` como separador. */
  filePath: string;
  line: number;
  via: 'handler' | 'import-graph';
}

export interface ExtractedRoute {
  /** MAYÚSCULAS: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, ALL. */
  method: string;
  /** Empieza por '/', sin '//' repetidos, sin '/' final salvo la raíz. */
  path: string;
  framework: 'express' | 'nestjs' | 'nextjs';
  /** Fichero del HANDLER, relativo a la raíz del proyecto. */
  filePath: string;
  /** Inicio del handler (1-based). */
  line: number;
  /** Fin del handler (1-based). */
  endLine: number;
  hasAuth: boolean | 'unknown';
  params: RouteParam[];
  reachableFiles: string[];
  staticFindings: StaticFindingRef[];
}

export interface UnresolvedRoute {
  filePath: string;
  line: number;
  reason: string;
}

export interface RouteArtifact {
  version: 1;
  generatedAt: string;
  /** Raíz del proyecto, absoluta. */
  target: string;
  frameworks: string[];
  routes: ExtractedRoute[];
  unresolved: UnresolvedRoute[];
}

export interface ExtractionContext {
  parsedFiles: ParsedFile[];
  graph: ImportGraph;
  /** Raíz del proyecto, absoluta. */
  root: string;
}

/** Ruta extraída antes de que el emisor calcule el grafo y los hallazgos. */
export type RawRoute = Omit<ExtractedRoute, 'reachableFiles' | 'staticFindings'>;

export interface ExtractionResult {
  routes: RawRoute[];
  unresolved: UnresolvedRoute[];
}
