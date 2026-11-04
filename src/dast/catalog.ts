import type { RuleCategory, Severity } from '../rules/types';

/** Ámbito de un hallazgo DAST: una vez por target, o por endpoint de la superficie. */
export type DastScope = 'target' | 'endpoint';

/**
 * Metadatos de cada regla DAST implementada, para `basesec rules`. Incluye pasivas (DAST-001…007), activas
 * (DAST-008, DAST-010) e inyección (DAST-011, DAST-1xx). DAST-009 no figura: no está implementada (plan §4.3).
 * Los metadatos de las pasivas se comprueban contra sus objetos en tests/cli/rules-dast.test.ts.
 */
export interface DastCatalogEntry {
  id: string;
  name: string;
  severity: Severity;
  category: RuleCategory;
  scope: DastScope;
  note: string;
}

export const DAST_CATALOG: readonly DastCatalogEntry[] = [
  {
    id: 'DAST-001',
    name: 'Missing security headers',
    severity: 'medium',
    category: 'misconfiguration',
    scope: 'target',
    note: 'Sin X-Content-Type-Options, X-Frame-Options (o frame-ancestors) ni Referrer-Policy en HTML.',
  },
  {
    id: 'DAST-002',
    name: 'Missing HSTS',
    severity: 'medium',
    category: 'misconfiguration',
    scope: 'target',
    note: 'Sin Strict-Transport-Security sobre HTTPS.',
  },
  {
    id: 'DAST-003',
    name: 'Missing or weak Content-Security-Policy',
    severity: 'medium',
    category: 'misconfiguration',
    scope: 'target',
    note: 'Sin CSP, o con unsafe-inline, unsafe-eval o * en script-src / default-src.',
  },
  {
    id: 'DAST-004',
    name: 'Permissive CORS at runtime',
    severity: 'high',
    category: 'misconfiguration',
    scope: 'target',
    note: 'Refleja un Origin arbitrario (o null) con Access-Control-Allow-Credentials: true.',
  },
  {
    id: 'DAST-005',
    name: 'Insecure cookie flags',
    severity: 'high',
    category: 'misconfiguration',
    scope: 'endpoint',
    note: 'Set-Cookie sin HttpOnly, SameSite o Secure (sobre HTTPS).',
  },
  {
    id: 'DAST-006',
    name: 'Stack trace exposed',
    severity: 'high',
    category: 'error-handling',
    scope: 'endpoint',
    note: 'Respuesta 5xx con un stack trace de Node.js y rutas internas.',
  },
  {
    id: 'DAST-007',
    name: 'Server banner leakage',
    severity: 'low',
    category: 'misconfiguration',
    scope: 'target',
    note: 'X-Powered-By, o Server con versión.',
  },
  {
    id: 'DAST-008',
    name: 'Unauthenticated sensitive endpoint',
    severity: 'medium',
    category: 'auth',
    scope: 'endpoint',
    note: 'Ruta sensible sin auth en el artefacto que responde 2xx sin credenciales. Requiere --routes o --scan.',
  },
  {
    id: 'DAST-010',
    name: 'Missing rate limiting',
    severity: 'low',
    category: 'auth',
    scope: 'target',
    note: 'Opt-in con --probe-rate-limit: 30 peticiones en ráfaga a un login o al healthcheck.',
  },
  {
    id: 'DAST-011',
    name: 'Open redirect (confirmed at runtime)',
    severity: 'medium',
    category: 'xss',
    scope: 'endpoint',
    note: 'Location que apunta a otro host tras inyectar una URL externa. Requiere --routes o --scan.',
  },
  {
    id: 'DAST-101',
    name: 'SQL injection (confirmed at runtime)',
    severity: 'critical',
    category: 'sql-injection',
    scope: 'endpoint',
    note: 'Inyección confirmada por oráculo (error SQL, timing, diff). Requiere --routes o --scan.',
  },
  {
    id: 'DAST-102',
    name: 'NoSQL injection (confirmed at runtime)',
    severity: 'high',
    category: 'nosql-injection',
    scope: 'endpoint',
    note: 'Inyección de operadores confirmada por diff de respuesta. Requiere --routes o --scan.',
  },
  {
    id: 'DAST-103',
    name: 'Command injection (confirmed at runtime)',
    severity: 'critical',
    category: 'command-injection',
    scope: 'endpoint',
    note: 'Inyección de comandos confirmada por timing. Requiere --routes o --scan.',
  },
  {
    id: 'DAST-104',
    name: 'Path traversal (confirmed at runtime)',
    severity: 'critical',
    category: 'path-traversal',
    scope: 'endpoint',
    note: 'Lectura de un fichero fuera del directorio por firma conocida. Requiere --routes o --scan.',
  },
  {
    id: 'DAST-105',
    name: 'Reflected XSS (confirmed at runtime)',
    severity: 'high',
    category: 'xss',
    scope: 'endpoint',
    note: 'Reflexión sin escapar del canario en una respuesta HTML. Requiere --routes o --scan.',
  },
];
