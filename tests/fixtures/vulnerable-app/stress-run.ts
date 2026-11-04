// Prueba de estrés de cierre limpio (la lanza tests/dast/runner-inject.test.ts en un proceso aparte): ataca el
// fixture lento con un presupuesto muy bajo y un timeout de petición corto. Si el cliente dejase un timer o un
// socket vivo, este proceso NO terminaría solo y la prueba del padre agotaría su tiempo.
import { createVulnerableApp } from './server.mjs';
import { runDast } from '../../../src/dast/runner';

const app = createVulnerableApp();
const origin = await app.start();
const result = await runDast({
  url: origin,
  surface: {
    artifact: {
      version: 1,
      generatedAt: '2026-08-02T10:00:00.000Z',
      target: '/tmp/basesec-stress-app',
      frameworks: ['express'],
      routes: [
        {
          method: 'GET',
          path: '/slow',
          framework: 'express',
          filePath: 'src/slow.ts',
          line: 1,
          endLine: 3,
          hasAuth: false,
          params: [{ name: 'x', in: 'query' }],
          reachableFiles: [],
          staticFindings: [],
        },
      ],
      unresolved: [],
    },
    source: 'routes-file',
    stale: false,
  },
  maxRequests: 2,
  requestTimeout: 300,
  evidence: false,
  injectionDelaySeconds: 1,
});
await app.stop();
process.stdout.write(`${JSON.stringify({ incomplete: result.stats.dast?.incomplete, requests: result.stats.dast?.requests })}\n`);
