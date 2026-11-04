import { defineConfig } from 'tsup';

// tsup corre las dos configuraciones en paralelo: ninguna puede usar clean (la limpieza va en el script build).
export default defineConfig([
  {
    entry: {
      index: 'src/cli/index.ts',
      worker: 'src/worker/analyzer.ts'
    },
    format: ['esm'],
    target: 'node22',
    clean: false,
    outDir: 'dist',
    splitting: false,
    sourcemap: true,
    dts: true,
    platform: 'node',
    external: [
      'typescript',
    ],
    esbuildOptions(options) {
      options.banner = {
        js: 'import { createRequire } from "module"; const require = createRequire(import.meta.url);',
      };
    }
  },
  {
    // Agente IAST: bundle CJS autocontenido que se carga con --require dentro de la app del usuario (plan §6.1).
    entry: { agent: 'src/dast/agent/index.ts' },
    format: ['cjs'],
    target: 'node22',
    outDir: 'dist',
    outExtension: () => ({ js: '.cjs' }),
    clean: false,
    dts: false,
    sourcemap: false,
    platform: 'node',
    noExternal: [/.*/],
  },
]);
