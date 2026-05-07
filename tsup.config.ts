import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/cli/index.ts',
    worker: 'src/worker/analyzer.ts'
  },
  format: ['esm'],
  target: 'node18',
  clean: true,
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
});