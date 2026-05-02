import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/cli/index.ts'],
  format: ['esm'],
  target: 'node18',
  banner: {
    js: '#!/usr/bin/env node',
  },
  clean: true,
  outDir: 'dist',
  splitting: false,
  sourcemap: true,
  dts: true,
  platform: 'node',
  external: [
    'typescript',
  ],
});