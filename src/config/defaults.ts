import type { basesecConfig, Severity, OutputFormat, RuleConfigOverride } from '../rules/types';

export const DEFAULT_IGNORE_PATTERNS: string[] = [
  'node_modules/**',
  'dist/**',
  'build/**',
  '.next/**',
  '.nuxt/**',
  'coverage/**',
  '*.min.js',
  '*.min.ts',
  '**/*.d.ts',
  '**/*.spec.ts',
  '**/*.test.ts',
  '.git/**',
  'vendor/**',
];

export const DEFAULT_EXTENSIONS: string[] = [
  '.js',
  '.ts',
  '.mjs',
  '.cjs',
  '.jsx',
  '.tsx',
];

export const DEFAULT_CONFIG: basesecConfig = {
  target: ['./src'],
  ignore: DEFAULT_IGNORE_PATTERNS,
  framework: 'auto',
  severity: 'low',
  taintAnalysis: true,
  rules: ['./rules'],
  rulesConfig: {},
  sanitizers: [],
  output: {
    format: 'terminal',
  },
};

export function mergeConfigWithDefaults(
  fileConfig: Partial<basesecConfig>,
  cliOverrides: Partial<basesecConfig> = {},
): basesecConfig {
  return {
    target: cliOverrides.target ?? fileConfig.target ?? DEFAULT_CONFIG.target,
    ignore: [
      ...new Set([
        ...DEFAULT_CONFIG.ignore,
        ...(fileConfig.ignore ?? []),
        ...(cliOverrides.ignore ?? []),
      ]),
    ],
    framework: cliOverrides.framework ?? fileConfig.framework ?? DEFAULT_CONFIG.framework,
    severity: cliOverrides.severity ?? fileConfig.severity ?? DEFAULT_CONFIG.severity,
    taintAnalysis: cliOverrides.taintAnalysis ?? fileConfig.taintAnalysis ?? DEFAULT_CONFIG.taintAnalysis,
    rules: cliOverrides.rules ?? fileConfig.rules ?? DEFAULT_CONFIG.rules,
    rulesConfig: {
      ...DEFAULT_CONFIG.rulesConfig,
      ...fileConfig.rulesConfig,
      ...cliOverrides.rulesConfig,
    },
    sanitizers: [
      ...DEFAULT_CONFIG.sanitizers,
      ...(fileConfig.sanitizers ?? []),
      ...(cliOverrides.sanitizers ?? []),
    ],
    output: {
      format: cliOverrides.output?.format ?? fileConfig.output?.format ?? DEFAULT_CONFIG.output.format,
      filePath: cliOverrides.output?.filePath ?? fileConfig.output?.filePath ?? DEFAULT_CONFIG.output.filePath,
    },
  };
}