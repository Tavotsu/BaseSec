import * as os from 'node:os';
import type { basesecConfig, Severity, OutputFormat, RuleConfigOverride } from '../rules/types';

export const SENSITIVE_FILE_PATTERNS: string[] = [
  '**/.env',
  '**/.env.*',
  '**/.env.local',
  '**/.env.*.local',
  '**/secrets.*',
  '**/credentials.*',
  '**/*.pem',
  '**/*.key',
  '**/*.p12',
  '**/*.pfx',
];

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
  ...SENSITIVE_FILE_PATTERNS,
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
  maxFileSize: 500 * 1024,
  maxFiles: 10000,
  cache: {
    maxAge: 24 * 60 * 60 * 1000,
    dir: os.tmpdir() + '/basesec-cache',
  },
  workers: {
    threshold: 50,
    max: 4,
  },
  output: {
    format: 'terminal',
  },
  ai: undefined,
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
    maxFileSize: cliOverrides.maxFileSize ?? fileConfig.maxFileSize ?? DEFAULT_CONFIG.maxFileSize,
    maxFiles: cliOverrides.maxFiles ?? fileConfig.maxFiles ?? DEFAULT_CONFIG.maxFiles,
    cache: {
      maxAge: fileConfig.cache?.maxAge ?? DEFAULT_CONFIG.cache!.maxAge,
      dir: fileConfig.cache?.dir ?? DEFAULT_CONFIG.cache!.dir,
    },
    workers: {
      threshold: fileConfig.workers?.threshold ?? DEFAULT_CONFIG.workers!.threshold,
      max: fileConfig.workers?.max ?? DEFAULT_CONFIG.workers!.max,
    },
    output: {
      format: cliOverrides.output?.format ?? fileConfig.output?.format ?? DEFAULT_CONFIG.output.format,
      filePath: cliOverrides.output?.filePath ?? fileConfig.output?.filePath ?? DEFAULT_CONFIG.output.filePath,
    },
    ai: cliOverrides.ai ?? fileConfig.ai ?? DEFAULT_CONFIG.ai,
  };
}