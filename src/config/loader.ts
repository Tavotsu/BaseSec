import * as fs from 'node:fs';
import * as path from 'node:path';
import type { basesecConfig, Severity, OutputFormat, RuleConfigOverride } from '../rules/types';
import { SENSITIVE_FILE_PATTERNS } from './defaults';
import { logger } from '../utils/logger';

const CONFIG_FILES = [
  'basesec.config.ts',
  'basesec.config.js',
  'basesec.config.json',
  '.basesecrc',
  '.basesecrc.json',
];

export function loadConfig(
  configPath?: string,
  projectRoot?: string,
): Partial<basesecConfig> {
  const root = projectRoot ?? process.cwd();

  if (configPath) {
    const resolved = path.resolve(root, configPath);
    if (!fs.existsSync(resolved)) {
      throw new Error(`Config file not found: ${resolved}`);
    }
    return loadConfigFile(resolved);
  }

  for (const filename of CONFIG_FILES) {
    const filePath = path.join(root, filename);
    if (fs.existsSync(filePath)) {
      return loadConfigFile(filePath);
    }
  }

  return loadFromPackageJson(root);
}

function loadConfigFile(filePath: string): Partial<basesecConfig> {
  const ext = path.extname(filePath);
  const basename = path.basename(filePath);

  if (ext === '.json' || basename === '.basesecrc' || basename === '.basesecrc.json') {
    return loadJsonConfig(filePath);
  }

  if (ext === '.ts') {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const config = extractConfigFromTs(content);
      if (config) return normalizeConfig(config);
    } catch (e) {
      logger.warn(`Failed to read/parse TS config at ${filePath}`, e);
    }
    return {};
  }

  if (ext === '.js') {
    try {
      return loadJsConfig(filePath);
    } catch (e) {
      logger.warn(`Failed to read/parse JS config at ${filePath}`, e);
      return {};
    }
  }

  return {};
}

function loadJsonConfig(filePath: string): Partial<basesecConfig> {
  if (!fs.existsSync(filePath)) return {};
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(content);

    if (path.basename(filePath) === 'package.json') {
      if (parsed.basesec && typeof parsed.basesec === 'object') {
        return normalizeConfig(parsed.basesec);
      }
      return {};
    }

    if (path.basename(filePath) === '.basesecrc' || path.basename(filePath) === '.basesecrc.json') {
      return normalizeConfig(parsed);
    }

    return normalizeConfig(parsed);
  } catch (e) {
    throw new Error(`Failed to parse config file ${filePath}: ${e instanceof Error ? e.message : String(e)}`);
  }
}

function loadJsConfig(filePath: string): Partial<basesecConfig> {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');

    const moduleExportsMatch = content.match(/module\.exports\s*=\s*(\{[\s\S]*?\})\s*;?\s*$/m);
    if (moduleExportsMatch) {
      try {
        const literal = moduleExportsMatch[1];
        const config = safeParseObject(literal);
        if (config) return normalizeConfig(config);
      } catch {
        // Fall through
      }
    }

    const defaultExportMatch = content.match(/export\s+default\s+(\{[\s\S]*?\n\})\s*;?\s*$/m);
    if (defaultExportMatch) {
      try {
        const literal = defaultExportMatch[1];
        const config = safeParseObject(literal);
        if (config) return normalizeConfig(config);
      } catch {
        // Fall through
      }
    }

    return {};
  } catch {
    return {};
  }
}

function safeParseObject(literal: string): Record<string, unknown> | null {
  const cleaned = literal
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/.*$/gm, '')
    .replace(/,\s*([}\]])/g, '$1')
    .replace(/(\w+)\s*:/g, '"$1":')
    .replace(/'/g, '"');

  try {
    return JSON.parse(cleaned);
  } catch (e) {
    logger.warn('Failed to parse config object literal', e);
    return null;
  }
}

function extractConfigFromTs(content: string): Record<string, unknown> | null {
  const defineConfigMatch = content.match(/defineConfig\s*\(\s*(\{[\s\S]*?\})\s*\)/);
  if (defineConfigMatch) {
    return safeParseObject(defineConfigMatch[1]);
  }

  const defaultExportMatch = content.match(/export\s+default\s+(\{[\s\S]*?\n\})\s*;?\s*$/m);
  if (defaultExportMatch) {
    return safeParseObject(defaultExportMatch[1]);
  }

  const moduleExportsMatch = content.match(/module\.exports\s*=\s*(\{[\s\S]*?\})\s*;?\s*$/m);
  if (moduleExportsMatch) {
    return safeParseObject(moduleExportsMatch[1]);
  }

  return null;
}

function loadFromPackageJson(root: string): Partial<basesecConfig> {
  const pkgPath = path.join(root, 'package.json');
  if (!fs.existsSync(pkgPath)) return {};

  return loadJsonConfig(pkgPath);
}

function normalizeConfig(raw: Record<string, unknown>): Partial<basesecConfig> {
  const config: Partial<basesecConfig> = {};

  if (raw.target) config.target = raw.target as string[];
  if (raw.ignore) {
    config.ignore = raw.ignore as string[];
    checkSensitiveFileOverride(raw.ignore as string[]);
  }
  if (raw.framework) config.framework = raw.framework as basesecConfig['framework'];
  if (raw.severity) config.severity = raw.severity as Severity;
  if (raw.taintAnalysis !== undefined) config.taintAnalysis = raw.taintAnalysis as boolean;
  if (raw.rules) config.rules = raw.rules as string[];
  if (raw.rulesConfig) config.rulesConfig = raw.rulesConfig as Record<string, RuleConfigOverride | false>;
  if (raw.sanitizers) config.sanitizers = raw.sanitizers as string[];
  if (raw.maxFileSize !== undefined) config.maxFileSize = Number(raw.maxFileSize);
  if (raw.maxFiles !== undefined) config.maxFiles = Number(raw.maxFiles);
  if (raw.cache && typeof raw.cache === 'object') {
    const cache = raw.cache as Record<string, unknown>;
    config.cache = {
      maxAge: cache.maxAge !== undefined ? Number(cache.maxAge) : undefined,
      dir: typeof cache.dir === 'string' ? cache.dir : undefined,
    };
  }
  if (raw.workers && typeof raw.workers === 'object') {
    const workers = raw.workers as Record<string, unknown>;
    config.workers = {
      threshold: workers.threshold !== undefined ? Number(workers.threshold) : undefined,
      max: workers.max !== undefined ? Number(workers.max) : undefined,
    };
  }
  if (raw.output && typeof raw.output === 'object') {
    const output = raw.output as Record<string, unknown>;
    const fmt = typeof output.format === 'string' ? output.format as OutputFormat : undefined;
    const fpath = typeof output.filePath === 'string' ? output.filePath : undefined;
    if (fmt) {
      config.output = { format: fmt, filePath: fpath };
    }
  }
  if (raw.ai && typeof raw.ai === 'object') {
    const ai = raw.ai as Record<string, unknown>;
    config.ai = {
      enabled: ai.enabled === true,
      provider: (ai.provider as 'openai' | 'ollama') ?? 'ollama',
      model: typeof ai.model === 'string' ? ai.model : undefined,
      contextLevel: (['minimal', 'context', 'file'].includes(ai.contextLevel as string)
        ? (ai.contextLevel as 'minimal' | 'context' | 'file')
        : 'minimal'),
      baseUrl: typeof ai.baseUrl === 'string' ? ai.baseUrl : undefined,
      maxFindings: ai.maxFindings !== undefined ? Number(ai.maxFindings) : undefined,
      timeout: ai.timeout !== undefined ? Number(ai.timeout) : undefined,
    };
  }

  return config;
}

function checkSensitiveFileOverride(userIgnore: string[]): void {
  for (const pattern of SENSITIVE_FILE_PATTERNS) {
    const hasNegation = userIgnore.some((p) => p === `!${pattern}` || p === `!${pattern.replace(/\*\*/g, '')}`);
    if (hasNegation) {
      console.error(`  Warning: Sensitive file pattern "${pattern}" was removed from ignore list. This may expose credentials in scan output.`);
    }
  }
}

export { CONFIG_FILES };