import * as fs from 'node:fs';
import * as path from 'node:path';
import type { secbaseConfig, Severity, OutputFormat, RuleConfigOverride } from '../rules/types';

const CONFIG_FILES = [
  'secbase.config.ts',
  'secbase.config.js',
  'secbase.config.json',
  '.secbaserc',
  '.secbaserc.json',
];

export function loadConfig(
  configPath?: string,
  projectRoot?: string,
): Partial<secbaseConfig> {
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

function loadConfigFile(filePath: string): Partial<secbaseConfig> {
  const ext = path.extname(filePath);
  const basename = path.basename(filePath);

  if (ext === '.json' || basename === '.secbaserc' || basename === '.secbaserc.json') {
    return loadJsonConfig(filePath);
  }

  if (ext === '.ts') {
    return loadJsonConfig(findCorrespondingJson(filePath)) ?? {};
  }

  if (ext === '.js') {
    try {
      return loadJsConfig(filePath);
    } catch {
      return {};
    }
  }

  return {};
}

function findCorrespondingJson(tsPath: string): string {
  const dir = path.dirname(tsPath);
  const base = path.basename(tsPath, '.ts');
  const jsonPath = path.join(dir, base + '.json');
  if (fs.existsSync(jsonPath)) return jsonPath;

  return tsPath.replace(/\.ts$/, '.json');
}

function loadJsonConfig(filePath: string): Partial<secbaseConfig> {
  if (!fs.existsSync(filePath)) return {};
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(content);

    if (path.basename(filePath) === 'package.json') {
      if (parsed.secbase && typeof parsed.secbase === 'object') {
        return normalizeConfig(parsed.secbase);
      }
      return {};
    }

    if (path.basename(filePath) === '.secbaserc' || path.basename(filePath) === '.secbaserc.json') {
      return normalizeConfig(parsed);
    }

    return normalizeConfig(parsed);
  } catch (e) {
    throw new Error(`Failed to parse config file ${filePath}: ${e instanceof Error ? e.message : String(e)}`);
  }
}

function loadJsConfig(filePath: string): Partial<secbaseConfig> {
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
  } catch {
    return null;
  }
}

function loadFromPackageJson(root: string): Partial<secbaseConfig> {
  const pkgPath = path.join(root, 'package.json');
  if (!fs.existsSync(pkgPath)) return {};

  return loadJsonConfig(pkgPath);
}

function normalizeConfig(raw: Record<string, unknown>): Partial<secbaseConfig> {
  const config: Partial<secbaseConfig> = {};

  if (raw.target) config.target = raw.target as string[];
  if (raw.ignore) config.ignore = raw.ignore as string[];
  if (raw.framework) config.framework = raw.framework as secbaseConfig['framework'];
  if (raw.severity) config.severity = raw.severity as Severity;
  if (raw.taintAnalysis !== undefined) config.taintAnalysis = raw.taintAnalysis as boolean;
  if (raw.rules) config.rules = raw.rules as string[];
  if (raw.rulesConfig) config.rulesConfig = raw.rulesConfig as Record<string, RuleConfigOverride | false>;
  if (raw.sanitizers) config.sanitizers = raw.sanitizers as string[];
  if (raw.output && typeof raw.output === 'object') {
    const output = raw.output as Record<string, unknown>;
    const fmt = typeof output.format === 'string' ? output.format as OutputFormat : undefined;
    const fpath = typeof output.filePath === 'string' ? output.filePath : undefined;
    if (fmt) {
      config.output = { format: fmt, filePath: fpath };
    }
  }

  return config;
}

export { CONFIG_FILES };