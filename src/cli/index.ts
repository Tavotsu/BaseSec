#!/usr/bin/env node
import { cac } from 'cac';
import { printBanner, printError } from './output';
import { runScan } from './commands/scan';
import { runInit } from './commands/init';
import { ALL_RULES } from '../rules/index';
import pc from 'picocolors';
import type { CliOptions, OutputFormat, Severity, RuleCategory } from '../rules/types';

const VALID_FORMATS: OutputFormat[] = ['terminal', 'json', 'sarif', 'html', 'markdown'];
const VALID_SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const VALID_FRAMEWORKS = ['auto', 'express', 'nestjs', 'mongoose', 'typeorm', 'fastify', 'koa', 'prisma'];

function kebabToCamel(str: string): string {
  return str.replace(/-([a-z])/g, (_: string, c: string) => c.toUpperCase());
}

function hasArg(arg: string): boolean {
  const camel = kebabToCamel(arg);
  return process.argv.includes('--' + arg) ||
         process.argv.includes('--' + arg + '=true') ||
         process.argv.includes('--' + camel) ||
         process.argv.includes('--' + camel + '=true');
}

function getArgValue(arg: string): string | undefined {
  const camel = kebabToCamel(arg);
  for (let i = 0; i < process.argv.length; i++) {
    const current = process.argv[i];
    if (current === '--' + arg && process.argv[i + 1] && !process.argv[i + 1].startsWith('--')) {
      return process.argv[i + 1];
    }
    if (current.startsWith('--' + arg + '=')) {
      return current.split('=')[1];
    }
    if (current === '--' + camel && process.argv[i + 1] && !process.argv[i + 1].startsWith('--')) {
      return process.argv[i + 1];
    }
    if (current.startsWith('--' + camel + '=')) {
      return current.split('=')[1];
    }
  }
  return undefined;
}

export async function main(): Promise<void> {
  const cli = cac('basesec');

  cli
    .version('0.1.3')
    .usage('<command> [options]');

  cli
    .command('scan [path]', 'Scan a directory for vulnerabilities')
    .option('--format <format>, -f', 'Output format: terminal|json|sarif|html|markdown', { default: 'terminal' })
    .option('--output <file>, -o', 'Output file path')
    .option('--severity <level>, -s', 'Minimum severity: critical|high|medium|low|info', { default: 'low' })
    .option('--rules <rules>, -r', 'Comma-separated rule IDs to run')
    .option('--ignore <patterns>, -i', 'Glob patterns to ignore', { type: [] })
    .option('--config <path>, -c', 'Path to config file')
    .option('--no-taint', 'Disable taint analysis')
    .option('--quiet, -q', 'Only show summary')
    .option('--strict', 'Exit with code 1 on any finding')
    .option('--framework <fw>', 'Force framework: express|nestjs|mongoose|typeorm|fastify|koa|prisma|auto', { default: 'auto' })
    .option('--no-color', 'Disable colored output')
    .option('--no-banner', 'Disable banner')
    .option('--workers <num>', 'Number of worker threads (default: auto)')
    .option('--no-cache', 'Disable result caching')
    .option('--no-deps', 'Disable dependency checking')
    .option('--read-env', 'Allow scanning of .env files')
    .option('--verbose, -V', 'Show verbose output')
    .action(async (path: string | undefined, options: any) => {
      const targetPath = path || process.cwd();

      const format = (options.format ?? 'terminal') as string;
      if (!VALID_FORMATS.includes(format as OutputFormat)) {
        printError(`Invalid format: ${format}. Valid options: ${VALID_FORMATS.join(', ')}`);
        process.exit(2);
      }

      const severity = (options.severity ?? 'low') as string;
      if (!VALID_SEVERITIES.includes(severity as Severity)) {
        printError(`Invalid severity: ${severity}. Valid options: ${VALID_SEVERITIES.join(', ')}`);
        process.exit(2);
      }

      const framework = (options.framework ?? 'auto') as string;
      if (!VALID_FRAMEWORKS.includes(framework)) {
        printError(`Invalid framework: ${framework}. Valid options: ${VALID_FRAMEWORKS.join(', ')}`);
        process.exit(2);
      }

      let workers: number | undefined = undefined;
      if (options.workers !== undefined && options.workers !== 'auto') {
        workers = parseInt(options.workers, 10);
        if (isNaN(workers) || workers < 0) {
          printError(`Invalid workers value: ${options.workers}. Must be a non-negative integer or "auto".`);
          process.exit(2);
        }
      }

      const rawIgnore: string[] = Array.isArray(options.ignore)
        ? options.ignore.filter((v: any) => v !== null && v !== undefined)
        : [];

      const cliOptions: CliOptions = {
        format: format as OutputFormat,
        output: options.output,
        severity: severity as Severity,
        rules: options.rules,
        ignore: rawIgnore,
        config: options.config,
        noTaint: options.taint === false,
        quiet: options.quiet ?? false,
        strict: options.strict ?? false,
        framework: framework as 'auto' | 'express' | 'nestjs' | 'mongoose' | 'typeorm' | 'fastify' | 'koa' | 'prisma',
        noColor: options.color === false,
        noBanner: options.banner === false,
        workers,
        noCache: options.cache === false || hasArg('no-cache'),
        noDeps: options.deps === false || hasArg('no-deps'),
        readEnv: options.readEnv === true || hasArg('read-env'),
        verbose: options.verbose === true || hasArg('verbose'),
      };

      if (!cliOptions.noBanner && !cliOptions.quiet) {
        printBanner(cliOptions.noColor);
      }

      try {
        const exitCode = await runScan(targetPath, cliOptions);
        process.exit(exitCode);
      } catch (e) {
        printError(e instanceof Error ? e.message : String(e));
        process.exit(2);
      }
    });

  cli
    .command('init', 'Initialize a basesec config file')
    .option('--format <format>', 'Config format: ts or json', { default: 'ts' })
    .action(async (options: any) => {
      try {
        await runInit(options.format ?? 'ts');
      } catch (e) {
        printError(e instanceof Error ? e.message : String(e));
        process.exit(2);
      }
    });

  cli
    .command('rules', 'List all built-in rules')
    .option('--category <cat>', 'Filter by category')
    .option('--severity <level>, -s', 'Filter by severity')
    .action((options: any) => {
      const category = options.category as string | undefined;
      const severity = options.severity as string | undefined;

      let rules = [...ALL_RULES];

      if (category) {
        rules = rules.filter((r) => r.category === category);
      }
      if (severity) {
        rules = rules.filter((r) => r.severity === severity);
      }

      if (rules.length === 0) {
        console.log(pc.yellow('  No rules found matching the specified filters.'));
        return;
      }

      const severityColors: Record<string, (s: string) => string> = {
        critical: pc.red,
        high: pc.red,
        medium: pc.yellow,
        low: pc.blue,
        info: pc.gray,
      };

      console.log(pc.bold(`\n  basesec rules (${rules.length} rules)\n`));

      const byCategory = new Map<string, typeof rules>();
      for (const rule of rules) {
        const cat = rule.category;
        if (!byCategory.has(cat)) byCategory.set(cat, []);
        byCategory.get(cat)!.push(rule);
      }

      for (const [cat, catRules] of byCategory) {
        console.log(pc.cyan(`  ${cat}`));
        for (const rule of catRules) {
          const colorFn = severityColors[rule.severity] ?? pc.white;
          const label = rule.severity.toUpperCase().padEnd(8);
          const frameworks = rule.frameworks.join(', ');
          console.log(`    ${colorFn(label)} ${pc.bold(rule.id)}: ${rule.name}`);
          console.log(pc.gray(`      ${rule.description}`));
          console.log(pc.gray(`      Frameworks: ${frameworks} | Tags: ${rule.tags.join(', ')}`));
        }
        console.log('');
      }
    });

  cli.help();

  try {
    cli.parse();
  } catch (e) {
    printError(e instanceof Error ? e.message : String(e));
    process.exit(2);
  }
}

main().catch((e) => {
  printError(e instanceof Error ? e.message : String(e));
  process.exit(2);
});