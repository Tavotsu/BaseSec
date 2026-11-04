#!/usr/bin/env node
import { cac } from 'cac';
import { printBanner, printError } from './output';
import { VERSION } from '../version';
import { runScan } from './commands/scan';
import { runDastCommand } from './commands/dast';
import { runInit } from './commands/init';
import { ALL_RULES } from '../rules/index';
import { ALL_DAST_RULES } from '../dast/rules/index';
import pc from 'picocolors';
import { revokeConsent } from '../ai/consent';
import type { CliOptions, OutputFormat, Severity } from '../rules/types';
import { VALID_FORMATS, VALID_SEVERITIES } from './validation';

const VALID_FRAMEWORKS = ['auto', 'express', 'nestjs', 'mongoose', 'typeorm', 'fastify', 'koa', 'prisma', 'react', 'nextjs', 'vue', 'angular', 'svelte'];

export async function main(): Promise<void> {
  const cli = cac('basesec');

  cli
    .version(VERSION)
    .usage('<command> [options]');

  cli
    .command('scan [path]', 'Scan a directory for vulnerabilities')
    .option('--format <format>, -f', 'Output format: terminal|json|sarif|html|markdown', { default: 'terminal' })
    .option('--output [file], -o', 'Output file path (default: ~/.basesec/scan-<timestamp>.<format>)')
    .option('--severity <level>, -s', 'Minimum severity: critical|high|medium|low|info', { default: 'low' })
    .option('--rules <rules>, -r', 'Comma-separated rule IDs to run')
    .option('--ignore <patterns>, -i', 'Glob patterns to ignore', { type: [] })
    .option('--config <path>, -c', 'Path to config file')
    .option('--no-taint', 'Disable taint analysis')
    .option('--quiet, -q', 'Only show summary')
    .option('--strict', 'Exit with code 1 on any finding')
    .option('--framework <fw>', 'Force framework: express|nestjs|mongoose|typeorm|fastify|koa|prisma|react|nextjs|vue|angular|svelte|auto', { default: 'auto' })
    .option('--no-color', 'Disable colored output')
    .option('--no-banner', 'Disable banner')
    .option('--workers <num>', 'Number of worker threads (default: auto)')
    .option('--no-cache', 'Disable result caching')
    .option('--no-deps', 'Disable dependency checking')
    .option('--read-env', 'Allow scanning of .env files ',{ default: 'false' })
    .option('--verbose, -V', 'Show verbose output')
    .option('--ai', 'Enable AI-powered analysis enhancement')
    .option('--ai-provider <provider>', 'LLM provider: ollama|openai')
    .option('--ai-model <model>', 'LLM model to use')
    .option('--ai-dry-run', 'Show what would be sent to the LLM without sending')
    .option('--ai-context <level>', 'Context level: minimal|context|file', { default: 'minimal' })
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
        framework: framework as 'auto' | 'express' | 'nestjs' | 'mongoose' | 'typeorm' | 'fastify' | 'koa' | 'prisma' | 'react' | 'nextjs' | 'vue' | 'angular' | 'svelte',
        noColor: options.color === false,
        noBanner: options.banner === false,
        workers,
        noCache: options.cache === false,
        noDeps: options.deps === false,
        readEnv: options.readEnv === true,
        verbose: options.verbose === true,
        ai: options.ai === true,
        aiProvider: options.aiProvider,
        aiModel: options.aiModel,
        aiDryRun: options.aiDryRun === true,
        aiContext: options.aiContext,
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
    .command('dast [url]', 'Test a running app for runtime security issues')
    .option('--health <path>', 'Healthcheck path (default: /)')
    .option('--header <header>', 'Request header "Name: value" (repeatable)', { type: [] })
    .option('--allow-remote', 'Allow non-local targets (requires confirmation)')
    .option('--rps <n>', 'Requests per second (default: 20)')
    .option('--concurrency <n>', 'Parallel requests (default: 5)')
    .option('--max-requests <n>', 'Hard request budget (default: 5000)')
    .option('--timeout <s>', 'Global timeout in seconds (default: 300)')
    .option('--request-timeout <ms>', 'Per-request timeout (default: 10000)')
    .option('--evidence-dir <dir>', 'Where to write .http evidence (default: ~/.basesec)')
    .option('--no-evidence', 'Do not write evidence files')
    .option('--rules <ids>', 'Comma-separated DAST rule IDs')
    .option('--config <path>, -c', 'Path to config file')
    .option('--allow-vulnerable-node', 'Run even if Node lacks mandatory security patches')
    .option('--format <format>, -f', 'Output format: terminal|json|sarif|html|markdown', { default: 'terminal' })
    .option('--output [file], -o', 'Output file path (default: ~/.basesec/scan-<timestamp>.<format>)')
    .option('--severity <level>, -s', 'Minimum severity: critical|high|medium|low|info', { default: 'low' })
    .option('--strict', 'Exit with code 1 on any finding')
    .option('--quiet, -q', 'Only show summary')
    .option('--verbose, -V', 'Show verbose output')
    .option('--no-color', 'Disable colored output')
    .option('--no-banner', 'Disable banner')
    .action(async (url: string | undefined, options: any) => {
      const format = (options.format ?? 'terminal') as string;
      if (!VALID_FORMATS.includes(format as OutputFormat)) {
        printError(`Invalid format: ${format}. Valid options: ${VALID_FORMATS.join(', ')}`);
        process.exit(3);
      }

      const severity = (options.severity ?? 'low') as string;
      if (!VALID_SEVERITIES.includes(severity as Severity)) {
        printError(`Invalid severity: ${severity}. Valid options: ${VALID_SEVERITIES.join(', ')}`);
        process.exit(3);
      }

      const headerFlags: string[] = Array.isArray(options.header)
        ? options.header.filter((v: unknown): v is string => typeof v === 'string')
        : [];

      // El banner va a stdout: con un formato no terminal rompería `-f json > fichero`.
      if (format === 'terminal' && options.banner !== false && options.quiet !== true) {
        printBanner(options.color === false);
      }

      try {
        const exitCode = await runDastCommand(url, {
          format: format as OutputFormat,
          output: options.output,
          severity: severity as Severity,
          strict: options.strict === true,
          quiet: options.quiet === true,
          verbose: options.verbose === true,
          noColor: options.color === false,
          config: options.config,
          health: options.health,
          header: headerFlags,
          allowRemote: options.allowRemote === true,
          allowVulnerableNode: options.allowVulnerableNode === true,
          rps: options.rps,
          concurrency: options.concurrency,
          maxRequests: options.maxRequests,
          timeout: options.timeout,
          requestTimeout: options.requestTimeout,
          evidenceDir: options.evidenceDir,
          // cac pone evidence=true por defecto: solo --no-evidence cuenta como flag explícito (la config decide el resto).
          evidence: options.evidence === false ? false : undefined,
          rules: options.rules,
        });
        process.exit(exitCode);
      } catch (e) {
        printError(e instanceof Error ? e.message : String(e));
        process.exit(2);
      }
    });

  cli
    .command('init', 'Initialize basesec config file')
    .option('--format <format>', 'Config format: ts or json', { default: 'ts' })
    .option('--revoke-ai-consent', 'Revoke AI consent')
    .action(async (options: any) => {
      if (options.revokeAiConsent) {
        revokeConsent();
        console.log('  AI consent revoked. You will be prompted again on next AI-enabled scan.');
        return;
      }
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
    .option('--dast', 'Show only DAST (runtime) rules')
    .action((options: any) => {
      const category = options.category as string | undefined;
      const severity = options.severity as string | undefined;
      const matches = (rule: { category: string; severity: string }): boolean =>
        (!category || rule.category === category) && (!severity || rule.severity === severity);

      const sastRules = options.dast === true ? [] : ALL_RULES.filter(matches);
      const dastRules = ALL_DAST_RULES.filter(matches);
      const total = sastRules.length + dastRules.length;

      if (total === 0) {
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

      console.log(pc.bold(`\n  basesec rules (${total} rules)\n`));

      const byCategory = new Map<string, typeof sastRules>();
      for (const rule of sastRules) {
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

      if (dastRules.length > 0) {
        console.log(pc.cyan('  DAST (runtime)'));
        for (const rule of dastRules) {
          const colorFn = severityColors[rule.severity] ?? pc.white;
          const label = rule.severity.toUpperCase().padEnd(8);
          console.log(`    ${colorFn(label)} ${pc.bold(rule.id)}: ${rule.name}`);
          console.log(pc.gray(`      ${rule.description}`));
          console.log(pc.gray(`      Scope: ${rule.once ? 'target' : 'endpoint'}`));
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
