#!/usr/bin/env node
import { cac } from 'cac';
import { printBanner, printError } from './output';
import { VERSION } from '../version';
import { runScan } from './commands/scan';
import { runDastCommand } from './commands/dast';
import { runVerify } from './commands/verify';
import { runInit } from './commands/init';
import { ALL_RULES } from '../rules/index';
import { DAST_CATALOG } from '../dast/catalog';
import pc from 'picocolors';
import { revokeConsent } from '../ai/consent';
import type { CliOptions, OutputFormat, Severity, VerifyDastOptions } from '../rules/types';
import { VALID_FORMATS, VALID_SEVERITIES, validateRouteOptions, validateVerifyOptions } from './validation';

const VALID_FRAMEWORKS = ['auto', 'express', 'nestjs', 'mongoose', 'typeorm', 'fastify', 'koa', 'prisma', 'react', 'nextjs', 'vue', 'angular', 'svelte'];

/** Repetibles --dast-header. cac rellena con null las ausentes (`type: []`), así que solo cuentan las cadenas. */
function dastHeaderValues(options: any): string[] {
  const headers: unknown = options.dastHeader;
  return Array.isArray(headers) ? headers.filter((v): v is string => typeof v === 'string') : [];
}

/** Flags --dast-* de `scan --verify` tal como los entrega cac (valores crudos: runVerify los valida). */
function verifyDastOptions(options: any): VerifyDastOptions {
  return {
    allowRemote: options.dastAllowRemote === true,
    allowVulnerableNode: options.dastAllowVulnerableNode === true,
    headers: dastHeaderValues(options),
    rules: options.dastRules,
    probeRateLimit: options.dastProbeRateLimit === true,
    agent: options.dastAgent === true,
    timeout: options.dastTimeout,
    requestTimeout: options.dastRequestTimeout,
    rps: options.dastRps,
    maxRequests: options.dastMaxRequests,
    evidenceDir: options.dastEvidenceDir,
    evidence: options.dastEvidence === false ? false : undefined,
  };
}

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
    .option('--emit-routes', 'Write the route artifact (attack surface) instead of the report')
    .option('--routes-out <file>', 'Path for the route artifact (requires --emit-routes; default ~/.basesec/routes/)')
    .option('--verify', 'Confirm static findings at runtime: attacks --target with the routes of this code (requires --target)')
    .option('--target <url>', 'Running app to verify against (used with --verify)')
    .option('--dast-allow-remote', 'Allow a non-local --target in --verify (requires confirmation)')
    .option('--dast-header <header>', 'Request header "Name: value" for --verify (repeatable)', { type: [] })
    .option('--dast-rules <ids>', 'Comma-separated DAST rule IDs for --verify')
    .option('--dast-probe-rate-limit', 'Enable DAST-010 in --verify')
    .option('--dast-agent', 'Correlate --verify with a running IAST agent (sockets in BASESEC_AGENT_DIR); needs the app started with NODE_OPTIONS')
    .option('--dast-timeout <s>', 'Global DAST timeout in seconds for --verify (default: 300)')
    .option('--dast-request-timeout <ms>', 'Per-request DAST timeout for --verify (default: 10000)')
    .option('--dast-rps <n>', 'DAST requests per second for --verify (default: 20)')
    .option('--dast-max-requests <n>', 'DAST request budget for --verify (default: 5000)')
    .option('--dast-evidence-dir <dir>', 'Where --verify writes .http evidence (default: ~/.basesec)')
    .option('--no-dast-evidence', 'Do not write evidence files in --verify')
    .option('--dast-allow-vulnerable-node', 'Run --verify even if Node lacks mandatory security patches')
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

      const emitRoutes = options.emitRoutes === true;
      // cac devuelve un array si la opción se repite: vale la última.
      const rawRoutesOut: unknown = Array.isArray(options.routesOut) ? options.routesOut.at(-1) : options.routesOut;
      const routesOut = typeof rawRoutesOut === 'string' ? rawRoutesOut : undefined;
      const routeError = validateRouteOptions({ emitRoutes, routesOut, ai: options.ai === true });
      if (routeError) {
        printError(routeError);
        process.exit(2);
      }

      // Flags --dast-* y --target: solo válidos con --verify. cac pone evidence=true por defecto (se mira el false).
      const dastFlagValues: Array<[string, unknown]> = [
        ['--target', options.target],
        ['--dast-allow-remote', options.dastAllowRemote === true ? true : undefined],
        ['--dast-header', dastHeaderValues(options).length > 0 ? true : undefined],
        ['--dast-rules', options.dastRules],
        ['--dast-probe-rate-limit', options.dastProbeRateLimit === true ? true : undefined],
        ['--dast-agent', options.dastAgent === true ? true : undefined],
        ['--dast-timeout', options.dastTimeout],
        ['--dast-request-timeout', options.dastRequestTimeout],
        ['--dast-rps', options.dastRps],
        ['--dast-max-requests', options.dastMaxRequests],
        ['--dast-evidence-dir', options.dastEvidenceDir],
        ['--no-dast-evidence', options.dastEvidence === false ? true : undefined],
        ['--dast-allow-vulnerable-node', options.dastAllowVulnerableNode === true ? true : undefined],
      ];
      const dastFlags = dastFlagValues.filter(([, value]) => value !== undefined).map(([flag]) => flag);
      const verify = options.verify === true;
      const target = typeof options.target === 'string' ? options.target : undefined;
      const verifyError = validateVerifyOptions({ verify, target, emitRoutes, ai: options.ai === true, dastFlags });
      if (verifyError) {
        printError(verifyError);
        process.exit(2);
      }
      // cac entrega `true` si un flag con valor va sin él: se rechaza aquí, con un mensaje claro.
      const valueFlags = ['--target', '--dast-rules', '--dast-timeout', '--dast-request-timeout', '--dast-rps', '--dast-max-requests', '--dast-evidence-dir'];
      const missingValue = dastFlagValues.find(([flag, value]) => valueFlags.includes(flag) && value === true);
      if (missingValue) {
        printError(`${missingValue[0]} needs a value`);
        process.exit(2);
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
        emitRoutes,
        routesOut,
        verify,
        target,
        verifyDast: verifyDastOptions(options),
      };

      if (!cliOptions.noBanner && !cliOptions.quiet) {
        printBanner(cliOptions.noColor);
      }

      try {
        const exitCode = cliOptions.verify === true
          ? await runVerify(targetPath, cliOptions)
          : await runScan(targetPath, cliOptions);
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
    .option('--probe-rate-limit', 'Send 30 rapid requests to a login or healthcheck to check rate limiting (DAST-010)')
    .option('--agent', 'Confirm injections with the IAST agent: canaries that reach a real sink (needs routes)')
    .option('--start <cmd>', 'Start the app with the IAST agent injected, wait for --health, and stop it after (implies --agent)')
    .option('--start-timeout <s>', 'Seconds to wait for the app to answer with --start (default: 60)')
    .option('--agent-dir <dir>', 'Directory with the agent sockets, for a manually started app (default: $BASESEC_AGENT_DIR or the tmp dir)')
    .option('--routes <file>', 'Route artifact to test (default: ~/.basesec/routes/<hash>.json)')
    .option('--scan <path>', 'Derive routes from this code path in memory (nothing is written)')
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
          probeRateLimit: options.probeRateLimit === true,
          agent: options.agent === true,
          start: options.start,
          // cac entrega `true` si el flag no lleva valor: se rechaza en el comando (exit 3).
          startTimeout: options.startTimeout === true ? '' : options.startTimeout,
          agentDir: typeof options.agentDir === 'string' ? options.agentDir : undefined,
          // cac entrega `true` si el flag no lleva valor; el comando lo rechaza con exit 3.
          routes: options.routes === undefined ? undefined : typeof options.routes === 'string' ? options.routes : '',
          scan: options.scan === undefined ? undefined : typeof options.scan === 'string' ? options.scan : '',
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
      const dastRules = DAST_CATALOG.filter(matches);
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

      // El título cuenta solo las SAST (ALL_RULES); con --dast, las DAST mostradas.
      const title = options.dast === true ? `basesec rules --dast (${dastRules.length} DAST rules)` : `basesec rules (${sastRules.length} rules)`;
      console.log(pc.bold(`\n  ${title}\n`));

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
          console.log(pc.gray(`      ${rule.note}`));
          console.log(pc.gray(`      Scope: ${rule.scope} | Category: ${rule.category}`));
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
