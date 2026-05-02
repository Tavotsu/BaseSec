import { cac } from 'cac';
import { printBanner, printVersion, printError } from './output';
import { runScan } from './commands/scan';
import { runInit } from './commands/init';
import type { CliOptions, OutputFormat, Severity } from '../rules/types';

export async function main(): Promise<void> {
  const cli = cac('secbase');

  cli
    .version('0.1.0')
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
    .option('--framework <fw>', 'Force framework: express|nestjs|auto', { default: 'auto' })
    .option('--no-color', 'Disable colored output')
    .option('--no-banner', 'Disable banner')
    .action(async (path: string | undefined, options: any) => {
      const targetPath = path || process.cwd();

      const rawIgnore: string[] = Array.isArray(options.ignore)
        ? options.ignore.filter((v: any) => v !== null && v !== undefined)
        : [];

      const cliOptions: CliOptions = {
        format: (options.format ?? 'terminal') as OutputFormat,
        output: options.output,
        severity: (options.severity ?? 'low') as Severity,
        rules: options.rules,
        ignore: rawIgnore,
        config: options.config,
        noTaint: options.taint === false,
        quiet: options.quiet ?? false,
        strict: options.strict ?? false,
        framework: (options.framework ?? 'auto') as 'auto' | 'express' | 'nestjs',
        noColor: options.color === false,
        noBanner: options.banner === false,
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
    .command('init', 'Initialize a secbase config file')
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
    .action((_options: any) => {
      printBanner(false);
      console.log('No rules registered yet.');
      console.log('Rules will be available in Phase 2.');
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