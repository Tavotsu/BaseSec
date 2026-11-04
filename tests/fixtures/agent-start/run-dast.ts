// Ejecuta `runDastCommand` como proceso propio, para simular Ctrl-C (SIGINT) sobre BaseSec.
import { runDastCommand } from '../../../src/cli/commands/dast';

const args = JSON.parse(process.env.BS_RUN_ARGS ?? '{}') as { url: string; options: Parameters<typeof runDastCommand>[1] };
runDastCommand(args.url, args.options).then((code) => process.exit(code));
