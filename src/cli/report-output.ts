import * as fs from 'node:fs';
import * as path from 'node:path';
import prompts from 'prompts';
import type { OutputFormat } from '../rules/types';
import { getDefaultReportPath } from '../utils/basesec-dir';

const TERMINAL_FORMATS = ['terminal'];

/**
 * Escribe un informe como lo hace `scan`: a `outputPath` (con confirmación si queda fuera del cwd),
 * a la ruta por defecto para formatos no terminal, o a stdout. Devuelve false si el usuario canceló.
 */
export async function emitReport(output: string, format: OutputFormat, outputPath?: string): Promise<boolean> {
  if (outputPath) {
    const resolvedOutput = path.resolve(outputPath);
    const cwd = process.cwd();

    if (!resolvedOutput.startsWith(cwd)) {
      const response = await prompts({
        type: 'confirm',
        name: 'value',
        message: `The output is configured to be generated outside the default path: ${resolvedOutput}, Are you sure you want to continue? (yes/no)`,
        initial: false
      });

      if (!response.value) {
        console.log('Operation cancelled by user.');
        return false;
      }
    }

    const dir = path.dirname(resolvedOutput);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(resolvedOutput, output, 'utf-8');
    console.log(`Report written to ${resolvedOutput}`);
  } else if (!TERMINAL_FORMATS.includes(format)) {
    const defaultPath = getDefaultReportPath(format);
    fs.writeFileSync(defaultPath, output, 'utf-8');
    console.log(`Report written to ${defaultPath}`);
  } else {
    console.log(output);
  }
  return true;
}
