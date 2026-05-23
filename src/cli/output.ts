import pc from 'picocolors';

const BANNER = `
    ____                 _____
   / __ )____ _________ / ___/___  _____
  / __  / __ \`/ ___/ _ \\\\__ \\/ _ \\/ ___/
 / /_/ / /_/ (__  )  __/__/ /  __/ /
/_____/\\__,_/____/\\___/____/\\___/\\___/
`;

export function printBanner(noColor: boolean = false): void {
  if (noColor) {
    console.log(BANNER);
    return;
  }

  const gradient: ((s: string) => string)[] = [
    (s: string) => `\x1b[38;2;0;255;255m${s}\x1b[0m`,  // cyan bright
    (s: string) => `\x1b[38;2;0;200;200m${s}\x1b[0m`,  // cyan
    (s: string) => `\x1b[38;2;0;100;255m${s}\x1b[0m`,  // blue
    (s: string) => `\x1b[38;2;0;200;100m${s}\x1b[0m`,  // green
  ];

  const lines = BANNER.split('\n').filter((l) => l.length > 0);
const colored = lines
      .map((line, i) => {
        const colorFn = gradient[i % gradient.length];
        return colorFn(line);
      })
      .join('\n');

  console.log(colored);
  console.log();
}

export function printVersion(): void {
  console.log(pc.cyan('basesec v0.1.0'));
}

export function printError(message: string): void {
  console.error(pc.red(`  Error: ${message}`));
}