import * as fs from 'node:fs';
import * as path from 'node:path';

const TS_CONFIG = `import { defineConfig } from 'secbase/config';

export default defineConfig({
  target: ['./src'],
  ignore: [
    'test/**',
    'tests/**',
    '**/*.spec.ts',
    '**/*.test.ts',
    'migrations/**',
  ],
  framework: 'auto',
  severity: 'low',
  taintAnalysis: true,
  rules: ['./rules'],
  rulesConfig: {},
  sanitizers: [],
  output: {
    format: 'terminal',
  },
});
`;

const JSON_CONFIG = `{
  "target": ["./src"],
  "ignore": [
    "test/**",
    "tests/**",
    "**/*.spec.ts",
    "**/*.test.ts",
    "migrations/**"
  ],
  "framework": "auto",
  "severity": "low",
  "taintAnalysis": true,
  "rules": ["./rules"],
  "rulesConfig": {},
  "sanitizers": [],
  "output": {
    "format": "terminal"
  }
}
`;

export async function runInit(format: string): Promise<void> {
  const fileName =
    format === 'json' ? 'secbase.config.json' : 'secbase.config.ts';
  const content = format === 'json' ? JSON_CONFIG : TS_CONFIG;

  const filePath = path.resolve(process.cwd(), fileName);

  if (fs.existsSync(filePath)) {
    console.log(`  Config file already exists: ${filePath}`);
    return;
  }

  fs.writeFileSync(filePath, content, 'utf-8');
  console.log(`  Created ${fileName}`);
}