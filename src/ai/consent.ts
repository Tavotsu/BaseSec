import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as readline from 'node:readline';

const CONSENT_VERSION = '1.0';

interface ConsentRecord {
  accepted: boolean;
  version: string;
  timestamp: string;
}

export function getConsentPath(): string {
  return path.join(os.homedir(), '.basesec', 'ai-consent');
}

export function checkConsent(): boolean {
  const consentPath = getConsentPath();
  if (!fs.existsSync(consentPath)) return false;
  try {
    const raw = fs.readFileSync(consentPath, 'utf-8');
    const record: ConsentRecord = JSON.parse(raw);
    return record.accepted === true && record.version === CONSENT_VERSION;
  } catch {
    return false;
  }
}

export function saveConsent(): void {
  const consentPath = getConsentPath();
  const dir = path.dirname(consentPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  const record: ConsentRecord = {
    accepted: true,
    version: CONSENT_VERSION,
    timestamp: new Date().toISOString(),
  };
  fs.writeFileSync(consentPath, JSON.stringify(record, null, 2), { encoding: 'utf-8', mode: 0o600 });
}

export function revokeConsent(): void {
  const consentPath = getConsentPath();
  if (fs.existsSync(consentPath)) {
    fs.unlinkSync(consentPath);
  }
}

export async function promptConsent(provider: string, contextLevel: string): Promise<boolean> {
  const border = '─'.repeat(65);
  const lines = [
    `┌${border}┐`,
    `│            BaseSec AI Enhancement — Privacy Notice              │`,
    `│                                                                 │`,
    `│  You are about to enable AI-powered analysis.                   │`,
    `│  This feature will send code snippets from your project to      │`,
    `│  an external LLM provider.                                      │`,
    `│                                                                 │`,
    `│  Provider: ${provider.padEnd(53)}│`,
    `│  Context level: ${contextLevel.padEnd(48)}│`,
    `│                                                                 │`,
    `│  BaseSec does NOT store any data sent to LLM providers.         │`,
    `│  However, BaseSec is NOT responsible for the privacy policy,    │`,
    `│  data retention, or telemetry of third-party LLM providers.     │`,
    `│                                                                 │`,
    `│  By accepting, you acknowledge that the use of external LLM     │`,
    `│  services is entirely your responsibility.                      │`,
    `│                                                                 │`,
    `└${border}┘`,
  ];

  for (const line of lines) {
    console.log(line);
  }

  if (!process.stdin.isTTY) {
    console.error('[basesec] AI consent required but stdin is not interactive. Run interactively to accept.');
    return false;
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise<boolean>((resolve) => {
    rl.question('  Do you accept? (yes/no): ', (answer) => {
      rl.close();
      const accepted = answer.trim().toLowerCase() === 'yes';
      if (accepted) {
        saveConsent();
      }
      resolve(accepted);
    });
  });
}
