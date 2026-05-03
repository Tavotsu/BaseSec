export const TAINT_SOURCES = [
  'req.body',
  'req.params',
  'req.query',
  'req.headers',
  'req.cookies',
  'req.files',
  'process.argv',
] as const;

export const TAINT_SOURCE_IDENTIFIERS = [
  'body',
  'params',
  'query',
  'headers',
  'cookies',
  'files',
] as const;

export const SQL_KEYWORDS = [
  'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'WHERE',
  'FROM', 'INTO', 'SET', 'VALUES', 'AND', 'OR',
] as const;

export const DANGEROUS_EXEC_FUNCTIONS = [
  'exec', 'execSync', 'spawn', 'execFile', 'execFileSync',
] as const;

export const SECRET_VAR_PATTERNS = [
  /^(?:API|APP|SECRET|PRIVATE|PUBLIC|ACCESS|AUTH|CLIENT|SERVER|DB|DATABASE|MONGO|REDIS|AWS|GCP|AZURE|STRIPE|GITHUB|GOOGLE|FACEBOOK|TWITTER|MAIL|SMTP|FTP|SSH|ENCRYPT|CIPHER|HMAC)_?(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|CREDENTIAL)$/i,
  /^(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_KEY|APP_KEY|PRIVATE_KEY|ACCESS_TOKEN)$/i,
] as const;

export const SECRET_VALUE_PATTERNS: { pattern: RegExp; name: string }[] = [
  { pattern: /^sk_live_[0-9a-f]{24,}$/i, name: 'Stripe Secret Key' },
  { pattern: /^sk_test_[0-9a-f]{24,}$/i, name: 'Stripe Test Key' },
  { pattern: /^AKIA[0-9A-Z]{16}$/, name: 'AWS Access Key' },
  { pattern: /^ghp_[0-9a-zA-Z]{36}$/, name: 'GitHub Token' },
  { pattern: /^gho_[0-9a-zA-Z]{36}$/, name: 'GitHub OAuth Token' },
  { pattern: /^glpat-[0-9a-zA-Z\-]{20,}$/, name: 'GitLab Token' },
  { pattern: /^[0-9a-f]{32,40}$/, name: 'Possible Hex Secret' },
  { pattern: /^AIza[0-9A-Z\-_]{35}$/, name: 'Google API Key' },
  { pattern: /^mongodb(\+srv)?:\/\/.+:.+@/i, name: 'MongoDB Connection String' },
  { pattern: /^postgres(ql)?:\/\/.+:.+@/i, name: 'PostgreSQL Connection String' },
  { pattern: /^mysql:\/\/.+:.+@/i, name: 'MySQL Connection String' },
  { pattern: /^redis:\/\/.+:.+@/i, name: 'Redis Connection String' },
];

export function isTaintSource(nodeText: string): boolean {
  for (const src of TAINT_SOURCES) {
    if (nodeText.includes(src)) return true;
  }
  return false;
}

export function containsSqlKeywords(text: string): boolean {
  const upper = text.toUpperCase();
  for (const kw of SQL_KEYWORDS) {
    if (upper.includes(kw)) return true;
  }
  return false;
}