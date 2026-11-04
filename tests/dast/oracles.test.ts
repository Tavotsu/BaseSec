import { describe, it, expect } from 'vitest';
import { reflectionOracle, signatureOracle } from '../../src/dast/oracles/reflection';
import { sqlErrorOracle } from '../../src/dast/oracles/sql-error';
import { timingOracle } from '../../src/dast/oracles/timing';
import { diffOracle } from '../../src/dast/oracles/diff';
import { redirectOracle } from '../../src/dast/oracles/redirect';
import type { HttpResponse } from '../../src/dast/types';

const CANARY = 'BS1a2b3c4d';
const HTML = { 'content-type': 'text/html; charset=utf-8' };

function res(overrides: Partial<HttpResponse> = {}): HttpResponse {
  return {
    status: 200,
    headers: {},
    body: '',
    contentEncoding: null,
    bodyDecoded: true,
    url: 'http://127.0.0.1:3000/search?q=x',
    redirects: [],
    timedOut: false,
    elapsedMs: 5,
    ...overrides,
  };
}

function input(attack: Partial<HttpResponse>, baseline: Partial<HttpResponse> = {}, payloadText = `"<img src=x onerror=alert(${CANARY})`) {
  return {
    baseline: res(baseline),
    attack: res(attack),
    canary: CANARY,
    payloadText,
  };
}

describe('reflectionOracle (xss)', () => {
  it('detects a raw, unescaped canary in an HTML response', () => {
    const payloadText = `"<img src=x onerror=alert(${CANARY})`;
    const result = reflectionOracle(input({ headers: HTML, body: `<p>${payloadText}</p>` }, {}, payloadText), 'xss');
    expect(result.detected).toBe(true);
    expect(result.confidence).toBe('medium');
  });

  it('does not detect a canary that is HTML-escaped', () => {
    const payloadText = `"<img src=x onerror=alert(${CANARY})`;
    const escaped = `&quot;&lt;img src=x onerror=alert(${CANARY})`;
    const result = reflectionOracle(input({ headers: HTML, body: `<p>${escaped}</p>` }, {}, payloadText), 'xss');
    expect(result.detected).toBe(false);
  });

  it('does not detect when the response is not HTML', () => {
    const payloadText = `"<img src=x onerror=alert(${CANARY})`;
    const result = reflectionOracle(
      input({ headers: { 'content-type': 'application/json' }, body: `{"q":"${payloadText}"}` }, {}, payloadText),
      'xss',
    );
    expect(result.detected).toBe(false);
  });

  it('does not detect when the canary is absent', () => {
    expect(reflectionOracle(input({ headers: HTML, body: '<p>nothing</p>' }), 'xss').detected).toBe(false);
  });
});

describe('reflectionOracle (echo, command output)', () => {
  it('detects the canary without requiring HTML', () => {
    const result = reflectionOracle(
      input({ headers: { 'content-type': 'text/plain' }, body: `output ${CANARY}\n` }, {}, `; echo ${CANARY}`),
      'echo',
    );
    expect(result.detected).toBe(true);
    expect(result.confidence).toBe('medium');
  });

  it('does not count an echo of the payload itself as command output', () => {
    const payloadText = `; echo ${CANARY}`;
    const result = reflectionOracle(input({ body: `you sent: ${payloadText}` }, {}, payloadText), 'echo');
    expect(result.detected).toBe(false);
  });
});

describe('signatureOracle (path traversal)', () => {
  it('detects a passwd signature present in the attack and absent from the baseline', () => {
    const result = signatureOracle(input({ body: 'root:x:0:0:root:/root:/bin/bash\n' }, { body: '{"ok":true}' }));
    expect(result.detected).toBe(true);
    expect(result.confidence).toBe('high');
  });

  it('detects a win.ini signature', () => {
    expect(signatureOracle(input({ body: '[fonts]\n[extensions]' }, { body: '' })).detected).toBe(true);
  });

  it('does not detect a signature that the baseline already contained', () => {
    const result = signatureOracle(input({ body: 'root:x:0:0:' }, { body: 'root:x:0:0:' }));
    expect(result.detected).toBe(false);
  });
});

describe('sqlErrorOracle', () => {
  it('detects a driver signature present only in the attack', () => {
    const result = sqlErrorOracle(input({ status: 500, body: 'syntax error at or near "\'"' }, { body: 'ok' }));
    expect(result.detected).toBe(true);
    expect(result.confidence).toBe('medium');
  });

  it('does not detect a signature the baseline already contained', () => {
    const result = sqlErrorOracle(input({ body: 'syntax error at or near "x"' }, { body: 'syntax error at or near "x"' }));
    expect(result.detected).toBe(false);
  });

  it('treats the mongo family as a low-confidence NoSQL signal only', () => {
    const attack = input({ status: 500, body: 'MongoServerError: bad operator' }, { body: 'ok' });
    expect(sqlErrorOracle(attack).detected).toBe(false);
    const mongo = sqlErrorOracle(attack, 'mongo');
    expect(mongo.detected).toBe(true);
    expect(mongo.confidence).toBe('low');
  });
});

describe('timingOracle', () => {
  const slow = (ms: number) => res({ elapsedMs: ms });

  it('detects a slow attack with a fast control', () => {
    const result = timingOracle({
      ...input({ elapsedMs: 1050 }, { elapsedMs: 5 }),
      control: res({ elapsedMs: 6 }),
      delaySeconds: 1,
    });
    expect(result.detected).toBe(true);
    expect(result.confidence).toBe('medium');
  });

  it('does not detect when the control is slow too (slow server)', () => {
    const result = timingOracle({
      ...input({ elapsedMs: 1050 }, { elapsedMs: 5 }),
      control: slow(1040),
      delaySeconds: 1,
    });
    expect(result.detected).toBe(false);
  });

  it('does not detect when the attack is not slower than the baseline', () => {
    const result = timingOracle({
      ...input({ elapsedMs: 20 }, { elapsedMs: 5 }),
      control: res({ elapsedMs: 6 }),
      delaySeconds: 2,
    });
    expect(result.detected).toBe(false);
  });

  it('never reports more than medium confidence', () => {
    const result = timingOracle({
      ...input({ elapsedMs: 5000 }, { elapsedMs: 5 }),
      control: res({ elapsedMs: 5 }),
      delaySeconds: 2,
    });
    expect(result.confidence).not.toBe('high');
    expect(result.confidence).toBe('medium');
  });
});

describe('diffOracle', () => {
  const benign = { body: 'x'.repeat(100) };

  it('detects a stable change in length against baseline and neutral', () => {
    const big = { body: 'y'.repeat(400) };
    const result = diffOracle({
      ...input(big, benign),
      attack2: res(big),
      neutral: res({ body: 'x'.repeat(100) }),
    });
    expect(result.detected).toBe(true);
    expect(result.confidence).toBe('low');
  });

  it('does not detect when the two attacks differ (unstable)', () => {
    const result = diffOracle({
      ...input({ body: 'y'.repeat(400) }, benign),
      attack2: res({ body: 'y'.repeat(10) }),
      neutral: res(benign),
    });
    expect(result.detected).toBe(false);
  });

  it('does not detect a change inside the natural variation of the page', () => {
    // baseline 100, neutral 130: variación natural 30, tolerancia 60. El ataque (150) cae dentro.
    const result = diffOracle({
      ...input({ body: 'z'.repeat(150) }, benign),
      attack2: res({ body: 'z'.repeat(150) }),
      neutral: res({ body: 'x'.repeat(130) }),
    });
    expect(result.detected).toBe(false);
  });
});

describe('redirectOracle', () => {
  const location = (value: string, status = 302) => res({ status, url: 'http://127.0.0.1:3000/go?url=x', headers: { location: value } });

  it('detects a location to another host that contains the canary', () => {
    const result = redirectOracle({
      baseline: res(),
      attack: location(`https://bs-${CANARY.toLowerCase()}.example.net`),
      canary: CANARY,
      payloadText: '',
    });
    expect(result.detected).toBe(true);
    expect(result.confidence).toBe('medium');
  });

  it('does not detect a location to the same host', () => {
    const result = redirectOracle({
      baseline: res(),
      attack: location(`http://127.0.0.1:3000/${CANARY}`),
      canary: CANARY,
      payloadText: '',
    });
    expect(result.detected).toBe(false);
  });

  it('does not detect a redirect without the canary', () => {
    const result = redirectOracle({
      baseline: res(),
      attack: location('https://login.example.net/sso'),
      canary: CANARY,
      payloadText: '',
    });
    expect(result.detected).toBe(false);
  });
});

describe('oracle precision (realistic false positives)', () => {
  const XSS_PAYLOAD = `"<img src=x onerror=alert(${CANARY})`;
  const xss = (body: string, headers: Record<string, string> = HTML) =>
    reflectionOracle(input({ headers, body }, {}, XSS_PAYLOAD), 'xss');

  describe('reflection (xss)', () => {
    it('does not fire on a value reflected inside an already escaped attribute', () => {
      const escaped = `&quot;&lt;img src=x onerror=alert(${CANARY})`;
      expect(xss(`<input value="${escaped}">`).detected).toBe(false);
    });

    it('does not fire when the page strips the angle bracket and leaves the canary loose', () => {
      expect(xss(`<p>"img src=x onerror=alert(${CANARY})</p>`).detected).toBe(false);
    });

    it('does not fire when the tag arrives percent-encoded', () => {
      expect(xss(`<p>%3Cimg src=x onerror=alert(${CANARY})</p>`).detected).toBe(false);
    });

    it('does not fire on a JSON response even if the payload is reflected verbatim', () => {
      expect(xss(`{"q":"${XSS_PAYLOAD}"}`, { 'content-type': 'application/json; charset=utf-8' }).detected).toBe(false);
    });

    it('does not fire when the response declares no content type', () => {
      expect(xss(`<p>${XSS_PAYLOAD}</p>`, {}).detected).toBe(false);
    });

    it('still fires when only the quote is escaped and the tag arrives intact', () => {
      expect(xss(`<p>&quot;<img src=x onerror=alert(${CANARY})</p>`).detected).toBe(true);
    });

    it('still fires when one reflection is escaped and another is raw', () => {
      const body = `<input value="&quot;&lt;img src=x onerror=alert(${CANARY})"><p>${XSS_PAYLOAD}</p>`;
      expect(xss(body).detected).toBe(true);
    });
  });

  describe('reflection (echo)', () => {
    const echo = (body: string) =>
      reflectionOracle(input({ headers: { 'content-type': 'text/plain' }, body }, {}, `; echo ${CANARY}`), 'echo');

    it('does not fire when the page repeats the payload with the shell characters removed', () => {
      expect(echo(`you searched for: echo ${CANARY}`).detected).toBe(false);
      expect(echo(`you searched for: echo&nbsp;${CANARY}`).detected).toBe(false);
      expect(echo(`you searched for: echo%20${CANARY}`).detected).toBe(false);
      expect(echo(`you searched for: echo "${CANARY}"`).detected).toBe(false);
    });

    it('fires when the output appears next to an echo of the payload', () => {
      expect(echo(`you sent: ; echo ${CANARY}\nresult:\n${CANARY}\n`).detected).toBe(true);
    });
  });

  describe('signature (path traversal)', () => {
    it('needs more than a lone [fonts] section to call it win.ini', () => {
      expect(signatureOracle(input({ body: 'config: [fonts] are listed here' }, { body: '' })).detected).toBe(false);
      expect(signatureOracle(input({ body: '; for 16-bit app support\n[fonts]' }, { body: '' })).detected).toBe(true);
    });

    it('does not fire when part of the win.ini signature is already in the baseline', () => {
      const body = '[fonts]\n[extensions]';
      expect(signatureOracle(input({ body }, { body: '[fonts]' })).detected).toBe(false);
    });
  });

  describe('sql-error', () => {
    it('does not treat a JSON parser complaint as a SQLite error', () => {
      const body = "Unrecognized token 'abc': was expecting (JSON String, Number, Array, Object or token 'null', 'true' or 'false')";
      expect(sqlErrorOracle(input({ status: 400, body }, { body: 'ok' })).detected).toBe(false);
    });

    it('detects the SQLite tokenizer error', () => {
      const body = 'SQLITE_ERROR: unrecognized token: "\'"';
      expect(sqlErrorOracle(input({ status: 500, body }, { body: 'ok' })).detected).toBe(true);
    });

    it('does not fire on a help page that always mentions the signature', () => {
      const body = '<p>A syntax error at or near a quote means the query is malformed.</p>';
      expect(sqlErrorOracle(input({ body }, { body })).detected).toBe(false);
    });
  });

  describe('timing', () => {
    it('requires the attack to be slower than the control, not only than the baseline', () => {
      // baseline rápida, control a medio camino, ataque algo más lento: ninguna diferencia llega al 80 % del delay.
      const result = timingOracle({
        ...input({ elapsedMs: 1700 }, { elapsedMs: 0 }),
        control: res({ elapsedMs: 1000 }),
        delaySeconds: 2,
      });
      expect(result.detected).toBe(false);
    });

    it('does not fire when a response did not complete', () => {
      const result = timingOracle({
        ...input({ elapsedMs: 5000, timedOut: true, status: 0 }, { elapsedMs: 5 }),
        control: res({ elapsedMs: 5 }),
        delaySeconds: 2,
      });
      expect(result.detected).toBe(false);
    });
  });

  describe('diff (NoSQLi)', () => {
    const json = (length: number) => ({ body: 'x'.repeat(length) });

    it('does not fire when the operator only makes the endpoint fail (4xx or 5xx)', () => {
      for (const status of [400, 422, 500]) {
        const result = diffOracle({
          ...input({ status, body: 'TypeError: role.trim is not a function' }, json(100)),
          attack2: res({ status, body: 'TypeError: role.trim is not a function' }),
          neutral: res(json(100)),
        });
        expect(result.detected, String(status)).toBe(false);
      }
    });

    it('fires when the operator turns a not-found into a stable success', () => {
      const notFound = { status: 404, body: 'not found' };
      const result = diffOracle({
        ...input({ status: 200, body: '[{"id":1}]' }, notFound),
        attack2: res({ status: 200, body: '[{"id":1}]' }),
        neutral: res(notFound),
      });
      expect(result.detected).toBe(true);
      expect(result.confidence).toBe('low');
    });

    it('does not fire when the status change does not repeat', () => {
      const notFound = { status: 404, body: 'not found' };
      const result = diffOracle({
        ...input({ status: 200, body: '[{"id":1}]' }, notFound),
        attack2: res(notFound),
        neutral: res(notFound),
      });
      expect(result.detected).toBe(false);
    });

    it('does not fire when the response shrinks', () => {
      const result = diffOracle({
        ...input(json(5), json(400)),
        attack2: res(json(5)),
        neutral: res(json(400)),
      });
      expect(result.detected).toBe(false);
    });

    it('does not fire on a small growth that a parameter echo explains', () => {
      const baseline = { body: '{"role":"bs11111111"}' };
      const echoed = { body: `{"role":{"$ne":"${CANARY}"}}` };
      const result = diffOracle({
        ...input(echoed, baseline),
        attack2: res(echoed),
        neutral: res({ body: '{"role":"bs22222222"}' }),
        reflected: ['bs11111111', 'bs22222222'],
      });
      expect(result.detected).toBe(false);
    });

    it('does not fire on a growth below the minimum, even with zero natural variation', () => {
      const result = diffOracle({
        ...input(json(120), json(100)),
        attack2: res(json(120)),
        neutral: res(json(100)),
      });
      expect(result.detected).toBe(false);
    });

    it('uses a third benign sample to measure natural variation', () => {
      const attack = json(450);
      const base = {
        ...input(attack, json(100)),
        attack2: res(attack),
        neutral: res(json(100)),
      };
      // Con dos muestras benignas iguales la tolerancia es 0 y el crecimiento parece una inyección...
      expect(diffOracle(base).detected).toBe(true);
      // ...pero una tercera muestra benigna de 500 bytes prueba que la página varía por naturaleza.
      expect(diffOracle({ ...base, neutral2: res(json(500)) }).detected).toBe(false);
    });
  });

  describe('redirect', () => {
    it('does not fire when the canary only travels in the query of a redirect to a third-party login', () => {
      const attack = res({
        status: 302,
        url: 'http://127.0.0.1:3000/login?next=x',
        headers: { location: `https://sso.example.org/login?return=https%3A%2F%2Fbs-${CANARY}.example.net` },
      });
      expect(redirectOracle({ baseline: res(), attack, canary: CANARY, payloadText: '' }).detected).toBe(false);
    });

    it('fires on a protocol-relative redirect whose host carries the canary', () => {
      const attack = res({
        status: 302,
        url: 'http://127.0.0.1:3000/go?url=x',
        headers: { location: `//bs-${CANARY}.example.net` },
      });
      expect(redirectOracle({ baseline: res(), attack, canary: CANARY, payloadText: '' }).detected).toBe(true);
    });
  });

  describe('hostile bodies', () => {
    it('scans a multi-megabyte body in linear time, and only up to the scan cap', () => {
      const big = '<'.repeat(4_000_000);
      const late = `${'a'.repeat(2_000_000)}root:x:0:0: syntax error at or near ${CANARY}`;
      const started = Date.now();
      reflectionOracle(input({ headers: HTML, body: big }), 'xss');
      reflectionOracle(input({ body: big }, {}, `; echo ${CANARY}`), 'echo');
      signatureOracle(input({ body: big }, { body: big }));
      sqlErrorOracle(input({ body: big }, { body: big }));
      diffOracle({ ...input({ body: big }, { body: 'x' }), attack2: res({ body: big }), neutral: res({ body: 'x' }) });
      expect(Date.now() - started).toBeLessThan(2000);
      // Pasado el tope no se busca: ni la firma ni el canario enterrados al final cuentan.
      expect(signatureOracle(input({ body: late }, { body: '' })).detected).toBe(false);
      expect(sqlErrorOracle(input({ body: late }, { body: '' })).detected).toBe(false);
    });
  });
});
