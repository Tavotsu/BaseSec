import { describe, it, expect } from 'vitest';
import { runRule } from '../helpers';
import { REACT001 } from '../../src/rules/categories/react/dangerously-set-innerhtml';
import { REACT002 } from '../../src/rules/categories/react/jsx-url-injection';
import { REACT003 } from '../../src/rules/categories/react/ref-innerhtml';
import { NEXT001 } from '../../src/rules/categories/react/next-public-secret';
import { NEXT002 } from '../../src/rules/categories/react/next-redirect';

describe('REACT-001: dangerouslySetInnerHTML', () => {
  it('flags non-literal __html', () => {
    expect(runRule(REACT001, 'const C = () => <div dangerouslySetInnerHTML={{ __html: userHtml }} />;', 'c.tsx').length).toBe(1);
  });
  it('ignores literal __html', () => {
    expect(runRule(REACT001, 'const C = () => <div dangerouslySetInnerHTML={{ __html: "<b>x</b>" }} />;', 'c.tsx')).toHaveLength(0);
  });
});

describe('REACT-002: unvalidated JSX url', () => {
  it('flags dynamic href', () => {
    expect(runRule(REACT002, 'const C = () => <a href={userUrl}>x</a>;', 'c.tsx').length).toBe(1);
  });
  it('ignores static href', () => {
    expect(runRule(REACT002, 'const C = () => <a href="/home">x</a>;', 'c.tsx')).toHaveLength(0);
  });
  it('ignores src on media elements, which cannot run a javascript: URI', () => {
    for (const tag of ['img', 'video', 'audio', 'source', 'track']) {
      expect(runRule(REACT002, `const C = () => <${tag} src={url} />;`, 'c.tsx')).toHaveLength(0);
    }
  });
  it('still flags src on document-loading elements', () => {
    expect(runRule(REACT002, 'const C = () => <iframe src={url} />;', 'c.tsx').length).toBe(1);
    expect(runRule(REACT002, 'const C = () => <script src={url} />;', 'c.tsx').length).toBe(1);
  });
  it('still flags href on a custom component that renders an anchor', () => {
    expect(runRule(REACT002, 'const C = () => <Link href={url}>x</Link>;', 'c.tsx').length).toBe(1);
  });
});

describe('REACT-003: innerHTML via ref', () => {
  it('flags ref.current.innerHTML', () => {
    expect(runRule(REACT003, 'ref.current.innerHTML = userInput;', 'c.tsx').length).toBe(1);
  });
  it('ignores static assignment', () => {
    expect(runRule(REACT003, 'ref.current.innerHTML = "x";', 'c.tsx')).toHaveLength(0);
  });
});

describe('NEXT-001: public env secret', () => {
  it('flags NEXT_PUBLIC_ secret', () => {
    expect(runRule(NEXT001, 'const k = process.env.NEXT_PUBLIC_API_SECRET;', 'c.tsx').length).toBe(1);
  });
  it('ignores non-secret public env', () => {
    expect(runRule(NEXT001, 'const u = process.env.NEXT_PUBLIC_BASE_URL;', 'c.tsx')).toHaveLength(0);
  });
  it('reports an unambiguous secret name as critical/high', () => {
    const [f] = runRule(NEXT001, 'const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;', 'c.tsx');
    expect(f.severity).toBe('critical');
    expect(f.confidence).toBe('high');
  });
  it('ignores vendor keys that are public by design', () => {
    for (const name of [
      'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY',
      'NEXT_PUBLIC_SUPABASE_ANON_KEY',
      'NEXT_PUBLIC_TURNSTILE_SITE_KEY',
      'NEXT_PUBLIC_FIREBASE_API_KEY',
      'NEXT_PUBLIC_POSTHOG_KEY',
      'NEXT_PUBLIC_MAPBOX_TOKEN',
      'NEXT_PUBLIC_SENTRY_DSN',
    ]) {
      expect(runRule(NEXT001, `const k = process.env.${name};`, 'c.tsx')).toHaveLength(0);
    }
  });
  it('downgrades an ambiguous _KEY/TOKEN name to medium/low', () => {
    const [f] = runRule(NEXT001, 'const k = process.env.NEXT_PUBLIC_ADMIN_TOKEN;', 'c.tsx');
    expect(f.severity).toBe('medium');
    expect(f.confidence).toBe('low');
  });
  it('still flags a public-by-design vendor name carrying a strong secret word', () => {
    expect(runRule(NEXT001, 'const k = process.env.NEXT_PUBLIC_FIREBASE_PRIVATE_KEY;', 'c.tsx').length).toBe(1);
  });
});

describe('NEXT-002: redirect open redirect', () => {
  it('flags redirect from searchParams', () => {
    expect(runRule(NEXT002, 'redirect(searchParams.get("next"));', 'c.tsx').length).toBe(1);
  });
  it('ignores static redirect', () => {
    expect(runRule(NEXT002, 'redirect("/home");', 'c.tsx')).toHaveLength(0);
  });
});
