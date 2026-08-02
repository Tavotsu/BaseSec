import { describe, it, expect } from 'vitest';
import { runRule } from '../helpers';
import { SVELTE001 } from '../../src/rules/categories/svelte/html-tag';

describe('SVELTE-001: {@html}', () => {
  it('flags dynamic {@html}', () => {
    expect(runRule(SVELTE001, '<div>{@html userHtml}</div>').length).toBe(1);
  });
  it('ignores static {@html}', () => {
    expect(runRule(SVELTE001, "<div>{@html '<b>x</b>'}</div>")).toHaveLength(0);
  });
  it('ignores templates without {@html}', () => {
    expect(runRule(SVELTE001, '<p>{text}</p>')).toHaveLength(0);
  });
});
