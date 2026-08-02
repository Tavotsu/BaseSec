import { describe, it, expect } from 'vitest';
import { runRule } from '../helpers';
import { VUE001 } from '../../src/rules/categories/vue/v-html';
import { VUE002 } from '../../src/rules/categories/vue/v-bind-url';
import { VUE003 } from '../../src/rules/categories/vue/render-innerhtml';

describe('VUE-001: v-html', () => {
  it('flags v-html binding', () => {
    expect(runRule(VUE001, '<template><div v-html="userHtml"></div></template>').length).toBe(1);
  });
  it('ignores templates without v-html', () => {
    expect(runRule(VUE001, '<template><div>{{ text }}</div></template>')).toHaveLength(0);
  });
  it('ignores a v-html bound to a string constant', () => {
    expect(runRule(VUE001, `<template><div v-html="'<b>hi</b>'"></div></template>`)).toHaveLength(0);
  });
  it('reports the real file line in a full SFC', () => {
    const vue = '<script>\nconst a = 1;\n</script>\n<template>\n  <div v-html="bio"></div>\n</template>';
    const f = runRule(VUE001, vue, 'c.vue');
    expect(f).toHaveLength(1);
    expect(f[0].line).toBe(5);
  });
});

describe('VUE-002: unvalidated :href/:src', () => {
  it('flags user-derived :href', () => {
    expect(runRule(VUE002, '<template><a :href="route.query.next">x</a></template>').length).toBe(1);
  });
  it('ignores static-ish :href without user hint', () => {
    expect(runRule(VUE002, "<template><a :href=\"localPath\">x</a></template>")).toHaveLength(0);
  });
});

describe('VUE-003: innerHTML in render function', () => {
  it('flags innerHTML prop in h()', () => {
    expect(runRule(VUE003, 'render() { return h("div", { innerHTML: userHtml }); }').length).toBe(1);
  });
  it('ignores literal innerHTML', () => {
    expect(runRule(VUE003, 'render() { return h("div", { innerHTML: "<b>x</b>" }); }')).toHaveLength(0);
  });
});
