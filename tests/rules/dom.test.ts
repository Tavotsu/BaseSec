import { describe, it, expect } from 'vitest';
import { runRule } from '../helpers';
import { DOM001 } from '../../src/rules/categories/dom/innerhtml-assignment';
import { DOM002 } from '../../src/rules/categories/dom/document-write';
import { DOM003 } from '../../src/rules/categories/dom/location-assignment';
import { DOM004 } from '../../src/rules/categories/dom/postmessage-wildcard';
import { DOM005 } from '../../src/rules/categories/dom/message-origin';
import { DOM006 } from '../../src/rules/categories/dom/storage-secrets';
import { DOM007 } from '../../src/rules/categories/dom/eval-network';
import { DOM008 } from '../../src/rules/categories/dom/prototype-pollution';

describe('DOM-001: innerHTML assignment', () => {
  it('flags dynamic innerHTML', () => {
    expect(runRule(DOM001, 'el.innerHTML = userInput;').length).toBe(1);
  });
  it('flags insertAdjacentHTML with dynamic arg', () => {
    expect(runRule(DOM001, 'el.insertAdjacentHTML("beforeend", userInput);').length).toBe(1);
  });
  it('ignores static innerHTML', () => {
    expect(runRule(DOM001, 'el.innerHTML = "<b>hi</b>";')).toHaveLength(0);
  });
});

describe('DOM-002: document.write', () => {
  it('flags dynamic document.write', () => {
    expect(runRule(DOM002, 'document.write(userInput);').length).toBe(1);
  });
  it('ignores static document.write', () => {
    expect(runRule(DOM002, 'document.write("hello");')).toHaveLength(0);
  });
});

describe('DOM-003: open redirect', () => {
  it('flags dynamic location.href', () => {
    expect(runRule(DOM003, 'location.href = userInput;').length).toBe(1);
  });
  it('flags dynamic window.open', () => {
    expect(runRule(DOM003, 'window.open(userInput);').length).toBe(1);
  });
  it('ignores static location.href', () => {
    expect(runRule(DOM003, 'location.href = "/home";')).toHaveLength(0);
  });
});

describe('DOM-004: postMessage wildcard', () => {
  it('flags wildcard targetOrigin', () => {
    expect(runRule(DOM004, 'win.postMessage(data, "*");').length).toBe(1);
  });
  it('ignores explicit targetOrigin', () => {
    expect(runRule(DOM004, 'win.postMessage(data, "https://x.com");')).toHaveLength(0);
  });
});

describe('DOM-005: message listener origin', () => {
  it('flags handler without origin check', () => {
    expect(runRule(DOM005, 'window.addEventListener("message", (e) => { handle(e.data); });').length).toBe(1);
  });
  it('ignores handler that checks origin', () => {
    expect(runRule(DOM005, 'window.addEventListener("message", (e) => { if (e.origin !== "x") return; handle(e.data); });')).toHaveLength(0);
  });
  it('flags a bare addEventListener on the implicit global', () => {
    expect(runRule(DOM005, 'addEventListener("message", (e) => { handle(e.data); });').length).toBe(1);
  });
  it('flags window.onmessage without origin check', () => {
    expect(runRule(DOM005, 'window.onmessage = (e) => handle(e.data);').length).toBe(1);
  });
  it('ignores worker_threads MessagePort listeners', () => {
    expect(runRule(DOM005, 'parentPort.addEventListener("message", (e) => handle(e.data));')).toHaveLength(0);
    expect(runRule(DOM005, 'port.addEventListener("message", (e) => handle(e.data));')).toHaveLength(0);
  });
  it('ignores WebSocket onmessage', () => {
    expect(runRule(DOM005, 'ws.onmessage = (e) => handle(e.data);')).toHaveLength(0);
  });
});

describe('DOM-006: storage secrets', () => {
  it('flags token in localStorage', () => {
    expect(runRule(DOM006, 'localStorage.setItem("token", jwt);').length).toBe(1);
  });
  it('ignores non-sensitive keys', () => {
    expect(runRule(DOM006, 'localStorage.setItem("theme", "dark");')).toHaveLength(0);
  });
  it('does not flag "author" (substring of auth)', () => {
    expect(runRule(DOM006, 'localStorage.setItem("author", name);')).toHaveLength(0);
  });
});

describe('DOM-007: eval with network/URL data', () => {
  it('flags eval of location data in a frontend file', () => {
    expect(runRule(DOM007, 'eval(location.hash);', 'comp.tsx').length).toBe(1);
  });
  it('ignores eval in a backend file', () => {
    expect(runRule(DOM007, 'eval(location.hash);', 'server.ts')).toHaveLength(0);
  });
  it('ignores static eval', () => {
    expect(runRule(DOM007, 'eval("1+1");', 'comp.tsx')).toHaveLength(0);
  });
});

describe('DOM-008: prototype pollution', () => {
  it('flags merge of URL data in a frontend file', () => {
    expect(runRule(DOM008, 'Object.assign(target, parseQuery(location.search));', 'comp.tsx').length).toBe(1);
  });
  it('ignores merge of non-URL data', () => {
    expect(runRule(DOM008, 'Object.assign(a, b);', 'comp.tsx')).toHaveLength(0);
  });
});
