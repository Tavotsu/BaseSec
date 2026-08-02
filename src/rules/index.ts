import type { Rule } from './types';

export { SQLI001 } from './categories/sql-injection/string-concat';
export { SQLI002 } from './categories/sql-injection/template-literal';
export { SQLI003 } from './categories/sql-injection/raw-query';
export { SQLI004 } from './categories/sql-injection/knex-raw';

export { NOSQL001 } from './categories/nosql-injection/mongo-where';
export { NOSQL002 } from './categories/nosql-injection/mongo-query-inject';
export { NOSQL003 } from './categories/nosql-injection/mongoose-lean';

export { XSS001 } from './categories/xss/res-send-unsafe';
export { XSS002 } from './categories/xss/missing-helmet';
export { XSS003 } from './categories/xss/unsafe-headers';
export { XSS004 } from './categories/xss/open-redirect';

export { CMDI001 } from './categories/command-injection/child-process';
export { CMDI002 } from './categories/command-injection/eval-usage';
export { CMDI003 } from './categories/command-injection/settimeout-string';

export { PATH001 } from './categories/path-traversal/fs-user-path';
export { PATH002 } from './categories/path-traversal/static-traversal';

export { AUTH001 } from './categories/auth/missing-auth-guard';
export { AUTH002 } from './categories/auth/weak-jwt-secret';
export { AUTH003 } from './categories/auth/cors-misconfig';
export { AUTH004 } from './categories/auth/missing-rate-limit';

export { SEC001 } from './categories/secrets/hardcoded-api-keys';
export { SEC002 } from './categories/secrets/hardcoded-passwords';
export { SEC003 } from './categories/secrets/hardcoded-crypto-keys';

export { ERR001 } from './categories/error-handling/exposed-stack';
export { ERR002 } from './categories/error-handling/catch-all';
export { ERR003 } from './categories/error-handling/unhandled-rejection';

export { CONF001 } from './categories/misconfiguration/missing-csp';
export { CONF002 } from './categories/misconfiguration/debug-mode';
export { CONF003 } from './categories/misconfiguration/insecure-cookies';
export { CONF004 } from './categories/misconfiguration/unlimited-body-parser';

export { DEP001 } from './categories/dependency-check/outdated-deps';
export { DEP002 } from './categories/dependency-check/vulnerable-deps';
export { DEP003 } from './categories/dependency-check/unused-deps';
export { DEP004 } from './categories/dependency-check/lockfile-mismatch';

export { FASTIFY001 } from './categories/fastify/missing-rate-limit';
export { FASTIFY002 } from './categories/fastify/missing-helmet';
export { FASTIFY003 } from './categories/fastify/missing-cors';

export { KOA001 } from './categories/koa/missing-helmet';
export { KOA002 } from './categories/koa/missing-cors';
export { KOA003 } from './categories/koa/unsafe-ctx-body';

export { PRISMA001 } from './categories/prisma/raw-query-injection';
export { PRISMA002 } from './categories/prisma/unsafe-raw-query';

export { DOM001 } from './categories/dom/innerhtml-assignment';
export { DOM002 } from './categories/dom/document-write';
export { DOM003 } from './categories/dom/location-assignment';
export { DOM004 } from './categories/dom/postmessage-wildcard';
export { DOM005 } from './categories/dom/message-origin';
export { DOM006 } from './categories/dom/storage-secrets';
export { DOM007 } from './categories/dom/eval-network';
export { DOM008 } from './categories/dom/prototype-pollution';

export { REACT001 } from './categories/react/dangerously-set-innerhtml';
export { REACT002 } from './categories/react/jsx-url-injection';
export { REACT003 } from './categories/react/ref-innerhtml';
export { NEXT001 } from './categories/react/next-public-secret';
export { NEXT002 } from './categories/react/next-redirect';

export { VUE001 } from './categories/vue/v-html';
export { VUE002 } from './categories/vue/v-bind-url';
export { VUE003 } from './categories/vue/render-innerhtml';

export { NG001 } from './categories/angular/bypass-security-trust';
export { NG002 } from './categories/angular/native-innerhtml';
export { NG003 } from './categories/angular/binding-innerhtml';
export { NG004 } from './categories/angular/jsonp-injection';
export { NG005 } from './categories/angular/navigate-open-redirect';
export { NG006 } from './categories/angular/unguarded-route';

export { SVELTE001 } from './categories/svelte/html-tag';

import { SQLI001 } from './categories/sql-injection/string-concat';
import { SQLI002 } from './categories/sql-injection/template-literal';
import { SQLI003 } from './categories/sql-injection/raw-query';
import { SQLI004 } from './categories/sql-injection/knex-raw';

import { NOSQL001 } from './categories/nosql-injection/mongo-where';
import { NOSQL002 } from './categories/nosql-injection/mongo-query-inject';
import { NOSQL003 } from './categories/nosql-injection/mongoose-lean';

import { XSS001 } from './categories/xss/res-send-unsafe';
import { XSS002 } from './categories/xss/missing-helmet';
import { XSS003 } from './categories/xss/unsafe-headers';
import { XSS004 } from './categories/xss/open-redirect';

import { CMDI001 } from './categories/command-injection/child-process';
import { CMDI002 } from './categories/command-injection/eval-usage';
import { CMDI003 } from './categories/command-injection/settimeout-string';

import { PATH001 } from './categories/path-traversal/fs-user-path';
import { PATH002 } from './categories/path-traversal/static-traversal';

import { AUTH001 } from './categories/auth/missing-auth-guard';
import { AUTH002 } from './categories/auth/weak-jwt-secret';
import { AUTH003 } from './categories/auth/cors-misconfig';
import { AUTH004 } from './categories/auth/missing-rate-limit';

import { SEC001 } from './categories/secrets/hardcoded-api-keys';
import { SEC002 } from './categories/secrets/hardcoded-passwords';
import { SEC003 } from './categories/secrets/hardcoded-crypto-keys';

import { ERR001 } from './categories/error-handling/exposed-stack';
import { ERR002 } from './categories/error-handling/catch-all';
import { ERR003 } from './categories/error-handling/unhandled-rejection';

import { CONF001 } from './categories/misconfiguration/missing-csp';
import { CONF002 } from './categories/misconfiguration/debug-mode';
import { CONF003 } from './categories/misconfiguration/insecure-cookies';
import { CONF004 } from './categories/misconfiguration/unlimited-body-parser';

import { DEP001 } from './categories/dependency-check/outdated-deps';
import { DEP002 } from './categories/dependency-check/vulnerable-deps';
import { DEP003 } from './categories/dependency-check/unused-deps';
import { DEP004 } from './categories/dependency-check/lockfile-mismatch';

import { FASTIFY001 } from './categories/fastify/missing-rate-limit';
import { FASTIFY002 } from './categories/fastify/missing-helmet';
import { FASTIFY003 } from './categories/fastify/missing-cors';

import { KOA001 } from './categories/koa/missing-helmet';
import { KOA002 } from './categories/koa/missing-cors';
import { KOA003 } from './categories/koa/unsafe-ctx-body';

import { PRISMA001 } from './categories/prisma/raw-query-injection';
import { PRISMA002 } from './categories/prisma/unsafe-raw-query';

import { DOM001 } from './categories/dom/innerhtml-assignment';
import { DOM002 } from './categories/dom/document-write';
import { DOM003 } from './categories/dom/location-assignment';
import { DOM004 } from './categories/dom/postmessage-wildcard';
import { DOM005 } from './categories/dom/message-origin';
import { DOM006 } from './categories/dom/storage-secrets';
import { DOM007 } from './categories/dom/eval-network';
import { DOM008 } from './categories/dom/prototype-pollution';

import { REACT001 } from './categories/react/dangerously-set-innerhtml';
import { REACT002 } from './categories/react/jsx-url-injection';
import { REACT003 } from './categories/react/ref-innerhtml';
import { NEXT001 } from './categories/react/next-public-secret';
import { NEXT002 } from './categories/react/next-redirect';

import { VUE001 } from './categories/vue/v-html';
import { VUE002 } from './categories/vue/v-bind-url';
import { VUE003 } from './categories/vue/render-innerhtml';

import { NG001 } from './categories/angular/bypass-security-trust';
import { NG002 } from './categories/angular/native-innerhtml';
import { NG003 } from './categories/angular/binding-innerhtml';
import { NG004 } from './categories/angular/jsonp-injection';
import { NG005 } from './categories/angular/navigate-open-redirect';
import { NG006 } from './categories/angular/unguarded-route';

import { SVELTE001 } from './categories/svelte/html-tag';

export const ALL_RULES: Rule[] = [
  SQLI001, SQLI002, SQLI003, SQLI004,
  NOSQL001, NOSQL002, NOSQL003,
  XSS001, XSS002, XSS003, XSS004,
  CMDI001, CMDI002, CMDI003,
  PATH001, PATH002,
  AUTH001, AUTH002, AUTH003, AUTH004,
  SEC001, SEC002, SEC003,
  ERR001, ERR002, ERR003,
  CONF001, CONF002, CONF003, CONF004,
  DEP001, DEP002, DEP003, DEP004,
  FASTIFY001, FASTIFY002, FASTIFY003,
  KOA001, KOA002, KOA003,
  PRISMA001, PRISMA002,
  DOM001, DOM002, DOM003, DOM004, DOM005, DOM006, DOM007, DOM008,
  REACT001, REACT002, REACT003, NEXT001, NEXT002,
  VUE001, VUE002, VUE003,
  NG001, NG002, NG003, NG004, NG005, NG006,
  SVELTE001,
];