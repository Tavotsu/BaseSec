import { describe, it, expect } from 'vitest';
import { runRule } from '../helpers';
import { NG001 } from '../../src/rules/categories/angular/bypass-security-trust';
import { NG002 } from '../../src/rules/categories/angular/native-innerhtml';
import { NG003 } from '../../src/rules/categories/angular/binding-innerhtml';
import { NG004 } from '../../src/rules/categories/angular/jsonp-injection';
import { NG005 } from '../../src/rules/categories/angular/navigate-open-redirect';
import { NG006 } from '../../src/rules/categories/angular/unguarded-route';

describe('NG-001: bypassSecurityTrust', () => {
  it('flags dynamic bypassSecurityTrustHtml', () => {
    expect(runRule(NG001, 'const s = this.sanitizer.bypassSecurityTrustHtml(userHtml);').length).toBe(1);
  });
  it('ignores literal bypass', () => {
    expect(runRule(NG001, 'const s = this.sanitizer.bypassSecurityTrustHtml("<b>x</b>");')).toHaveLength(0);
  });
});

describe('NG-002: nativeElement.innerHTML', () => {
  it('flags dynamic nativeElement.innerHTML', () => {
    expect(runRule(NG002, 'this.el.nativeElement.innerHTML = userInput;').length).toBe(1);
  });
  it('ignores static assignment', () => {
    expect(runRule(NG002, 'this.el.nativeElement.innerHTML = "x";')).toHaveLength(0);
  });
});

describe('NG-003: [innerHTML] binding', () => {
  it('flags [innerHTML] binding', () => {
    expect(runRule(NG003, '<div [innerHTML]="userHtml"></div>').length).toBe(1);
  });
  it('ignores template without [innerHTML]', () => {
    expect(runRule(NG003, '<div>{{ text }}</div>')).toHaveLength(0);
  });
});

describe('NG-004: HttpClient.jsonp', () => {
  it('flags jsonp with dynamic url', () => {
    expect(runRule(NG004, 'this.http.jsonp(userUrl, "cb");').length).toBe(1);
  });
  it('ignores jsonp with static args', () => {
    expect(runRule(NG004, 'this.http.jsonp("https://x.com", "cb");')).toHaveLength(0);
  });
});

describe('NG-005: router open redirect', () => {
  it('flags navigateByUrl from query params', () => {
    expect(runRule(NG005, 'this.router.navigateByUrl(this.route.snapshot.queryParams.next);').length).toBe(1);
  });
  it('ignores static navigateByUrl', () => {
    expect(runRule(NG005, 'this.router.navigateByUrl("/home");')).toHaveLength(0);
  });
});

describe('NG-006: unguarded sensitive route', () => {
  it('flags admin route without guard', () => {
    expect(runRule(NG006, 'const routes = [{ path: "admin", component: AdminComponent }];').length).toBe(1);
  });
  it('ignores guarded admin route', () => {
    expect(runRule(NG006, 'const routes = [{ path: "admin", component: AdminComponent, canActivate: [AuthGuard] }];')).toHaveLength(0);
  });
  it('ignores nav-menu entries that merely have a path', () => {
    expect(runRule(NG006, 'const nav = [{ path: "admin", label: "Admin", icon: "shield" }];')).toHaveLength(0);
  });
  it('flags lazy routes declared with loadComponent/loadChildren', () => {
    expect(runRule(NG006, 'const routes = [{ path: "settings", loadComponent: () => import("./s") }];').length).toBe(1);
    expect(runRule(NG006, 'const routes = [{ path: "admin", loadChildren: () => import("./a") }];').length).toBe(1);
  });
});
