import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowLeft, Plus, Bug } from 'lucide-react';
import { Button } from '../components/atoms/Button';

const VERSIONS = [
  {
    version: '0.1.4',
    date: '2026-06-04',
    type: 'major',
    changes: [
      { label: 'AI-powered analysis enhancement', detail: 'Enriches findings with AI-generated explanations and detects suspicious taint flows that may bypass existing rules', type: 'added' },
      { label: 'Auto-save reports', detail: 'Non-terminal formats auto-save to ~/.basesec/ without needing --output', type: 'added' },
    ],
  },
  {
    version: '0.1.3',
    date: '2026-06-01',
    type: 'patch',
    changes: [
      { label: 'Windows flag recognition', detail: 'Added hasArg() and getArgValue() to handle both kebab-case and camelCase flags', type: 'fixed' },
      { label: '--help flags updated', detail: 'Added 0.1.1 and 0.1.2 flags to --help', type: 'fixed' },
    ],
  },
  {
    version: '0.1.2',
    date: '2026-05-23',
    type: 'major',
    changes: [
      { label: 'Fastify support', detail: '3 new rules: FASTIFY-001, FASTIFY-002, FASTIFY-003', type: 'added' },
      { label: 'Koa support', detail: '3 new rules: KOA-001, KOA-002, KOA-003', type: 'added' },
      { label: 'Prisma support', detail: '2 new rules: PRISMA-001, PRISMA-002', type: 'added' },
      { label: 'Dependency checking', detail: '4 new rules: DEP-001 to DEP-004 (CVE detection, audit, unused, lockfile)', type: 'added' },
      { label: 'New CLI flags', detail: '--no-deps, --read-env, --verbose', type: 'added' },
    ],
  },
  {
    version: '0.1.1',
    date: '2026-05-10',
    type: 'patch',
    changes: [
      { label: 'typescript in dependencies', detail: 'Fixes ERR_MODULE_NOT_FOUND on global install', type: 'fixed' },
      { label: 'NestJS taint propagation', detail: '@Body(), @Param(), @Query() now correctly registered as taint sources', type: 'fixed' },
      { label: 'ERR-001 detection broadened', detail: 'Catches any .stack/.message access inside response arguments', type: 'fixed' },
      { label: 'NOSQL-002 over-reporting', detail: 'Mongoose detectMongoosePatterns() now separates leanLineNumbers from whereLineNumbers', type: 'fixed' },
    ],
  },
  {
    version: '0.1.0',
    date: '2025-05-07',
    type: 'major',
    changes: [
      { label: '30 security rules', detail: 'Across 9 categories: SQLI, NOSQL, XSS, CMDI, PATH, AUTH, SEC, ERR, CONF', type: 'added' },
      { label: 'Taint analysis engine', detail: 'Data flow tracking from sources (req.query, req.body) to dangerous sinks', type: 'added' },
      { label: 'Framework detection', detail: 'Express, NestJS, Mongoose, TypeORM with native context resolution', type: 'added' },
      { label: '5 output formats', detail: 'Terminal, JSON, SARIF, HTML, Markdown', type: 'added' },
      { label: '342 tests', detail: '~88.75% statement coverage', type: 'added' },
    ],
  },
  {
    version: '0.0.9',
    date: '2025-04-01',
    type: 'minor',
    changes: [
      { label: 'Initial project scaffold', detail: 'CLI with scan and init commands', type: 'added' },
      { label: 'Core pipeline', detail: 'FileCollector → Parser → Analyzer → ResultStore', type: 'added' },
      { label: 'TypeScript Compiler API parser', detail: 'ts.createSourceFile-based parsing', type: 'added' },
      { label: 'Terminal and JSON formatters', detail: 'Two output formats for scan results', type: 'added' },
    ],
  },
];

const VERSION_COLORS: Record<string, { bg: string; border: string; badge: string; text: string; icon: string }> = {
  major: { bg: '#0a1f0a', border: '#1a3a1a', badge: '#00FF41', text: '#00FF41', icon: '#00FF41' },
  minor: { bg: '#0f0f0f', border: '#2a2a2a', badge: '#9CA3AF', text: '#9CA3AF', icon: '#6B7280' },
  patch: { bg: '#0a0f1a', border: '#1a2a3a', badge: '#38BDF8', text: '#38BDF8', icon: '#38BDF8' },
};

const Changelog: React.FC = () => {
  return (
    <div className="flex-1 py-12 px-4 relative z-10">
      <div className="max-w-5xl mx-auto">
        <div className="mb-16 pb-8">
          <Link to="/" className="inline-flex items-center gap-2 text-[var(--color-primary)] hover:underline mb-6 text-sm tracking-widest uppercase font-medium">
            <ArrowLeft size={12} /> Home
          </Link>
          <div className="flex items-end gap-6">
            <h1 className="text-5xl md:text-6xl font-heading font-bold uppercase tracking-wide text-white">
              <span style={{ color: 'var(--color-primary)' }}>Change</span>log
            </h1>
            <span className="text-sm text-[var(--color-muted)] mb-2 tracking-widest font-mono">v0.0.9 → v0.1.4</span>
          </div>
          <p className="mt-4 text-[var(--color-foreground)] text-sm opacity-50 max-w-xl leading-relaxed">
            Complete version history of BaseSec — from initial scaffold to AI-powered analysis.
          </p>
        </div>

        <div className="relative space-y-8">
          <div
            className="absolute left-[1.35rem] top-8 bottom-8 w-px"
            style={{
              background: 'linear-gradient(to bottom, var(--color-primary), var(--color-border) 60%, transparent)',
            }}
          />

          {VERSIONS.map((ver) => {
            const c = VERSION_COLORS[ver.type];
            return (
              <div
                key={ver.version}
                className="relative pl-0"
              >
                <div
                  className="border p-6 relative group transition-all duration-300 hover:border-opacity-60"
                  style={{
                    backgroundColor: c.bg,
                    borderColor: c.border,
                  }}
                >
                  <div className="absolute top-0 right-0 w-48 h-48 pointer-events-none"
                    style={{
                      background: `radial-gradient(circle at top right, ${c.badge}08 0%, transparent 60%)`,
                    }}
                  />

                  <div className="flex items-center gap-4 mb-6 flex-wrap">
                    <span
                      className="text-sm font-bold px-3 py-1 border"
                      style={{
                        borderColor: c.border,
                        color: c.badge,
                        backgroundColor: `${c.badge}12`,
                      }}
                    >
                      v{ver.version}
                    </span>
                    <span className="text-xs text-[var(--color-muted)] font-mono">{ver.date}</span>
                    <span
                      className="text-[10px] uppercase tracking-widest px-2 py-1 border font-medium"
                      style={{ borderColor: c.border, color: c.text + '99' }}
                    >
                      {ver.type}
                    </span>
                  </div>

                  <div className="space-y-3">
                    {ver.changes.map((change, cidx) => (
                      <div key={cidx} className="flex items-start gap-3">
                        <span
                          className="mt-0.5 w-5 h-5 rounded flex items-center justify-center flex-shrink-0"
                          style={{
                            backgroundColor: change.type === 'added' ? `${c.badge}15` : '#38BDF815',
                            color: change.type === 'added' ? c.icon : '#38BDF8',
                          }}
                        >
                          {change.type === 'added' ? <Plus size={10} strokeWidth={3} /> : <Bug size={10} strokeWidth={3} />}
                        </span>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-semibold leading-tight" style={{ color: '#F3F4F6' }}>{change.label}</p>
                          <p className="text-xs mt-1 leading-relaxed" style={{ color: '#9CA3AF' }}>{change.detail}</p>
                        </div>
                      </div>
                    ))}
                  </div>

                  <div
                    className="absolute bottom-0 left-0 right-0 h-[2px] opacity-0 group-hover:opacity-100 transition-opacity duration-500"
                    style={{
                      background: `linear-gradient(to right, ${c.badge}60, ${c.badge}00)`,
                    }}
                  />
                </div>
              </div>
            );
          })}
        </div>

        <div className="mt-20 pb-24 text-center">
          <Link to="/features">
            <Button variant="primary" className="tracking-widest uppercase text-xs px-8 py-3">
              See it in action →
            </Button>
          </Link>
        </div>
      </div>
    </div>
  );
};

export default Changelog;