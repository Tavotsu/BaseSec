import React from 'react';
import { Button } from '../components/atoms/Button';
import { PackageManager } from '../components/molecules/PackageManager';
import { FeatureCard } from '../components/molecules/FeatureCard';
import { Shield, Cpu, Zap, FileSearch, GitBranch, FileOutput } from 'lucide-react';
import { Link } from 'react-router-dom';

const Landing: React.FC = () => {
  return (
    <div className="flex-1">
      {/* Hero Section */}
      <section className="min-h-[80vh] flex flex-col items-center justify-center text-center px-4 relative z-10">
        <div className="mb-8 relative inline-block">
          <img src="/logo.png" alt="BaseSec Logo" className="w-32 h-32 md:w-48 md:h-48 drop-shadow-[0_0_24px_rgba(0,255,65,0.4)]" />
          <div className="absolute inset-0 border border-[var(--color-primary)]/20 rounded-full animate-ping opacity-30"></div>
        </div>

        <h1 className="text-4xl md:text-7xl font-bold font-heading mb-6 tracking-tighter uppercase text-glow">
          <span className="text-white">Base</span><span className="text-[var(--color-primary)]">Sec</span>
        </h1>
        <p className="text-lg md:text-xl text-[var(--color-foreground)] max-w-2xl mx-auto mb-3 font-body opacity-90 leading-relaxed">
          CLI SAST tool for Node.js backends.
        </p>
        <p className="text-sm text-[var(--color-foreground)]/60 max-w-xl mx-auto mb-10 font-mono leading-relaxed">
          Detect vulnerabilities via AST analysis and taint tracking — before they reach production.
        </p>

        <PackageManager />

        <div className="mt-8 flex flex-col sm:flex-row gap-4 justify-center">
          <Link to="/features">
            <Button variant="primary" className="w-full sm:w-auto">
              See it in action
            </Button>
          </Link>
          <Button variant="outline" onClick={() => window.open('https://github.com/tavotsu/BaseSec', '_blank')}>
            GitHub Repository
          </Button>
        </div>
      </section>

      {/* Core Features */}
      <section className="py-20 relative z-10 border-t border-[var(--color-border)]">
        <div className="max-w-7xl mx-auto px-4">
          <div className="text-center mb-16">
            <p className="font-mono text-xs text-[var(--color-primary)] uppercase tracking-[0.3em] mb-3">01. Architecture</p>
            <h2 className="text-3xl font-heading font-bold uppercase tracking-widest text-white mb-4">
              Core Protocols
            </h2>
            <div className="h-px w-32 bg-gradient-to-r from-transparent via-[var(--color-primary)]/60 to-transparent mx-auto"></div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-px bg-[var(--color-border)]">
            <FeatureCard
              icon={<Cpu size={28} />}
              title="AST Analysis Engine"
              description="Parses JS/TS files with the TypeScript Compiler API (ts.createSourceFile). Inspects syntax trees at the node level — no regex, no heuristics."
            />
            <FeatureCard
              icon={<Zap size={28} />}
              title="Taint Tracking"
              description="Tracks untrusted data from sources (req.query, req.body, req.params) through assignments and function calls to dangerous sinks like db.query or exec()."
            />
            <FeatureCard
              icon={<FileSearch size={28} />}
              title="30+ Security Rules"
              description="9 categories: SQLI, NOSQL, XSS, CMDI, PATH, AUTH, SSTI, IDOR, misconfiguration. Each rule maps to a CVE-class and produces actionable remedies."
            />
            <FeatureCard
              icon={<Shield size={28} />}
              title="Framework-Aware"
              description="Native context resolution for Express, NestJS, Mongoose, TypeORM, and Sequelize. Detects routes, guards, decorators, and schema definitions in context."
            />
            <FeatureCard
              icon={<FileOutput size={28} />}
              title="5 Report Formats"
              description="Terminal, JSON, SARIF (GitHub Code Scanning), HTML, and Markdown. Drop SARIF straight into your CI pipeline and surface results in pull requests."
            />
            <FeatureCard
              icon={<GitBranch size={28} />}
              title="CI/CD Ready"
              description="Single binary, zero config required. Supports .basesecrc, basesec.config.ts, and package.json entries. Runs in under 0.5s on most codebases."
            />
          </div>

          <div className="mt-16 text-center">
            <div className="inline-flex items-center gap-6 font-mono text-xs text-[var(--color-foreground)]/40 uppercase tracking-widest">
              <span><span className="text-[var(--color-primary)]">78</span> files/sec</span>
              <span className="text-[var(--color-border)]">|</span>
              <span><span className="text-[var(--color-primary)]">9</span> rule categories</span>
              <span className="text-[var(--color-border)]">|</span>
              <span><span className="text-[var(--color-primary)]">5</span> output formats</span>
              <span className="text-[var(--color-border)]">|</span>
              <span><span className="text-[var(--color-primary)]">4</span> frameworks</span>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};

export default Landing;
