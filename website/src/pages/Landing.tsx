import React from 'react';
import { Button } from '../components/atoms/Button';
import { PackageManager } from '../components/molecules/PackageManager';
import { FeatureCard } from '../components/molecules/FeatureCard';
import { StatsBar } from '../components/molecules/StatsBar';
import { Shield, Cpu, Zap, FileSearch, GitBranch, FileOutput, Brain } from 'lucide-react';
import { Link } from 'react-router-dom';

const Landing: React.FC = () => {
  return (
    <div className="flex-1">
      {/* Hero Section */}
      <section className="min-h-[80vh] flex flex-col items-center justify-center text-center px-4 relative z-10">
        <div className="mb-8 relative inline-block">
          <img src="./logo.png" alt="BaseSec Logo" className="w-32 h-32 md:w-48 md:h-48 drop-shadow-[0_0_24px_rgba(0,255,65,0.4)]" />
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

      {/* Stats Bar */}
      <section className="relative z-10 border-t border-[var(--color-border)]">
        <div className="max-w-7xl mx-auto px-4 py-8">
          <p className="font-mono text-xs text-[var(--color-foreground)]/40 uppercase tracking-[0.3em] mb-4 text-center">Live Stats</p>
          <StatsBar />
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

          <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-[var(--color-border)]">
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
              title="42 Security Rules"
              description="10 categories including SQLI, NOSQL, XSS, CMDI, PATH, AUTH, SEC, ERR, CONF, and DEP. Each rule maps to a CVE-class and produces actionable remedies for developers."
            />
            <FeatureCard
              icon={<Shield size={28} />}
              title="Framework-Aware"
              description="Native context resolution for Express, NestJS, Fastify, Koa, Prisma, Mongoose, and TypeORM. Detects routes, guards, and raw queries in context."
            />
            <FeatureCard
              icon={<GitBranch size={28} />}
              title="Supply Chain Security"
              description="Validates package dependencies against known CVEs, flags unused modules, checks lockfile mismatches, and auto-protects .env files from exposure."
            />
            <FeatureCard
              icon={<Brain size={28} />}
              title="AI-Powered Analysis"
              description="Opt-in AI enrichment via Ollama (local, no data leaves your machine) or OpenAI. Detects suspicious taint flows that may bypass existing rules with AI-001."
            />
          </div>

          <div className="mt-px">
            <div className="flex justify-center">
              <FeatureCard
                icon={<FileOutput size={28} />}
                title="CI/CD & Reporting"
                description="Zero-config CLI with 5 formats (Terminal, JSON, SARIF, HTML, MD). Fine-tune workers via .basesecrc and use --verbose for deep execution tracing."
              />
            </div>
          </div>

          <div className="mt-16 text-center">
            <div className="inline-flex items-center gap-6 font-mono text-xs text-[var(--color-foreground)]/40 uppercase tracking-widest flex-wrap justify-center">
              <span><span className="text-[var(--color-primary)]">78</span> files/sec</span>
              <span className="text-[var(--color-border)] hidden sm:inline">|</span>
              <span><span className="text-[var(--color-primary)]">42</span> security rules</span>
              <span className="text-[var(--color-border)] hidden sm:inline">|</span>
              <span><span className="text-[var(--color-primary)]">10</span> rule categories</span>
              <span className="text-[var(--color-border)] hidden sm:inline">|</span>
              <span><span className="text-[var(--color-primary)]">5</span> output formats</span>
              <span className="text-[var(--color-border)] hidden sm:inline">|</span>
              <span><span className="text-[var(--color-primary)]">7</span> frameworks</span>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};

export default Landing;
