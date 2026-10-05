import { TerminalAnimation } from '../components/organisms/TerminalAnimation';
import { Terminal, ArrowLeft } from 'lucide-react';
import { Link } from 'react-router-dom';

const CLI_FLAGS = [
  { flag: '--format <type>', desc: 'Output format: terminal, json, sarif, html, md' },
  { flag: '--framework <name>', desc: 'Force detection: express, nestjs, react, vue, svelte...' },
  { flag: '--read-env', desc: 'Scan environment files for exposed secrets (skips by default)' },
  { flag: '--ai', desc: 'Opt-in AI taint reasoning via local Ollama or OpenAI' },
  { flag: '--verbose', desc: 'Display deep pipeline tracing and worker thread telemetry' },
  { flag: '--no-deps', desc: 'Bypass package.json supply chain CVE checks' },
];

const Features: React.FC = () => {
  return (
    <div className="flex-1 py-12 lg:py-16 px-4 max-w-7xl mx-auto w-full relative z-10">
      {/* Page Header */}
      <div className="mb-10 text-center max-w-3xl mx-auto">
        <Link 
          to="/" 
          className="inline-flex items-center gap-1.5 text-xs font-mono text-[var(--color-muted)] hover:text-white mb-6 px-3 py-1 rounded-full bg-[#12151D] border border-[#1E232B] transition-colors"
        >
          <ArrowLeft size={12} /> Back to Overview
        </Link>
        <h1 className="text-3xl sm:text-5xl font-heading font-extrabold text-white tracking-tight">
          Interactive CLI <span className="text-[var(--color-primary)]">Simulation</span>
        </h1>
        <p className="mt-3 text-sm sm:text-base text-[var(--color-muted)] leading-relaxed">
          Test-drive BaseSec’s analysis engine. Watch how AST nodes are generated, taint flows tracked across controllers and components, and actionable remedies produced.
        </p>
      </div>

      {/* Terminal View */}
      <div className="mb-14">
        <TerminalAnimation />
      </div>

      {/* CLI Reference Grid */}
      <div className="p-6 sm:p-8 rounded-2xl bg-[#0F1117] border border-[#1E232B] max-w-5xl mx-auto">
        <div className="flex items-center justify-between mb-4 border-b border-[#1E232B] pb-3">
          <h3 className="font-heading font-bold text-white text-base flex items-center gap-2">
            <Terminal size={16} className="text-[var(--color-primary)]" />
            Common Command Flags
          </h3>
          <span className="text-xs font-mono text-[var(--color-muted)]">cac framework</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-xs">
          {CLI_FLAGS.map((item) => (
            <div key={item.flag} className="p-3 rounded-lg bg-[#08090C] border border-[#171A21]">
              <span className="text-[var(--color-primary)] font-bold block mb-1">
                {item.flag}
              </span>
              <span className="text-[var(--color-muted)] text-[11px] font-sans">
                {item.desc}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Features;
