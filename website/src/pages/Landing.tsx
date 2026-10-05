import { useState } from 'react';
import { Button } from '../components/atoms/Button';
import { PackageManager } from '../components/molecules/PackageManager';
import { SecurityInspector } from '../components/molecules/SecurityInspector';
import { RulesMatrix } from '../components/organisms/RulesMatrix';
import { ArchitecturePipeline } from '../components/organisms/ArchitecturePipeline';
import { TerminalAnimation } from '../components/organisms/TerminalAnimation';
import { ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';

const Landing: React.FC = () => {
  const [selectedFormat, setSelectedFormat] = useState<'sarif' | 'terminal' | 'json' | 'html'>('sarif');

  return (
    <div className="flex-1 flex flex-col gap-24 lg:gap-32 pb-24">
      {/* ───── Hero Section: Asymmetric Precision Command Deck ───── */}
      <section className="pt-12 sm:pt-20 lg:pt-24 px-4 max-w-7xl mx-auto w-full relative z-10">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-8 items-center">
          
          {/* Left Column: Authoritative Message & Quick Run */}
          <div className="lg:col-span-6 flex flex-col text-left">
            {/* Version indicator */}
            <div className="inline-flex items-center gap-2 text-xs font-mono text-[#94A3B8] mb-5">
              <span className="w-2 h-2 rounded-full bg-[var(--color-primary)]" />
              <span>basesec v0.1.7</span>
              <span className="text-[#334155]">•</span>
              <span>Node.js, React, Vue, Svelte, Angular</span>
            </div>

            {/* Solid, authoritative heading - NO GRADIENT SLOP */}
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-heading font-extrabold text-white tracking-tight leading-[1.08] mb-5">
              Static security testing for JavaScript &amp; TypeScript.
            </h1>

            {/* Accurate technical subtext */}
            <p className="text-base sm:text-lg text-[#94A3B8] leading-relaxed mb-8 max-w-xl">
              Zero regex guesswork. BaseSec executes the TypeScript Compiler API directly, tracking tainted data flows from HTTP queries to database and DOM execution sinks in under 0.4 seconds.
            </p>

            {/* Command Box */}
            <div className="mb-8">
              <PackageManager />
            </div>

            {/* Action Buttons */}
            <div className="flex flex-col sm:flex-row items-center gap-3 mb-8">
              <Link to="/features" className="w-full sm:w-auto">
                <Button variant="primary" size="lg" className="w-full sm:w-auto font-semibold">
                  Launch Interactive Demo <ArrowRight size={16} />
                </Button>
              </Link>
              <a 
                href="https://github.com/tavotsu/BaseSec" 
                target="_blank" 
                rel="noreferrer"
                className="w-full sm:w-auto"
              >
                <Button variant="secondary" size="lg" className="w-full sm:w-auto">
                  <svg className="w-4 h-4 fill-current mr-1" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
                  GitHub Repository
                </Button>
              </a>
            </div>

            {/* Proof Strip - NO GENERIC BOXES */}
            <div className="flex items-center gap-6 sm:gap-8 text-xs font-mono text-[#64748B] flex-wrap pt-4 border-t border-[#1C2028]">
              <div>
                <span className="text-white font-bold tabular-nums">78+</span> files/sec
              </div>
              <div>
                <span className="text-white font-bold tabular-nums">65</span> security rules
              </div>
              <div>
                <span className="text-white font-bold tabular-nums">12</span> frameworks
              </div>
              <div>
                <span className="text-[var(--color-primary)] font-bold">100%</span> offline
              </div>
            </div>
          </div>

          {/* Right Column: Living Code & Taint Inspector */}
          <div className="lg:col-span-6 w-full">
            <SecurityInspector />
          </div>

        </div>
      </section>

      {/* ───── Interactive CVE Rule Matrix ───── */}
      <section className="px-4 max-w-7xl mx-auto w-full relative z-10">
        <div className="mb-8">
          <h2 className="text-2xl sm:text-3xl font-heading font-bold text-white tracking-tight">
            65 Rules Across 11 Vulnerability Classes
          </h2>
          <p className="text-sm text-[#94A3B8] mt-1 max-w-2xl leading-relaxed">
            Every rule maps to an official CWE and CVE class. Inspect how BaseSec checks tainted arguments against dangerous sinks and returns actionable line-by-line remedies.
          </p>
        </div>

        <RulesMatrix />
      </section>

      {/* ───── Architecture & Compiler Pipeline ───── */}
      <section className="px-4 max-w-7xl mx-auto w-full relative z-10">
        <ArchitecturePipeline />
      </section>

      {/* ───── Live CLI Output Simulation ───── */}
      <section className="px-4 max-w-7xl mx-auto w-full relative z-10">
        <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 mb-8">
          <div>
            <h2 className="text-2xl sm:text-3xl font-heading font-bold text-white tracking-tight">
              Real-World Terminal Scan
            </h2>
            <p className="text-sm text-[#94A3B8] mt-1 max-w-xl">
              Simulated scan of <code className="text-white font-mono text-xs bg-[#111317] px-1.5 py-0.5 rounded border border-[#1E232B]">basesec scan ./src</code> against 78 real files.
            </p>
          </div>
          <div className="text-xs font-mono text-[#64748B]">
            Elapsed: <span className="text-white tabular-nums">0.3s</span> · TS Compiler API
          </div>
        </div>

        <TerminalAnimation />
      </section>

      {/* ───── CI/CD & Reporting Formats ───── */}
      <section className="px-4 max-w-7xl mx-auto w-full relative z-10">
        <div className="p-8 lg:p-10 rounded-2xl border border-[#1C2028] bg-[#0A0C10]">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
            <div className="lg:col-span-7">
              <h3 className="text-2xl font-heading font-bold text-white mb-3 tracking-tight">
                Native SARIF for GitHub Actions &amp; GitLab
              </h3>
              <p className="text-sm text-[#94A3B8] leading-relaxed mb-6 max-w-xl">
                BaseSec integrates seamlessly into your automated workflows. Generate SARIF reports that render directly inside your pull request checks and the GitHub Security tab, with automated exit codes to block vulnerable releases.
              </p>

              {/* Format selector tabs */}
              <div className="flex items-center gap-2 mb-4 font-mono text-xs">
                {(['sarif', 'terminal', 'json', 'html'] as const).map((fmt) => (
                  <button
                    key={fmt}
                    onClick={() => setSelectedFormat(fmt)}
                    className={`px-3 py-1.5 rounded-lg uppercase transition-all ${
                      selectedFormat === fmt
                        ? 'bg-[var(--color-primary)] text-[#08090B] font-bold'
                        : 'bg-[#12151D] text-[#94A3B8] hover:text-white border border-[#1C2028]'
                    }`}
                  >
                    --format {fmt}
                  </button>
                ))}
              </div>

              <div className="text-xs font-mono text-[#64748B]">
                {selectedFormat === 'sarif' && 'Emits OASIS SARIF v2.1.0 JSON with exact file URIs and line/column ranges.'}
                {selectedFormat === 'terminal' && 'Color-coded terminal tables with ANSI highlighting and severity totals.'}
                {selectedFormat === 'json' && 'Machine-readable JSON schema for custom parsing and security telemetry.'}
                {selectedFormat === 'html' && 'Standalone offline HTML audit report with interactive category filters.'}
              </div>
            </div>

            {/* Code example of GitHub Actions workflow */}
            <div className="lg:col-span-5 p-4 rounded-xl bg-[#060709] border border-[#161820] font-mono text-xs text-[#CBD5E1] overflow-x-auto">
              <div className="text-[#64748B] text-[10px] pb-2 border-b border-[#14171E] mb-2 flex items-center justify-between">
                <span>.github/workflows/security.yml</span>
                <span>GitHub Action</span>
              </div>
              <pre className="text-[11px] leading-relaxed">
{`- name: Run BaseSec SAST
  run: npx basesec scan ./src --format sarif --output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif`}
              </pre>
            </div>
          </div>
        </div>
      </section>

      {/* ───── Bottom Execution Strip ───── */}
      <section className="px-4 max-w-4xl mx-auto w-full relative z-10 text-center">
        <h2 className="text-2xl sm:text-3xl font-heading font-bold text-white tracking-tight mb-3">
          Test BaseSec against your codebase now
        </h2>
        <p className="text-sm text-[#94A3B8] max-w-lg mx-auto mb-6">
          No sign-ups, no tokens, no background services. Run directly from your command line in 5 seconds.
        </p>

        <div className="inline-flex items-center gap-3 p-2 pl-4 rounded-xl bg-[#0E1015] border border-[#1C2028] font-mono text-xs text-white shadow-xl">
          <span>npx basesec scan ./src</span>
          <button
            onClick={() => navigator.clipboard.writeText('npx basesec scan ./src')}
            className="px-3 py-1.5 rounded-lg bg-[var(--color-primary)] text-[#08090B] font-bold hover:bg-[#1AFF53] transition-colors"
          >
            Copy
          </button>
        </div>
      </section>
    </div>
  );
};

export default Landing;
