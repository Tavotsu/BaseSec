import React from 'react';
import { TerminalAnimation } from '../components/organisms/TerminalAnimation';

const Features: React.FC = () => {
  return (
    <div className="flex-1 py-12 px-4 relative z-10">
      <div className="max-w-7xl mx-auto">
        <div className="mb-12 border-b border-[var(--color-border)] pb-8 text-center">
          <h1 className="text-4xl font-heading font-bold uppercase tracking-wider text-white">
            <span className="text-[var(--color-primary)]">System</span> Diagnostics
          </h1>
          <p className="mt-4 text-[var(--color-foreground)] font-mono max-w-2xl mx-auto opacity-80">
            Witness the engine in action. BaseSec scans files, builds AST representations, and runs deep taint-tracking analysis to catch vulnerabilities before they reach production.
          </p>
        </div>

        <TerminalAnimation />
      </div>
    </div>
  );
};

export default Features;
