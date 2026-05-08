import React, { useState } from 'react';

type PM = 'npm' | 'pnpm' | 'bun' | 'yarn';

export const PackageManager: React.FC = () => {
  const [pm, setPm] = useState<PM>('npm');

  const commands: Record<PM, string> = {
    npm: 'npm install -g basesec',
    pnpm: 'pnpm add -g basesec',
    bun: 'bun add -g basesec',
    yarn: 'yarn global add basesec'
  };

  return (
    <div className="w-full max-w-md mx-auto border border-[var(--color-border)] bg-[var(--color-secondary)]/80 rounded-md overflow-hidden mt-8 text-left shadow-[0_0_15px_rgba(0,255,65,0.1)] transition-all hover:shadow-[0_0_20px_rgba(0,255,65,0.2)]">
      <div className="flex bg-[#121212] border-b border-[var(--color-border)] relative">
        {(['npm', 'pnpm', 'bun', 'yarn'] as PM[]).map((manager) => (
          <button
            key={manager}
            onClick={() => setPm(manager)}
            className={`flex-1 py-3 text-xs font-mono font-bold uppercase transition-all duration-300 relative ${
              pm === manager 
                ? 'text-[var(--color-primary)] bg-[var(--color-primary)]/5' 
                : 'text-[var(--color-foreground)]/50 hover:text-[var(--color-foreground)] hover:bg-[var(--color-muted)]/50'
            }`}
          >
            {manager}
            {pm === manager && (
              <div className="absolute bottom-0 left-0 w-full h-[2px] bg-[var(--color-primary)] shadow-[0_0_8px_var(--color-primary)]" />
            )}
          </button>
        ))}
      </div>
      <div className="p-5 font-mono text-sm flex justify-between items-center group bg-[#0A0A0A]">
        <div className="flex gap-3 items-center">
          <span className="text-[var(--color-primary)] select-none">❯</span>
          <span className="text-[var(--color-foreground)]">{commands[pm]}</span>
        </div>
        <button 
          onClick={() => navigator.clipboard.writeText(commands[pm])}
          className="text-[var(--color-foreground)]/30 hover:text-[var(--color-primary)] transition-colors opacity-0 group-hover:opacity-100"
          title="Copy to clipboard"
        >
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
        </button>
      </div>
    </div>
  );
};
