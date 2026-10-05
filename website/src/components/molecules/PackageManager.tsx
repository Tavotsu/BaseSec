import React, { useState } from 'react';
import { Check, Copy, Terminal } from 'lucide-react';

type CommandType = 'npx' | 'npm' | 'pnpm' | 'bun';

export const PackageManager: React.FC = () => {
  const [activeTab, setActiveTab] = useState<CommandType>('npx');
  const [copied, setCopied] = useState(false);

  const commands: Record<CommandType, string> = {
    npx: 'npx basesec scan ./src',
    pnpm: 'pnpm dlx basesec scan ./src',
    npm: 'npm install -g basesec',
    bun: 'bunx basesec scan ./src'
  };

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(commands[activeTab]);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
    }
  };

  return (
    <div className="w-full max-w-xl mx-auto rounded-xl border border-[var(--color-border)] bg-[#0C0E12] shadow-2xl overflow-hidden text-left transition-all">
      {/* Tab Header */}
      <div className="flex items-center justify-between px-3 pt-2 pb-0 bg-[#0E1116] border-b border-[var(--color-border)]">
        <div className="flex gap-1">
          {(['npx', 'pnpm', 'npm', 'bun'] as CommandType[]).map((tab) => (
            <button
              key={tab}
              onClick={() => {
                setActiveTab(tab);
                setCopied(false);
              }}
              className={`px-3 py-1.5 text-xs font-mono font-medium rounded-t-md transition-all duration-150 relative ${
                activeTab === tab
                  ? 'text-[var(--color-primary)] bg-[#0C0E12] border-t border-x border-[var(--color-border)]'
                  : 'text-[var(--color-muted)] hover:text-white hover:bg-white/[0.03]'
              }`}
            >
              {tab === 'npx' ? '⚡ npx (zero-install)' : tab}
              {activeTab === tab && (
                <span className="absolute -bottom-px left-0 right-0 h-px bg-[#0C0E12]" />
              )}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-1.5 text-[11px] font-mono text-[var(--color-muted)] pb-2 pr-2">
          <Terminal size={12} className="text-[var(--color-primary)] opacity-80" />
          <span>v0.1.7</span>
        </div>
      </div>

      {/* Command Bar */}
      <div className="p-4 font-mono text-sm flex items-center justify-between gap-4 bg-[#0C0E12]">
        <div className="flex items-center gap-3 overflow-x-auto py-1 scrollbar-none min-w-0">
          <span className="text-[var(--color-primary)] font-bold select-none text-base">❯</span>
          <span className="text-[#E2E8F0] tracking-wide whitespace-nowrap">
            {commands[activeTab]}
          </span>
        </div>

        <button
          onClick={handleCopy}
          aria-label="Copy command to clipboard"
          className="flex-shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-[#1E232B] bg-[#14171E] hover:bg-[#1C202A] text-xs font-medium text-[var(--color-foreground)] transition-colors hover:text-white active:scale-95"
          title="Copy to clipboard"
        >
          {copied ? (
            <>
              <Check size={14} className="text-[var(--color-primary)]" />
              <span className="text-[var(--color-primary)] font-mono text-xs">Copied</span>
            </>
          ) : (
            <>
              <Copy size={14} className="text-[var(--color-muted)]" />
              <span className="font-mono text-xs text-[var(--color-muted)]">Copy</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
};
