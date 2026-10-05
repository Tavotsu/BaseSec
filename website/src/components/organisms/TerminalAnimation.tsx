import { useState, useEffect } from 'react';
import { RotateCw, FastForward, Check, Copy } from 'lucide-react';

const ASCII = `    ____                 _____          
   / __ )____ _________ / ___/__  _____
  / __  / __ \`/ ___/ _ \\__ \\/ _ \\/ ___/
 / /_/ / /_/ (__  )  __/__/ / __/ /__
/_____/\\__,_/____/\\___/____/\\___/\\___/ `;

interface LineItem {
  text: string;
  delay: number;
  type: 'cmd' | 'ascii' | 'info' | 'success' | 'warn' | 'warn-finding' | 'error-title' | 'error' | 'code' | 'code-error' | 'remedy' | 'divider' | 'summary' | 'prompt';
}

const lines: LineItem[] = [
  { text: "user@host:~$ basesec scan ./src", delay: 200, type: "cmd" },
  { text: ASCII, delay: 50, type: "ascii" },
  { text: "[INFO] Initializing BaseSec Engine v0.1.7...", delay: 500, type: "info" },
  { text: "[INFO] Discovering source files...", delay: 800, type: "info" },
  { text: "[INFO] Frameworks detected: express, nestjs, mongoose, react, vue", delay: 1100, type: "info" },
  { text: "[INFO] Files: 78 (.ts, .tsx, .vue) | Skipped: 0", delay: 1400, type: "info" },
  { text: "[INFO] Building Abstract Syntax Trees... DONE", delay: 1800, type: "success" },
  { text: "[INFO] Running Taint Analysis (65 active rules)...", delay: 2200, type: "info" },
  { text: "[WARN] Analyzing flow in controllers/auth.controller.ts...", delay: 2700, type: "warn" },
  { text: "─".repeat(60), delay: 3000, type: "divider" },
  { text: "[HIGH] SQLI-001: SQL Injection via Tainted Input", delay: 3300, type: "error-title" },
  { text: "  File: src/controllers/auth.controller.ts:42", delay: 3500, type: "error" },
  { text: "  Code: db.query(`SELECT * FROM users WHERE id = '${userId}'`)", delay: 3700, type: "code" },
  { text: "  > Untrusted req.query.id flows directly into SQL execution sink.", delay: 3900, type: "code-error" },
  { text: "  Remedy: Use parameterized queries: db.query('SELECT * FROM users WHERE id = ?', [userId])", delay: 4100, type: "remedy" },
  { text: "[HIGH] AUTH-001: Missing Authentication Guard", delay: 4400, type: "error-title" },
  { text: "  File: src/controllers/user.controller.ts:77", delay: 4600, type: "error" },
  { text: "  Code: router.delete('/users/:id', deleteUser)", delay: 4800, type: "code" },
  { text: "  > Route handler for .delete() has no authentication middleware.", delay: 5000, type: "code-error" },
  { text: "  Remedy: Add authentication middleware to all mutating endpoints.", delay: 5200, type: "remedy" },
  { text: "[HIGH] REACT-001: XSS via dangerouslySetInnerHTML", delay: 5500, type: "error-title" },
  { text: "  File: src/components/Comment.tsx:18", delay: 5700, type: "error" },
  { text: "  Code: <div dangerouslySetInnerHTML={{ __html: comment }} />", delay: 5900, type: "code" },
  { text: "  > useSearchParams() value reaches raw HTML injection without sanitization.", delay: 6100, type: "code-error" },
  { text: "  Remedy: Render as text, or sanitize with DOMPurify before injecting HTML.", delay: 6300, type: "remedy" },
  { text: "[MEDIUM] XSS-002: Missing Helmet Middleware", delay: 6600, type: "warn-finding" },
  { text: "  File: src/app.ts:1", delay: 6800, type: "error" },
  { text: "  > Express app without helmet(). Missing security headers.", delay: 7000, type: "code-error" },
  { text: "─".repeat(60), delay: 7300, type: "divider" },
  { text: "Scan complete: 100 findings (9 high, 10 medium, 81 low)", delay: 7500, type: "summary" },
  { text: "Duration: 0.3s", delay: 7700, type: "info" },
  { text: "user@host:~$ ", delay: 8000, type: "prompt" },
];

export const TerminalAnimation: React.FC = () => {
  const [visibleLines, setVisibleLines] = useState<number>(0);
  const [key, setKey] = useState(0);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const timeouts: number[] = [];
    lines.forEach((line, index) => {
      const timeout = window.setTimeout(() => {
        setVisibleLines(index + 1);
      }, line.delay);
      timeouts.push(timeout);
    });
    return () => timeouts.forEach(clearTimeout);
  }, [key]);

  const handleReplay = () => {
    setVisibleLines(0);
    setKey((k) => k + 1);
  };

  const showAll = () => {
    setVisibleLines(lines.length);
  };

  const copyLog = async () => {
    try {
      const textToCopy = lines.map(l => l.text).join('\n');
      await navigator.clipboard.writeText(textToCopy);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // ignore
    }
  };

  const typeClass = (type: string) => {
    switch (type) {
      case 'ascii': return 'text-[var(--color-primary)] font-mono text-xs leading-none mb-3 block opacity-90 select-none';
      case 'cmd': return 'text-white font-bold';
      case 'info': return 'text-slate-400';
      case 'success': return 'text-[var(--color-primary)] font-medium';
      case 'warn': return 'text-amber-300';
      case 'warn-finding': return 'text-amber-400 font-bold mt-3';
      case 'error-title': return 'text-red-400 font-bold mt-3';
      case 'error': return 'text-red-300/80';
      case 'code': return 'text-slate-400 font-mono text-xs pl-2 bg-[#050608] py-0.5 rounded my-0.5 border border-[#161922]';
      case 'code-error': return 'text-orange-300 font-mono text-xs pl-2 bg-orange-950/20 py-0.5 border-l-2 border-orange-500 my-0.5';
      case 'remedy': return 'text-emerald-400 font-mono text-xs pl-2 bg-emerald-950/20 py-0.5 border-l-2 border-emerald-500 my-0.5';
      case 'divider': return 'text-[#1E232B] text-xs select-none';
      case 'summary': return 'text-[var(--color-primary)] font-bold mt-2';
      case 'prompt': return 'text-[var(--color-primary)] mt-3';
      default: return 'text-slate-300';
    }
  };

  return (
    <div className="w-full max-w-5xl mx-auto rounded-2xl border border-[#1E232B] bg-[#0A0C10] shadow-2xl overflow-hidden font-mono text-xs sm:text-sm text-left relative group">
      {/* Title bar */}
      <div className="flex items-center justify-between px-4 py-3 bg-[#0E1015] border-b border-[#1E232B] relative z-20">
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-[#FF5F56]/80 hover:bg-[#FF5F56] transition-colors" />
          <div className="w-3 h-3 rounded-full bg-[#FFBD2E]/80 hover:bg-[#FFBD2E] transition-colors" />
          <div className="w-3 h-3 rounded-full bg-[#27C93F]/80 hover:bg-[#27C93F] transition-colors" />
          <span className="ml-3 text-xs text-[var(--color-muted)] font-medium">
            basesec scan — 78 files scanned
          </span>
        </div>

        <div className="flex items-center gap-2">
          {visibleLines < lines.length && (
            <button
              onClick={showAll}
              className="inline-flex items-center gap-1 px-2 py-1 text-xs text-[var(--color-muted)] hover:text-white rounded bg-white/[0.04] hover:bg-white/[0.08] transition-colors"
              title="Skip animation"
            >
              <FastForward size={12} />
              <span>Fast forward</span>
            </button>
          )}

          <button
            onClick={handleReplay}
            className="inline-flex items-center gap-1 px-2 py-1 text-xs text-[var(--color-muted)] hover:text-[var(--color-primary)] rounded bg-white/[0.04] hover:bg-white/[0.08] transition-colors"
            title="Replay animation"
          >
            <RotateCw size={12} />
            <span>Replay</span>
          </button>

          <button
            onClick={copyLog}
            className="inline-flex items-center gap-1 px-2 py-1 text-xs text-[var(--color-muted)] hover:text-white rounded bg-white/[0.04] hover:bg-white/[0.08] transition-colors"
            title="Copy log"
          >
            {copied ? <Check size={12} className="text-[var(--color-primary)]" /> : <Copy size={12} />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>
      </div>

      {/* Terminal Content Screen */}
      <div className="p-5 sm:p-6 min-h-[460px] max-h-[600px] relative z-20 overflow-y-auto scrollbar-thin bg-[#08090C]">
        {lines.slice(0, visibleLines).map((line, i) => (
          line.type === 'ascii' ? (
            <pre key={i} className={typeClass(line.type)}>{line.text}</pre>
          ) : (
            <div key={i} className={`mb-1 leading-relaxed ${typeClass(line.type)}`}>
              {line.type === 'prompt' ? (
                <span>
                  {line.text}
                  <span className="inline-block w-2 h-3.5 bg-[var(--color-primary)] ml-1 align-middle animate-pulse" />
                </span>
              ) : (
                line.text
              )}
            </div>
          )
        ))}
      </div>
    </div>
  );
};
