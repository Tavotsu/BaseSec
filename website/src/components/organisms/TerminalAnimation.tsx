import React, { useState, useEffect, useCallback } from 'react';

const ASCII = `    ____                 _____          
   / __ )____ _________ / ___/__  _____
  / __  / __ \`/ ___/ _ \\__ \\/ _ \\/ ___/
 / /_/ / /_/ (__  )  __/__/ / __/ /__
/_____/\\__,_/____/\\___/____/\\___/\\___/ `;

const lines = [
  { text: "user@host:~$ basesec scan ./src", delay: 600, type: "cmd" },
  { text: ASCII, delay: 0, type: "ascii" },
  { text: "[INFO] Initializing BaseSec Engine v1.0.0...", delay: 900, type: "info" },
  { text: "[INFO] Discovering source files...", delay: 1200, type: "info" },
  { text: "[INFO] Frameworks detected: express, nestjs, mongoose, typeorm", delay: 1600, type: "info" },
  { text: "[INFO] Files: 78 | Skipped: 0", delay: 2000, type: "info" },
  { text: "[INFO] Building Abstract Syntax Trees... DONE", delay: 2500, type: "success" },
  { text: "[INFO] Running Taint Analysis (32 active rules)...", delay: 3200, type: "info" },
  { text: "[WARN] Analyzing flow in controllers/auth.controller.ts...", delay: 3900, type: "warn" },
  { text: "─".repeat(60), delay: 4400, type: "divider" },
  { text: "[HIGH] SQLI-001: SQL Injection via Tainted Input", delay: 4700, type: "error-title" },
  { text: "  File: src/controllers/auth.controller.ts:42", delay: 5000, type: "error" },
  { text: "  Code: db.query(`SELECT * FROM users WHERE id = '${userId}'`)", delay: 5200, type: "code" },
  { text: "  > Untrusted req.query.id flows directly into SQL execution sink.", delay: 5450, type: "code-error" },
  { text: "  Remedy: Use parameterized queries: db.query('SELECT * FROM users WHERE id = ?', [userId])", delay: 5700, type: "remedy" },
  { text: "[HIGH] AUTH-001: Missing Authentication Guard", delay: 6100, type: "error-title" },
  { text: "  File: src/controllers/user.controller.ts:77", delay: 6300, type: "error" },
  { text: "  Code: router.delete('/users/:id', deleteUser)", delay: 6500, type: "code" },
  { text: "  > Route handler for .delete() has no authentication middleware.", delay: 6700, type: "code-error" },
  { text: "  Remedy: Add authentication middleware to all mutating endpoints.", delay: 6900, type: "remedy" },
  { text: "[MEDIUM] XSS-002: Missing Helmet Middleware", delay: 7300, type: "warn-finding" },
  { text: "  File: src/app.ts:1", delay: 7500, type: "error" },
  { text: "  > Express app without helmet(). Missing security headers.", delay: 7700, type: "code-error" },
  { text: "─".repeat(60), delay: 8100, type: "divider" },
  { text: "Scan complete: 100 findings (9 high, 10 medium, 81 low)", delay: 8400, type: "summary" },
  { text: "Duration: 0.3s", delay: 8600, type: "info" },
  { text: "user@host:~$ ", delay: 9000, type: "prompt" },
];

export const TerminalAnimation: React.FC = () => {
  const [visibleLines, setVisibleLines] = useState<number>(0);
  const [key, setKey] = useState(0);

  const startAnimation = useCallback(() => {
    setVisibleLines(0);
    const timeouts: number[] = [];
    lines.forEach((line, index) => {
      const timeout = window.setTimeout(() => {
        setVisibleLines(index + 1);
      }, line.delay);
      timeouts.push(timeout);
    });
    return () => timeouts.forEach(clearTimeout);
  }, []);

  useEffect(() => {
    return startAnimation();
  }, [key, startAnimation]);

  const typeClass = (type: string) => {
    switch (type) {
      case 'ascii': return 'text-[var(--color-primary)] font-mono text-xs leading-tight mb-3 block opacity-80';
      case 'cmd': return 'text-white font-bold';
      case 'info': return 'text-gray-400';
      case 'success': return 'text-[var(--color-primary)]';
      case 'warn': return 'text-yellow-400';
      case 'warn-finding': return 'text-yellow-300 font-bold mt-3';
      case 'error-title': return 'text-[var(--color-destructive)] font-bold mt-3';
      case 'error': return 'text-red-400/80';
      case 'code': return 'text-gray-500 font-mono text-xs pl-2';
      case 'code-error': return 'text-orange-400 font-mono text-xs pl-2 bg-orange-950/20 py-0.5';
      case 'remedy': return 'text-emerald-500/80 font-mono text-xs pl-2';
      case 'divider': return 'text-[var(--color-border)] text-xs select-none';
      case 'summary': return 'text-[var(--color-primary)] font-bold mt-2';
      case 'prompt': return 'text-[var(--color-primary)] mt-3';
      default: return '';
    }
  };

  return (
    <div className="w-full max-w-5xl mx-auto bg-[#0a0a0a] rounded-lg border border-[var(--color-border)] shadow-[0_0_40px_rgba(0,255,65,0.08)] overflow-hidden font-mono text-sm text-left relative group">
      {/* Scanline overlay */}
      <div className="absolute inset-0 pointer-events-none z-10" style={{
        backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 3px, rgba(0,0,0,0.08) 3px, rgba(0,0,0,0.08) 4px)',
      }}></div>

      {/* Title bar */}
      <div className="flex items-center px-4 py-3 bg-[#111] border-b border-[var(--color-border)] relative z-20">
        <div className="flex gap-2">
          <div className="w-3 h-3 rounded-full bg-[#FF5F56]"></div>
          <div className="w-3 h-3 rounded-full bg-[#FFBD2E]"></div>
          <div className="w-3 h-3 rounded-full bg-[#27C93F]"></div>
        </div>
        <div className="ml-4 text-xs text-gray-600 uppercase tracking-widest">basesec — scan</div>
        <button
          onClick={() => setKey(k => k + 1)}
          className="ml-auto text-[var(--color-primary)]/60 hover:text-[var(--color-primary)] opacity-0 group-hover:opacity-100 transition-all text-xs tracking-widest"
        >
          ↻ REPLAY
        </button>
      </div>

      {/* Output */}
      <div className="p-6 min-h-[520px] relative z-20 overflow-auto">
        {lines.slice(0, visibleLines).map((line, i) => (
          line.type === 'ascii'
            ? <pre key={i} className={typeClass(line.type)}>{line.text}</pre>
            : (
          <div key={i} className={`mb-1 leading-relaxed ${typeClass(line.type)}`}>
            {line.type === 'prompt'
              ? <span>{line.text}<span className="inline-block w-2 h-4 bg-[var(--color-primary)] ml-px align-middle animate-pulse"></span></span>
              : line.text
            }
          </div>
            )
        ))}
      </div>
    </div>
  );
};
