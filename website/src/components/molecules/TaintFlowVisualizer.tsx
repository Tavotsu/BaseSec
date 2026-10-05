import { useState } from 'react';
import { AlertTriangle, CheckCircle2, Shield, Code2, Sparkles } from 'lucide-react';

interface Scenario {
  id: string;
  name: string;
  category: string;
  ruleId: string;
  framework: string;
  severity: 'HIGH' | 'CRITICAL' | 'MEDIUM';
  source: {
    label: string;
    code: string;
    description: string;
  };
  flow: {
    code: string;
    description: string;
  };
  sink: {
    label: string;
    code: string;
    description: string;
  };
  remedy: string;
}

const SCENARIOS: Scenario[] = [
  {
    id: 'sqli',
    name: 'SQL Injection Flow',
    category: 'SQLI',
    ruleId: 'SQLI-001',
    framework: 'Express / TypeORM',
    severity: 'HIGH',
    source: {
      label: 'Taint Source',
      code: 'const { userId } = req.query;',
      description: 'Untrusted user input directly captured from query params.'
    },
    flow: {
      code: 'const query = `SELECT * FROM users WHERE id = \'${userId}\'`;',
      description: 'Taint propagates through template string interpolation.'
    },
    sink: {
      label: 'Dangerous Sink',
      code: 'await db.query(query);',
      description: 'Unsanitized input reaches raw database execution.'
    },
    remedy: 'await db.query("SELECT * FROM users WHERE id = ?", [userId]);'
  },
  {
    id: 'xss',
    name: 'Frontend DOM XSS',
    category: 'XSS',
    ruleId: 'REACT-001',
    framework: 'React / Next.js',
    severity: 'HIGH',
    source: {
      label: 'Browser Source',
      code: 'const query = searchParams.get("preview");',
      description: 'URL parameter extracted from Next.js / React Router hook.'
    },
    flow: {
      code: 'const htmlContent = formatMarkdown(query);',
      description: 'Flows into formatted string without HTML escaping.'
    },
    sink: {
      label: 'Dangerous Sink',
      code: '<div dangerouslySetInnerHTML={{ __html: htmlContent }} />',
      description: 'Raw HTML injection bypasses React JSX automatic escaping.'
    },
    remedy: '<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(htmlContent) }} />'
  },
  {
    id: 'cmdi',
    name: 'Command Injection',
    category: 'CMDI',
    ruleId: 'CMDI-001',
    framework: 'Fastify / Node.js',
    severity: 'CRITICAL',
    source: {
      label: 'HTTP Body Source',
      code: 'const { branch } = request.body;',
      description: 'Payload received directly from client JSON request.'
    },
    flow: {
      code: 'const cmd = `git checkout ${branch}`;',
      description: 'Input concatenated directly into shell execution command.'
    },
    sink: {
      label: 'Dangerous Sink',
      code: 'exec(cmd, callback);',
      description: 'Child process spawned with unescaped shell metacharacters.'
    },
    remedy: 'execFile("git", ["checkout", branch], callback);'
  }
];

export const TaintFlowVisualizer: React.FC = () => {
  const [selectedId, setSelectedId] = useState('sqli');
  const [showRemedy, setShowRemedy] = useState(false);

  const scenario = SCENARIOS.find(s => s.id === selectedId) || SCENARIOS[0];

  return (
    <div className="w-full rounded-2xl border border-[var(--color-border)] bg-[#0C0E13] p-5 md:p-8 shadow-2xl relative overflow-hidden">
      {/* Background radial accent */}
      <div className="absolute top-0 right-0 w-96 h-96 bg-[var(--color-primary)]/5 rounded-full blur-3xl pointer-events-none" />

      {/* Header & Scenario Selector */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-[var(--color-border)]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-[var(--color-primary)]/10 text-[var(--color-primary)] border border-[var(--color-primary)]/20">
              <Sparkles size={12} /> AST Taint Flow Engine
            </span>
            <span className="text-xs font-mono text-[var(--color-muted)]">
              Real-time sink tracking
            </span>
          </div>
          <h3 className="text-xl font-heading font-bold text-white tracking-tight">
            How BaseSec Catches What Linters Miss
          </h3>
        </div>

        {/* Scenario Pills */}
        <div className="flex gap-1.5 bg-[#14171F] p-1 rounded-lg border border-[var(--color-border)]">
          {SCENARIOS.map((s) => (
            <button
              key={s.id}
              onClick={() => {
                setSelectedId(s.id);
                setShowRemedy(false);
              }}
              className={`px-3 py-1.5 rounded-md text-xs font-mono font-medium transition-all ${
                selectedId === s.id
                  ? 'bg-[var(--color-surface)] text-white shadow-sm border border-[var(--color-border)]'
                  : 'text-[var(--color-muted)] hover:text-white'
              }`}
            >
              {s.category}
            </button>
          ))}
        </div>
      </div>

      {/* Metadata Bar */}
      <div className="flex items-center justify-between flex-wrap gap-3 py-3 text-xs font-mono text-[var(--color-muted)] border-b border-[var(--color-border-subtle)]">
        <div className="flex items-center gap-3">
          <span className="text-white font-semibold flex items-center gap-1.5">
            <Code2 size={14} className="text-[var(--color-primary)]" />
            {scenario.name}
          </span>
          <span className="text-[#1E232B]">•</span>
          <span>{scenario.framework}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="px-2 py-0.5 rounded bg-red-950/40 text-red-400 border border-red-900/40 font-bold">
            {scenario.severity}
          </span>
          <span className="px-2 py-0.5 rounded bg-[#161921] border border-[#1E232B] text-[var(--color-foreground)]">
            {scenario.ruleId}
          </span>
        </div>
      </div>

      {/* The 3-Step Flow Diagram */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 my-6">
        {/* Step 1: Source */}
        <div className="flex flex-col p-4 rounded-xl bg-[#0F1117] border border-[#1E232B] relative">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono font-semibold uppercase tracking-wider text-amber-400 flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
              1. {scenario.source.label}
            </span>
          </div>
          <div className="p-3 rounded-lg bg-[#07080A] border border-[#1A1D24] font-mono text-xs text-[#F1F5F9] my-2 overflow-x-auto">
            <code>{scenario.source.code}</code>
          </div>
          <p className="text-xs text-[var(--color-muted)] mt-auto pt-2 leading-relaxed">
            {scenario.source.description}
          </p>
        </div>

        {/* Step 2: Propagation */}
        <div className="flex flex-col p-4 rounded-xl bg-[#0F1117] border border-[#1E232B] relative">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono font-semibold uppercase tracking-wider text-orange-400 flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-orange-400" />
              2. AST Propagation
            </span>
          </div>
          <div className="p-3 rounded-lg bg-[#07080A] border border-[#1A1D24] font-mono text-xs text-[#F1F5F9] my-2 overflow-x-auto">
            <code>{scenario.flow.code}</code>
          </div>
          <p className="text-xs text-[var(--color-muted)] mt-auto pt-2 leading-relaxed">
            {scenario.flow.description}
          </p>
        </div>

        {/* Step 3: Dangerous Sink */}
        <div className="flex flex-col p-4 rounded-xl bg-[#0F1117] border border-red-900/30 relative">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono font-semibold uppercase tracking-wider text-red-400 flex items-center gap-1.5">
              <AlertTriangle size={13} className="text-red-400" />
              3. {scenario.sink.label}
            </span>
          </div>
          <div className="p-3 rounded-lg bg-[#07080A] border border-red-900/40 font-mono text-xs text-red-200 my-2 overflow-x-auto">
            <code>{scenario.sink.code}</code>
          </div>
          <p className="text-xs text-[var(--color-muted)] mt-auto pt-2 leading-relaxed">
            {scenario.sink.description}
          </p>
        </div>
      </div>

      {/* Remediation Action Card */}
      <div className="mt-4 p-4 rounded-xl border border-[var(--color-border)] bg-[#10131A] transition-all">
        <div className="flex items-center justify-between flex-wrap gap-2 mb-2">
          <span className="text-xs font-mono font-semibold uppercase tracking-wider text-[var(--color-primary)] flex items-center gap-1.5">
            <Shield size={14} /> BaseSec Suggested Remediation
          </span>
          <button
            onClick={() => setShowRemedy(!showRemedy)}
            className="text-xs font-mono text-[var(--color-primary)] hover:underline"
          >
            {showRemedy ? 'Hide diff' : 'Show safe code'}
          </button>
        </div>

        <div className="p-3 rounded-lg bg-[#07080A] border border-emerald-950/60 font-mono text-xs text-emerald-300 flex items-center justify-between gap-4 overflow-x-auto">
          <code>{scenario.remedy}</code>
          <span className="flex-shrink-0 inline-flex items-center gap-1 text-[11px] text-emerald-400 font-sans">
            <CheckCircle2 size={13} /> Safe
          </span>
        </div>
      </div>
    </div>
  );
};
