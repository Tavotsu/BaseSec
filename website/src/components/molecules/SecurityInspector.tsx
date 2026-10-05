import { useState } from 'react';
import { CheckCircle2, ShieldAlert, RefreshCw, Wrench } from 'lucide-react';

interface CodeScenario {
  id: string;
  name: string;
  framework: string;
  fileName: string;
  ruleId: string;
  cwe: string;
  severity: 'HIGH' | 'CRITICAL';
  vulnerableLines: { num: number; code: string; highlight?: 'source' | 'flow' | 'sink' }[];
  fixedLines: { num: number; code: string; highlight?: 'fixed' }[];
  sinkExplanation: string;
  remedyExplanation: string;
}

const SCENARIOS: CodeScenario[] = [
  {
    id: 'sqli',
    name: 'SQL Injection',
    framework: 'Express / Node.js',
    fileName: 'src/controllers/auth.controller.ts',
    ruleId: 'SQLI-001',
    cwe: 'CWE-89',
    severity: 'HIGH',
    vulnerableLines: [
      { num: 39, code: 'export async function getUser(req: Request, res: Response) {' },
      { num: 40, code: '  const { userId } = req.query; // Untrusted input', highlight: 'source' },
      { num: 41, code: '  const sql = `SELECT * FROM users WHERE id = \'${userId}\'`;', highlight: 'flow' },
      { num: 42, code: '  const result = await db.query(sql); // Direct sink', highlight: 'sink' },
      { num: 43, code: '  return res.json(result);' },
      { num: 44, code: '}' },
    ],
    fixedLines: [
      { num: 39, code: 'export async function getUser(req: Request, res: Response) {' },
      { num: 40, code: '  const { userId } = req.query;' },
      { num: 41, code: '  // Parameterized query isolates data from execution syntax', highlight: 'fixed' },
      { num: 42, code: '  const result = await db.query("SELECT * FROM users WHERE id = ?", [userId]);', highlight: 'fixed' },
      { num: 43, code: '  return res.json(result);' },
      { num: 44, code: '}' },
    ],
    sinkExplanation: 'req.query.userId flows unchecked into raw SQL execution string.',
    remedyExplanation: 'Parameterized query binds userId safely without AST syntax mutation.'
  },
  {
    id: 'xss',
    name: 'Frontend DOM XSS',
    framework: 'React / Next.js',
    fileName: 'src/components/SearchBanner.tsx',
    ruleId: 'REACT-001',
    cwe: 'CWE-79',
    severity: 'HIGH',
    vulnerableLines: [
      { num: 14, code: 'export function SearchBanner() {' },
      { num: 15, code: '  const searchParams = useSearchParams();', highlight: 'source' },
      { num: 16, code: '  const query = searchParams.get("q") || "";', highlight: 'flow' },
      { num: 17, code: '  return <div dangerouslySetInnerHTML={{ __html: query }} />;', highlight: 'sink' },
      { num: 18, code: '}' },
    ],
    fixedLines: [
      { num: 14, code: 'export function SearchBanner() {' },
      { num: 15, code: '  const searchParams = useSearchParams();' },
      { num: 16, code: '  const query = searchParams.get("q") || "";' },
      { num: 17, code: '  return <div>{query}</div>; // Safe JSX text interpolation', highlight: 'fixed' },
      { num: 18, code: '}' },
    ],
    sinkExplanation: 'URL search parameter injected directly into raw DOM innerHTML.',
    remedyExplanation: 'Native JSX text node escapes all HTML entities automatically.'
  },
  {
    id: 'auth',
    name: 'Missing Auth Guard',
    framework: 'NestJS Backend',
    fileName: 'src/users/users.controller.ts',
    ruleId: 'AUTH-001',
    cwe: 'CWE-306',
    severity: 'CRITICAL',
    vulnerableLines: [
      { num: 28, code: '@Controller("users")' },
      { num: 29, code: 'export class UsersController {' },
      { num: 30, code: '  @Delete(":id") // Mutating endpoint lacks @UseGuards()', highlight: 'sink' },
      { num: 31, code: '  async deleteUser(@Param("id") id: string) {' },
      { num: 32, code: '    return this.usersService.remove(id);' },
      { num: 33, code: '  }' },
      { num: 34, code: '}' },
    ],
    fixedLines: [
      { num: 28, code: '@Controller("users")' },
      { num: 29, code: 'export class UsersController {' },
      { num: 30, code: '  @UseGuards(JwtAuthGuard, RolesGuard) // Guard attached', highlight: 'fixed' },
      { num: 31, code: '  @Delete(":id")' },
      { num: 32, code: '  async deleteUser(@Param("id") id: string) {' },
      { num: 33, code: '    return this.usersService.remove(id);' },
      { num: 34, code: '  }' },
      { num: 35, code: '}' },
    ],
    sinkExplanation: 'Mutating DELETE route handler has no authentication decorator.',
    remedyExplanation: 'Added JwtAuthGuard and RolesGuard decorators before endpoint.'
  }
];

export const SecurityInspector: React.FC = () => {
  const [selectedId, setSelectedId] = useState('sqli');
  const [isFixed, setIsFixed] = useState(false);

  const scenario = SCENARIOS.find((s) => s.id === selectedId) || SCENARIOS[0];
  const lines = isFixed ? scenario.fixedLines : scenario.vulnerableLines;

  return (
    <div className="w-full rounded-xl border border-[#1C2028] bg-[#0A0C10] shadow-2xl overflow-hidden font-mono text-xs">
      {/* Workbench Header */}
      <div className="flex items-center justify-between px-4 py-2.5 bg-[#0E1015] border-b border-[#1C2028] flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <div className="flex gap-1.5 mr-2">
            <span className="w-2.5 h-2.5 rounded-full bg-[#EF4444]/60" />
            <span className="w-2.5 h-2.5 rounded-full bg-[#F59E0B]/60" />
            <span className="w-2.5 h-2.5 rounded-full bg-[#10B981]/60" />
          </div>
          <span className="text-[#94A3B8] text-[11px] font-mono">
            {scenario.fileName}
          </span>
        </div>

        {/* Scenario Switcher */}
        <div className="flex items-center gap-1 bg-[#060709] p-0.5 rounded border border-[#1A1D24]">
          {SCENARIOS.map((s) => (
            <button
              key={s.id}
              onClick={() => {
                setSelectedId(s.id);
                setIsFixed(false);
              }}
              className={`px-2 py-1 rounded text-[10px] font-mono transition-colors ${
                selectedId === s.id
                  ? 'bg-[#181B24] text-white font-semibold'
                  : 'text-[#64748B] hover:text-[#CBD5E1]'
              }`}
            >
              {s.name}
            </button>
          ))}
        </div>
      </div>

      {/* Code Display Pane */}
      <div className="p-4 sm:p-5 bg-[#060709] overflow-x-auto min-h-[190px]">
        {lines.map((line) => {
          let lineBg = 'hover:bg-white/[0.02]';
          let indicator = null;

          if (!isFixed && line.highlight === 'source') {
            lineBg = 'bg-amber-500/10 text-amber-200 border-l-2 border-amber-400 pl-2';
            indicator = (
              <span className="ml-3 text-[10px] px-1.5 py-0.2 rounded bg-amber-950 text-amber-300 font-sans border border-amber-800/60">
                [Taint Source]
              </span>
            );
          } else if (!isFixed && line.highlight === 'flow') {
            lineBg = 'bg-sky-500/10 text-sky-200 border-l-2 border-sky-400 pl-2';
            indicator = (
              <span className="ml-3 text-[10px] px-1.5 py-0.2 rounded bg-sky-950 text-sky-300 font-sans border border-sky-800/60">
                [AST Flow]
              </span>
            );
          } else if (!isFixed && line.highlight === 'sink') {
            lineBg = 'bg-red-500/15 text-red-200 border-l-2 border-red-500 pl-2 font-semibold';
            indicator = (
              <span className="ml-3 text-[10px] px-1.5 py-0.2 rounded bg-red-950 text-red-300 font-sans border border-red-800/60">
                [Dangerous Sink: {scenario.ruleId}]
              </span>
            );
          } else if (isFixed && line.highlight === 'fixed') {
            lineBg = 'bg-emerald-500/10 text-emerald-200 border-l-2 border-emerald-400 pl-2 font-medium';
            indicator = (
              <span className="ml-3 text-[10px] px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-300 font-sans border border-emerald-800/60">
                [Remediated]
              </span>
            );
          }

          return (
            <div key={line.num} className={`flex items-center py-0.5 transition-colors ${lineBg}`}>
              <span className="w-8 text-[11px] text-[#475569] select-none text-right pr-3 flex-shrink-0">
                {line.num}
              </span>
              <pre className="font-mono text-xs whitespace-pre">
                <code>{line.code}</code>
              </pre>
              {indicator}
            </div>
          );
        })}
      </div>

      {/* Inspector Status Bar & Remediation Action */}
      <div className="p-3 sm:p-4 bg-[#0E1015] border-t border-[#1C2028] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          {isFixed ? (
            <div className="flex items-center gap-2 text-emerald-400 font-semibold">
              <CheckCircle2 size={16} />
              <span>0 Vulnerabilities Detected</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-950/60 border border-emerald-800/50 text-emerald-300">
                CLEAN AST
              </span>
            </div>
          ) : (
            <div className="flex items-center gap-2 text-red-400 font-semibold">
              <ShieldAlert size={16} />
              <span>{scenario.ruleId} · {scenario.cwe}</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-950/60 border border-red-800/50 text-red-300">
                {scenario.severity} RISK
              </span>
            </div>
          )}
        </div>

        {/* Toggle Remediation Button */}
        <button
          onClick={() => setIsFixed(!isFixed)}
          className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-sans font-medium transition-all ${
            isFixed
              ? 'bg-[#181B24] text-[#E2E8F0] border border-[#2D3340] hover:bg-[#202430]'
              : 'bg-[var(--color-primary)] text-[#08090B] font-bold hover:bg-[#1AFF53] shadow-[0_0_15px_rgba(0,255,65,0.25)]'
          }`}
        >
          {isFixed ? (
            <>
              <RefreshCw size={13} />
              <span>Reset to Vulnerable</span>
            </>
          ) : (
            <>
              <Wrench size={13} />
              <span>Apply BaseSec Remediation</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
};
