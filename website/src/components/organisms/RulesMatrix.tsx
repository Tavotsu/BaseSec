import { useState } from 'react';
import { ChevronRight, Search } from 'lucide-react';

interface RuleItem {
  id: string;
  category: 'SQLI' | 'XSS' | 'AUTH' | 'CMDI' | 'SEC' | 'DEP' | 'FRAMEWORK';
  cwe: string;
  name: string;
  framework: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  badSnippet: string;
  remedySnippet: string;
}

const RULES_DATA: RuleItem[] = [
  {
    id: 'SQLI-001',
    category: 'SQLI',
    cwe: 'CWE-89',
    name: 'SQL Injection via Tainted Parameter',
    framework: 'Express / TypeORM / pg',
    severity: 'HIGH',
    badSnippet: "db.query(`SELECT * FROM users WHERE id = '${userId}'`)",
    remedySnippet: "db.query('SELECT * FROM users WHERE id = ?', [userId])"
  },
  {
    id: 'REACT-001',
    category: 'XSS',
    cwe: 'CWE-79',
    name: 'DOM XSS via dangerouslySetInnerHTML',
    framework: 'React / Next.js',
    severity: 'HIGH',
    badSnippet: "<div dangerouslySetInnerHTML={{ __html: userBio }} />",
    remedySnippet: "<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userBio) }} />"
  },
  {
    id: 'VUE-001',
    category: 'XSS',
    cwe: 'CWE-79',
    name: 'Unsanitized v-html Binding in SFC',
    framework: 'Vue 3 / Nuxt',
    severity: 'HIGH',
    badSnippet: '<div v-html="route.query.content"></div>',
    remedySnippet: '<div v-text="route.query.content"></div>'
  },
  {
    id: 'SVELTE-001',
    category: 'XSS',
    cwe: 'CWE-79',
    name: 'Raw HTML Injection in Template',
    framework: 'SvelteKit / Svelte',
    severity: 'HIGH',
    badSnippet: '{@html $page.url.searchParams.get("msg")}',
    remedySnippet: '{$page.url.searchParams.get("msg")}'
  },
  {
    id: 'AUTH-001',
    category: 'AUTH',
    cwe: 'CWE-306',
    name: 'Missing Authentication Guard on Mutating Route',
    framework: 'NestJS / Express',
    severity: 'CRITICAL',
    badSnippet: "router.delete('/users/:id', deleteHandler)",
    remedySnippet: "router.delete('/users/:id', requireAuth, deleteHandler)"
  },
  {
    id: 'CMDI-001',
    category: 'CMDI',
    cwe: 'CWE-78',
    name: 'Command Injection via Child Process',
    framework: 'Node.js / Fastify',
    severity: 'CRITICAL',
    badSnippet: 'exec(`git checkout ${branch}`)',
    remedySnippet: 'execFile("git", ["checkout", branch])'
  },
  {
    id: 'SEC-001',
    category: 'SEC',
    cwe: 'CWE-798',
    name: 'Hardcoded API Token / Private Key Exposure',
    framework: 'All JS/TS Runtimes',
    severity: 'CRITICAL',
    badSnippet: 'const STRIPE_KEY = "sk_live_51M..."',
    remedySnippet: 'const STRIPE_KEY = process.env.STRIPE_SECRET_KEY'
  },
  {
    id: 'PRISMA-001',
    category: 'SQLI',
    cwe: 'CWE-89',
    name: 'Unescaped Query in $queryRawUnsafe',
    framework: 'Prisma ORM',
    severity: 'HIGH',
    badSnippet: 'await prisma.$queryRawUnsafe(`SELECT * FROM ${table}`)',
    remedySnippet: 'await prisma.$queryRaw`SELECT * FROM Users WHERE id = ${id}`'
  },
  {
    id: 'DEP-001',
    category: 'DEP',
    cwe: 'CWE-1395',
    name: 'Known Critical Vulnerability in package.json',
    framework: 'npm / pnpm / yarn / bun',
    severity: 'CRITICAL',
    badSnippet: '"dependencies": { "jsonwebtoken": "<8.5.1" }',
    remedySnippet: '"dependencies": { "jsonwebtoken": "^9.0.0" }'
  }
];

export const RulesMatrix: React.FC = () => {
  const [activeCategory, setActiveCategory] = useState<string>('ALL');
  const [expandedRule, setExpandedRule] = useState<string | null>('SQLI-001');
  const [searchQuery, setSearchQuery] = useState('');

  const categories = [
    { id: 'ALL', label: 'All Categories' },
    { id: 'SQLI', label: 'SQL Injection' },
    { id: 'XSS', label: 'DOM & XSS' },
    { id: 'AUTH', label: 'Authentication' },
    { id: 'CMDI', label: 'Command Injection' },
    { id: 'SEC', label: 'Secrets & Tokens' },
    { id: 'DEP', label: 'Supply Chain' },
  ];

  const filteredRules = RULES_DATA.filter((rule) => {
    const matchesCat = activeCategory === 'ALL' || rule.category === activeCategory;
    const matchesQuery = 
      rule.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      rule.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      rule.framework.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCat && matchesQuery;
  });

  return (
    <div className="w-full rounded-2xl border border-[#1C2028] bg-[#0A0C10] p-6 lg:p-8 shadow-2xl">
      {/* Category Pills & Search */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-[#1C2028]">
        <div className="flex items-center gap-1.5 flex-wrap">
          {categories.map((cat) => (
            <button
              key={cat.id}
              onClick={() => setActiveCategory(cat.id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
                activeCategory === cat.id
                  ? 'bg-[var(--color-primary)] text-[#08090B] font-bold shadow-sm'
                  : 'bg-[#12151D] text-[#94A3B8] hover:text-white border border-[#1A1E26]'
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>

        {/* Search Input */}
        <div className="relative min-w-[220px]">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#64748B]" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter 65 rules by ID, CWE..."
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-[#0E1015] border border-[#1C2028] text-xs font-mono text-[#F8FAFC] placeholder-[#475569] focus:outline-none focus:border-[var(--color-primary)]/50"
          />
        </div>
      </div>

      {/* Rules Registry List */}
      <div className="divide-y divide-[#161922] mt-2">
        {filteredRules.map((rule) => {
          const isExpanded = expandedRule === rule.id;

          return (
            <div key={rule.id} className="py-3.5 transition-colors">
              <div
                onClick={() => setExpandedRule(isExpanded ? null : rule.id)}
                className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 cursor-pointer hover:bg-white/[0.02] p-2 rounded-lg transition-colors select-none"
              >
                <div className="flex items-center gap-3">
                  <span className="font-mono text-xs font-bold text-[var(--color-primary)] px-2 py-0.5 rounded bg-[var(--color-primary)]/10 border border-[var(--color-primary)]/20">
                    {rule.id}
                  </span>
                  <span className="text-xs font-mono text-[#64748B] hidden md:inline">
                    {rule.cwe}
                  </span>
                  <span className="text-sm font-sans font-semibold text-[#F1F5F9]">
                    {rule.name}
                  </span>
                </div>

                <div className="flex items-center gap-3">
                  <span className="text-xs font-mono text-[#94A3B8] text-right">
                    {rule.framework}
                  </span>
                  <span
                    className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                      rule.severity === 'CRITICAL'
                        ? 'bg-red-950/60 text-red-300 border-red-800/60'
                        : 'bg-amber-950/60 text-amber-300 border-amber-800/60'
                    }`}
                  >
                    {rule.severity}
                  </span>
                  <ChevronRight
                    size={16}
                    className={`text-[#64748B] transition-transform duration-200 ${
                      isExpanded ? 'rotate-90 text-white' : ''
                    }`}
                  />
                </div>
              </div>

              {/* Expanded Inspection Drawer */}
              {isExpanded && (
                <div className="mt-3 ml-2 sm:ml-4 pl-4 border-l-2 border-[#202530] space-y-3 pt-1 pb-2">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {/* Vulnerable Pattern */}
                    <div className="p-3 rounded-lg bg-[#060709] border border-red-950/50">
                      <span className="text-[11px] font-mono text-red-400 font-semibold block mb-1.5">
                        ✕ Vulnerable Flow Sink
                      </span>
                      <pre className="font-mono text-xs text-red-200 overflow-x-auto p-2 bg-[#0A0C10] rounded border border-[#161922]">
                        <code>{rule.badSnippet}</code>
                      </pre>
                    </div>

                    {/* Remediation Snippet */}
                    <div className="p-3 rounded-lg bg-[#060709] border border-emerald-950/50">
                      <span className="text-[11px] font-mono text-emerald-400 font-semibold block mb-1.5">
                        ✓ BaseSec Suggested Remediation
                      </span>
                      <pre className="font-mono text-xs text-emerald-200 overflow-x-auto p-2 bg-[#0A0C10] rounded border border-[#161922]">
                        <code>{rule.remedySnippet}</code>
                      </pre>
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
