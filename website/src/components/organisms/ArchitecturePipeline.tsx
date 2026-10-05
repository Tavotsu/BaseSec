export const ArchitecturePipeline: React.FC = () => {
  const steps = [
    {
      step: '01',
      title: 'File Discovery & SFC Blanking',
      detail: 'Fast-glob locates .js, .ts, .vue, .svelte. extractSfcScript blanks non-script markup with matching newlines, ensuring 1:1 AST line accuracy with zero compiler plugins.',
      tag: 'fast-glob · SFC extractor'
    },
    {
      step: '02',
      title: 'TypeScript Compiler API',
      detail: 'Feeds sanitized buffers into ts.createSourceFile(). Generates full abstract syntax trees with accurate node positions, parent references, and identifier bindings.',
      tag: 'ts.createSourceFile · No regex'
    },
    {
      step: '03',
      title: 'Parallel Worker Threads',
      detail: 'Distributes AST analysis across Node.js worker_threads. Reaches 78+ files per second on multi-core workstations without blocking the CLI event loop.',
      tag: 'worker_threads · Zero blocking'
    },
    {
      step: '04',
      title: 'Deep Taint Propagation Graph',
      detail: 'Identifies untrusted sources (req.query, req.body, location.search) and walks assignment chains until finding a sanitizer or a dangerous sink (db.query, exec, innerHTML).',
      tag: 'Source → Flow → Sink'
    },
    {
      step: '05',
      title: 'SARIF & CI/CD Formats',
      detail: 'Produces compliant SARIF v2.1.0 JSON natively uploaded to the GitHub Security tab, alongside terminal tables, HTML summaries, and automated exit codes.',
      tag: 'GitHub Security Tab · CI exit 1'
    }
  ];

  const frameworks = [
    {
      category: 'Node.js Backend Runtimes',
      items: [
        { name: 'Express', hook: 'req.query, req.body, route handlers' },
        { name: 'NestJS', hook: '@Body(), @Query(), @UseGuards() guards' },
        { name: 'Fastify', hook: 'request.body, reply.send() error leakage' },
        { name: 'Koa', hook: 'ctx.request.query, ctx.throw() safety' },
      ]
    },
    {
      category: 'Frontend & Meta-Frameworks',
      items: [
        { name: 'React / Next.js', hook: 'useSearchParams, dangerouslySetInnerHTML' },
        { name: 'Vue 3 / Nuxt', hook: 'v-html, $route, .vue SFC <script>' },
        { name: 'Svelte / SvelteKit', hook: '{@html}, $page.url, .svelte SFC' },
        { name: 'Angular', hook: 'bypassSecurityTrustHtml, ActivatedRoute' },
      ]
    },
    {
      category: 'Database Engines & ORMs',
      items: [
        { name: 'Prisma', hook: '$queryRawUnsafe, raw SQL interpolation' },
        { name: 'Mongoose', hook: '$where evaluations, .lean() object checks' },
        { name: 'TypeORM', hook: 'query(), createQueryBuilder where clauses' },
      ]
    }
  ];

  return (
    <div className="w-full space-y-12">
      {/* Step by Step Pipeline Strip */}
      <div className="rounded-2xl border border-[#1C2028] bg-[#0A0C10] p-6 lg:p-8">
        <h3 className="text-xl font-heading font-bold text-white mb-2 tracking-tight">
          Deterministic Pipeline Execution
        </h3>
        <p className="text-sm text-[#94A3B8] max-w-2xl mb-8 leading-relaxed">
          How BaseSec processes an enterprise codebase without cloud servers, external dependencies, or AST degradation.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-4 relative">
          {steps.map((st) => (
            <div 
              key={st.step} 
              className="p-4 rounded-xl bg-[#0E1016] border border-[#1A1E26] flex flex-col justify-between relative group hover:border-[var(--color-primary)]/40 transition-colors"
            >
              <div>
                <div className="flex items-center justify-between mb-3">
                  <span className="font-mono text-xs font-bold text-[var(--color-primary)]">
                    {st.step}
                  </span>
                  <span className="w-1.5 h-1.5 rounded-full bg-[#1C2028] group-hover:bg-[var(--color-primary)] transition-colors" />
                </div>
                <h4 className="text-xs font-sans font-bold text-white mb-2 leading-snug">
                  {st.title}
                </h4>
                <p className="text-[11px] text-[#94A3B8] leading-relaxed">
                  {st.detail}
                </p>
              </div>
              <div className="mt-4 pt-3 border-t border-[#161820] text-[10px] font-mono text-[#64748B]">
                {st.tag}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Framework Support Grid */}
      <div className="rounded-2xl border border-[#1C2028] bg-[#0A0C10] p-6 lg:p-8">
        <div className="flex items-center justify-between mb-6 flex-wrap gap-4">
          <div>
            <h3 className="text-xl font-heading font-bold text-white tracking-tight">
              12 Framework Context Resolvers
            </h3>
            <p className="text-sm text-[#94A3B8] mt-1">
              Exact import verification prevents false positives. Detects decorators, request wrappers, and raw sinks natively.
            </p>
          </div>
          <span className="text-xs font-mono px-3 py-1 rounded bg-[var(--color-primary)]/10 text-[var(--color-primary)] border border-[var(--color-primary)]/20">
            Zero False Positives Threshold
          </span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {frameworks.map((fwGroup) => (
            <div key={fwGroup.category} className="p-5 rounded-xl bg-[#0E1016] border border-[#1A1E26]">
              <h4 className="text-xs font-mono uppercase font-bold text-[var(--color-primary)] tracking-wider mb-4 pb-2 border-b border-[#181B22]">
                {fwGroup.category}
              </h4>
              <div className="space-y-3">
                {fwGroup.items.map((fw) => (
                  <div key={fw.name} className="flex flex-col text-xs font-mono">
                    <span className="font-semibold text-white">
                      {fw.name}
                    </span>
                    <span className="text-[11px] text-[#64748B] font-sans mt-0.5">
                      {fw.hook}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
