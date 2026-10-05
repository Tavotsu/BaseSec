import { useState, useEffect, useRef } from 'react';
import { ShieldCheck, Cpu, Star, Download, Flame } from 'lucide-react';

interface Stats {
  updatedAt: string;
  github: {
    stars: number;
    forks: number;
    openIssues: number;
  };
  npm: {
    weeklyDownloads: number;
    monthlyDownloads: number;
  };
}

function useCountUp(target: number, duration = 1200, active = false) {
  const [value, setValue] = useState(0);

  useEffect(() => {
    if (!active || target === 0) return;
    const startTime = performance.now();
    let frameId: number;

    const step = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setValue(Math.floor(eased * target));
      if (progress < 1) {
        frameId = requestAnimationFrame(step);
      }
    };

    frameId = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frameId);
  }, [target, duration, active]);

  if (!active) return 0;
  return target === 0 ? 0 : value;
}

interface MetricCardProps {
  icon: React.ReactNode;
  label: string;
  value: number | string;
  sublabel: string;
  active: boolean;
  numeric?: boolean;
}

const MetricCard: React.FC<MetricCardProps> = ({ icon, label, value, sublabel, active, numeric = true }) => {
  const numValue = typeof value === 'number' ? value : 0;
  const count = useCountUp(numValue, 1200, active);

  return (
    <div className="flex flex-col p-4 rounded-xl bg-[#0F1117] border border-[#1E232B] hover:border-[var(--color-primary)]/30 transition-all duration-200 group">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-mono uppercase tracking-wider text-[var(--color-muted)] group-hover:text-white transition-colors">
          {label}
        </span>
        <div className="text-[var(--color-primary)] opacity-70 group-hover:opacity-100 transition-opacity">
          {icon}
        </div>
      </div>
      <div className="flex items-baseline gap-1.5">
        <span className="font-heading text-2xl lg:text-3xl font-bold text-white tracking-tight">
          {numeric ? count.toLocaleString() : value}
        </span>
      </div>
      <span className="text-[11px] font-mono text-[var(--color-muted)]/70 mt-1">
        {sublabel}
      </span>
    </div>
  );
};

export const StatsBar: React.FC = () => {
  const [stats, setStats] = useState<Stats | null>(null);
  const [visible, setVisible] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch('./stats.json')
      .then((r) => {
        if (!r.ok) throw new Error('Not found');
        return r.json();
      })
      .then(setStats)
      .catch(() => {
        // Fallback placeholder data
        setStats({
          updatedAt: new Date().toISOString(),
          github: { stars: 128, forks: 14, openIssues: 2 },
          npm: { weeklyDownloads: 1420, monthlyDownloads: 5800 }
        });
      });
  }, []);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) setVisible(true);
      },
      { threshold: 0.1 }
    );
    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);

  return (
    <div ref={ref} className="w-full">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 lg:gap-4">
        <MetricCard
          icon={<ShieldCheck size={18} />}
          label="Security Rules"
          value={65}
          sublabel="11 categories (CVE-mapped)"
          active={visible}
        />
        <MetricCard
          icon={<Cpu size={18} />}
          label="Scan Throughput"
          value="78+"
          sublabel="Files/sec via TS Compiler API"
          active={visible}
          numeric={false}
        />
        <MetricCard
          icon={<Flame size={18} />}
          label="Frameworks"
          value={12}
          sublabel="Node.js, React, Vue, Svelte..."
          active={visible}
        />
        <MetricCard
          icon={stats?.github.stars ? <Star size={18} /> : <Download size={18} />}
          label={stats?.github.stars ? "GitHub Stars" : "Test Suites"}
          value={stats?.github.stars || 527}
          sublabel={stats?.github.stars ? "Open source community" : "Automated security tests"}
          active={visible}
        />
      </div>
    </div>
  );
};
