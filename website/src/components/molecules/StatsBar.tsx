import React, { useState, useEffect, useRef } from 'react';

interface Stats {
  updatedAt: string;
  github: {
    stars: number;
    forks: number;
    openIssues: number;
    views: { count: number; uniques: number };
    clones: { count: number; uniques: number };
  };
  npm: {
    weeklyDownloads: number;
    monthlyDownloads: number;
  };
}

function useCountUp(target: number, duration = 1500, active = false) {
  const [value, setValue] = useState(0);

  useEffect(() => {
    if (!active || target === 0) { setValue(target); return; }
    const startTime = performance.now();

    function step(now: number) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setValue(Math.floor(eased * target));
      if (progress < 1) requestAnimationFrame(step);
    }

    requestAnimationFrame(step);
  }, [target, duration, active]);

  return value;
}

interface StatCardProps {
  label: string;
  value: number;
  sublabel?: string;
  active: boolean;
  suffix?: string;
}

const StatCard: React.FC<StatCardProps> = ({ label, value, sublabel, active, suffix = '' }) => {
  const count = useCountUp(value, 1400, active);

  return (
    <div className="flex flex-col items-center gap-1 px-6 py-4 border border-[var(--color-border)] bg-[var(--color-secondary)] group hover:border-[var(--color-primary)]/50 transition-colors duration-300 relative overflow-hidden">
      <div className="absolute bottom-0 left-0 h-[1px] bg-[var(--color-primary)] w-0 group-hover:w-full transition-all duration-500"></div>
      <span className="font-heading text-2xl font-bold text-[var(--color-primary)]">
        {count.toLocaleString()}{suffix}
      </span>
      <span className="font-mono text-xs text-white uppercase tracking-widest">{label}</span>
      {sublabel && (
        <span className="font-mono text-[10px] text-[var(--color-foreground)]/40 uppercase tracking-wider">{sublabel}</span>
      )}
    </div>
  );
};

export const StatsBar: React.FC = () => {
  const [stats, setStats] = useState<Stats | null>(null);
  const [visible, setVisible] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch('./stats.json')
      .then((r) => r.json())
      .then(setStats)
      .catch(() => setStats(null));
  }, []);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => { if (entry.isIntersecting) setVisible(true); },
      { threshold: 0.2 }
    );
    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);

  if (!stats) return null;

  return (
    <div ref={ref} className="w-full">
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-px bg-[var(--color-border)]">
        <StatCard label="npm / week" value={stats.npm.weeklyDownloads} active={visible} />
        <StatCard label="npm / month" value={stats.npm.monthlyDownloads} active={visible} />
        <StatCard label="Stars" value={stats.github.stars} active={visible} />
      </div>
      <p className="text-[10px] font-mono text-[var(--color-foreground)]/30 text-right mt-1 pr-1">
        Updated {new Date(stats.updatedAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
      </p>
    </div>
  );
};
