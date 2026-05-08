import React from 'react';

interface FeatureCardProps {
  icon: React.ReactNode;
  title: string;
  description: string;
}

export const FeatureCard: React.FC<FeatureCardProps> = ({ icon, title, description }) => {
  return (
    <div className="border border-[var(--color-border)] bg-[var(--color-secondary)] p-6 hover:border-[var(--color-primary)]/60 transition-colors duration-300 group relative overflow-hidden">
      <div className="mb-4 text-[var(--color-primary)]">
        {icon}
      </div>
      <h3 className="font-heading text-base mb-2 text-white uppercase tracking-wider">{title}</h3>
      <p className="text-[var(--color-foreground)] text-sm leading-relaxed opacity-70">
        {description}
      </p>
      <div className="absolute bottom-0 left-0 h-[2px] bg-[var(--color-primary)] w-0 group-hover:w-full transition-all duration-500 ease-out shadow-[0_0_8px_var(--color-primary)]"></div>
    </div>
  );
};
