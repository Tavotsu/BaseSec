import React from 'react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'outline' | 'ghost' | 'destructive';
  size?: 'sm' | 'md' | 'lg';
  children: React.ReactNode;
}

export const Button: React.FC<ButtonProps> = ({ 
  variant = 'primary', 
  size = 'md',
  className = '', 
  children, 
  ...props 
}) => {
  const baseStyle = "inline-flex items-center justify-center font-medium transition-all duration-150 select-none rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-[#090A0C] active:scale-[0.98] disabled:opacity-50 disabled:pointer-events-none";
  
  const sizes = {
    sm: "px-3 py-1.5 text-xs gap-1.5",
    md: "px-4 py-2.5 text-sm gap-2",
    lg: "px-6 py-3 text-base gap-2.5"
  };

  const variants = {
    primary: "bg-[var(--color-primary)] text-[#090A0C] font-semibold hover:bg-[var(--color-primary-hover)] shadow-[0_0_20px_rgba(0,255,65,0.25)] hover:shadow-[0_0_25px_rgba(0,255,65,0.4)] border border-[var(--color-primary)]",
    secondary: "bg-[#16191F] text-[var(--color-foreground)] border border-[var(--color-border)] hover:border-[var(--color-primary)]/40 hover:bg-[#1E222A]",
    outline: "bg-transparent text-[var(--color-foreground)] border border-[var(--color-border)] hover:border-[var(--color-muted)] hover:bg-[#16191F]/50",
    ghost: "bg-transparent text-[var(--color-muted)] hover:text-white hover:bg-[#16191F]",
    destructive: "bg-red-950/40 text-red-400 border border-red-900/50 hover:bg-red-900/30 hover:border-red-700/60"
  };

  return (
    <button 
      className={`${baseStyle} ${sizes[size]} ${variants[variant]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
};
