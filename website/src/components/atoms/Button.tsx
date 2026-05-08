import React from 'react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'destructive' | 'outline';
  children: React.ReactNode;
}

export const Button: React.FC<ButtonProps> = ({ variant = 'primary', className = '', children, ...props }) => {
  const baseStyle = "px-6 py-3 font-heading uppercase tracking-widest text-sm transition-all duration-300 relative overflow-hidden group";
  
  const variants = {
    primary: "bg-transparent text-[var(--color-primary)] border border-[var(--color-primary)] hover:bg-[var(--color-primary)]/10 neon-border",
    destructive: "bg-transparent text-[var(--color-destructive)] border border-[var(--color-destructive)] hover:bg-[var(--color-destructive)]/10 shadow-[0_0_5px_var(--color-destructive)]",
    outline: "bg-transparent text-[var(--color-foreground)] border border-[var(--color-border)] hover:border-[var(--color-foreground)] hover:text-white"
  };

  return (
    <button 
      className={`${baseStyle} ${variants[variant]} ${className}`}
      {...props}
    >
      <span className="relative z-10">{children}</span>
      {variant === 'primary' && (
        <div className="absolute top-0 -left-[100%] w-1/2 h-full bg-gradient-to-r from-transparent via-[var(--color-primary)]/20 to-transparent skew-x-12 group-hover:animate-[sweep_1s_ease-in-out_infinite]" />
      )}
    </button>
  );
};
