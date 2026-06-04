import { Routes, Route, Link } from 'react-router-dom';
import Landing from './pages/Landing';
import Features from './pages/Features';
import Changelog from './pages/Changelog';


function App() {
  return (
    <div className="min-h-screen flex flex-col relative">
      {/* Animated background layers */}
      <div className="cyber-bg"></div>
      <div className="cyber-particles" aria-hidden="true">
        {Array.from({ length: 10 }).map((_, i) => (
          <span key={i} style={{
            '--x': `${10 + i * 9}%`,
            '--sz': `${i % 3 === 0 ? '3px' : i % 2 === 0 ? '2px' : '1.5px'}`,
            '--dur': `${10 + (i * 1.7).toFixed(1)}s`,
            '--d': `-${(i * 1.3).toFixed(1)}s`,
          } as React.CSSProperties}></span>
        ))}
      </div>

      <header className="border-b border-[var(--color-border)] bg-[var(--color-background)]/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <Link to="/" className="flex items-center gap-3 group">
              <img src="./solologo.png" alt="BaseSec Logo" className="w-8 h-8 drop-shadow-[0_0_8px_rgba(0,255,65,0.8)] group-hover:animate-pulse" />
              <span className="font-heading font-bold text-xl tracking-wider text-glow uppercase">BaseSec</span>
            </Link>
            <nav className="flex gap-6">
              <Link to="/" className="text-sm uppercase tracking-widest hover:text-[var(--color-primary)] glitch-hover transition-colors">Home</Link>
              <Link to="/features" className="text-sm uppercase tracking-widest hover:text-[var(--color-primary)] glitch-hover transition-colors">Live Demo</Link>
              <Link to="/changelog" className="text-sm uppercase tracking-widest hover:text-[var(--color-primary)] glitch-hover transition-colors">Changelog</Link>
              <a href="https://github.com/tavotsu/BaseSec" target="_blank" rel="noreferrer" className="text-sm uppercase tracking-widest hover:text-[var(--color-primary)] glitch-hover transition-colors">GitHub</a>
            </nav>
          </div>
        </div>
      </header>

      <main className="flex-1 flex flex-col">
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/features" element={<Features />} />
          <Route path="/changelog" element={<Changelog />} />
        </Routes>
      </main>

      <footer className="border-t border-[var(--color-border)] py-10 mt-auto bg-[var(--color-background)]/90 backdrop-blur-sm z-10">
        <div className="max-w-7xl mx-auto px-4">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-3">
              <img src="./solologo.png" alt="BaseSec" className="w-7 h-7" />
              <span className="font-heading text-sm tracking-wider text-[var(--color-muted)] uppercase">BaseSec</span>
            </div>

            <nav className="flex items-center gap-8">
              <Link to="/" className="text-[10px] uppercase tracking-widest text-[var(--color-muted)] hover:text-[var(--color-primary)] transition-colors">Home</Link>
              <Link to="/changelog" className="text-[10px] uppercase tracking-widest text-[var(--color-muted)] hover:text-[var(--color-primary)] transition-colors">Changelog</Link>
              <a href="https://github.com/tavotsu/BaseSec" target="_blank" rel="noreferrer" className="text-[10px] uppercase tracking-widest text-[var(--color-muted)] hover:text-[var(--color-primary)] transition-colors">GitHub</a>
              <a href="https://github.com/Tavotsu/BaseSec/issues" target="_blank" rel="noreferrer" className="text-[10px] uppercase tracking-widest text-[var(--color-muted)] hover:text-[var(--color-primary)] transition-colors">Issues</a>
            </nav>

            <p className="text-[10px] text-[var(--color-muted)] tracking-widest uppercase font-mono">
              {new Date().getFullYear()} — Tavotsu
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
