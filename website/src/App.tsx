import { Routes, Route, Link } from 'react-router-dom';
import Landing from './pages/Landing';
import Features from './pages/Features';


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
              <img src={`${import.meta.env.BASE_URL}solologo.png`} alt="BaseSec Logo" className="w-8 h-8 drop-shadow-[0_0_8px_rgba(0,255,65,0.8)] group-hover:animate-pulse" />
              <span className="font-heading font-bold text-xl tracking-wider text-glow uppercase">BaseSec</span>
            </Link>
            <nav className="flex gap-6">
              <Link to="/" className="text-sm uppercase tracking-widest hover:text-[var(--color-primary)] glitch-hover transition-colors">Home</Link>
              <Link to="/features" className="text-sm uppercase tracking-widest hover:text-[var(--color-primary)] glitch-hover transition-colors">Features</Link>
              <a href="https://github.com/tavotsu/BaseSec" target="_blank" rel="noreferrer" className="text-sm uppercase tracking-widest hover:text-[var(--color-primary)] glitch-hover transition-colors">GitHub</a>
            </nav>
          </div>
        </div>
      </header>

      <main className="flex-1 flex flex-col">
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/features" element={<Features />} />
        </Routes>
      </main>

      <footer className="border-t border-[var(--color-border)] py-8 mt-auto bg-[var(--color-background)]/90 backdrop-blur-sm z-10">
        <div className="max-w-7xl mx-auto px-4 text-center">
          <p className="text-[var(--color-muted)] text-xs uppercase tracking-widest">
            By Tavotsu - {new Date().getFullYear()}. Security first, questions later.
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;
