import { Routes, Route, Link, useLocation } from 'react-router-dom';
import Landing from './pages/Landing';
import Features from './pages/Features';
import Changelog from './pages/Changelog';
import { Terminal } from 'lucide-react';

function App() {
  const location = useLocation();

  const navLinks = [
    { name: 'Overview', path: '/' },
    { name: 'Live Demo', path: '/features' },
    { name: 'Changelog', path: '/changelog' },
  ];

  return (
    <div className="min-h-screen flex flex-col relative text-[var(--color-foreground)]">
      {/* Refined developer grid background */}
      <div className="dev-bg" aria-hidden="true" />

      {/* Header */}
      <header className="border-b border-[#1E232B] bg-[#090A0C]/85 backdrop-blur-md sticky top-0 z-50 transition-colors">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <Link to="/" className="flex items-center gap-3 group">
              <div className="w-8 h-8 rounded-lg bg-[#14171E] border border-[#1E2430] flex items-center justify-center p-1 group-hover:border-[var(--color-primary)]/50 transition-colors">
                <img 
                  src="./solologo.png" 
                  alt="BaseSec" 
                  className="w-full h-full object-contain filter group-hover:drop-shadow-[0_0_8px_rgba(0,255,65,0.6)] transition-all" 
                />
              </div>
              <span className="font-heading font-bold text-lg tracking-tight text-white flex items-center gap-1.5">
                Base<span className="text-[var(--color-primary)]">Sec</span>
              </span>
            </Link>

            {/* Navigation links */}
            <nav className="hidden md:flex items-center gap-1 bg-[#101217] p-1 rounded-lg border border-[#1C2028]">
              {navLinks.map((link) => {
                const isActive = location.pathname === link.path;
                return (
                  <Link
                    key={link.path}
                    to={link.path}
                    className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
                      isActive
                        ? 'text-white bg-[#1A1E27] font-semibold'
                        : 'text-[var(--color-muted)] hover:text-white hover:bg-white/[0.04]'
                    }`}
                  >
                    {link.name}
                  </Link>
                );
              })}
            </nav>

            {/* Right actions */}
            <div className="flex items-center gap-3">
              <Link 
                to="/features"
                className="hidden sm:inline-flex items-center gap-1.5 text-xs font-mono text-[var(--color-muted)] hover:text-white px-2.5 py-1.5 rounded-md hover:bg-white/[0.04] transition-colors"
              >
                <Terminal size={13} className="text-[var(--color-primary)]" />
                <span>CLI v0.1.7</span>
              </Link>
              
              <a
                href="https://github.com/tavotsu/BaseSec"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-lg border border-[#1E232B] bg-[#12151D] hover:bg-[#1A1E28] hover:border-[#2D3340] text-white transition-all shadow-sm active:scale-95"
              >
                <svg className="w-3.5 h-3.5 fill-current" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
                <span>GitHub</span>
              </a>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 flex flex-col">
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/features" element={<Features />} />
          <Route path="/changelog" element={<Changelog />} />
        </Routes>
      </main>

      {/* Footer */}
      <footer className="border-t border-[#1E232B] py-12 mt-auto bg-[#090A0C]/90 backdrop-blur-md z-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-3">
              <div className="w-6 h-6 rounded bg-[#14171E] border border-[#1E232B] p-0.5">
                <img src="./solologo.png" alt="BaseSec" className="w-full h-full object-contain" />
              </div>
              <span className="font-heading text-sm font-bold tracking-tight text-white">
                Base<span className="text-[var(--color-primary)]">Sec</span>
              </span>
              <span className="text-xs text-[var(--color-muted)] font-mono ml-2 border-l border-[#1E232B] pl-3">
                Static Application Security Testing for JS &amp; TS
              </span>
            </div>

            <nav className="flex items-center gap-6 text-xs text-[var(--color-muted)] font-medium">
              <Link to="/" className="hover:text-[var(--color-primary)] transition-colors">Overview</Link>
              <Link to="/features" className="hover:text-[var(--color-primary)] transition-colors">Live Demo</Link>
              <Link to="/changelog" className="hover:text-[var(--color-primary)] transition-colors">Changelog</Link>
              <a href="https://github.com/tavotsu/BaseSec" target="_blank" rel="noreferrer" className="hover:text-[var(--color-primary)] transition-colors">Repository</a>
              <a href="https://github.com/Tavotsu/BaseSec/issues" target="_blank" rel="noreferrer" className="hover:text-[var(--color-primary)] transition-colors">Issues</a>
            </nav>

            <div className="text-xs text-[var(--color-muted)] font-mono">
              MIT License · Tavotsu
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
