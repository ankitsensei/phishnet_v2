import React from 'react';
import { Shield, Radio, Activity, Network, Eye, FileText, Smartphone, BarChart3, Search, Terminal } from 'lucide-react';

interface NavbarProps {
  activeTab: 'dashboard' | 'graph' | 'similarity' | 'ctlogs' | 'takedowns' | 'apk' | 'benchmarks' | 'sandbox';
  setActiveTab: (tab: 'dashboard' | 'graph' | 'similarity' | 'ctlogs' | 'takedowns' | 'apk' | 'benchmarks' | 'sandbox') => void;
  activeThreatCount: number;
  takedownCount: number;
  ctLogVelocity: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  activeThreatCount,
  takedownCount,
  ctLogVelocity
}) => {
  const navItems = [
    { id: 'dashboard', label: 'Operations Feed', icon: Activity },
    { id: 'graph', label: 'Campaign Graph', icon: Network },
    { id: 'similarity', label: 'Visual AI Engine', icon: Eye },
    { id: 'ctlogs', label: 'CT Log Crawler', icon: Radio, badge: `${ctLogVelocity}/s` },
    { id: 'takedowns', label: 'Takedown Generator', icon: FileText, badge: `${takedownCount}` },
    { id: 'apk', label: 'APK Trojan Lab', icon: Smartphone },
    { id: 'sandbox', label: 'Live Scanner', icon: Terminal },
    { id: 'benchmarks', label: 'Metrics & Recall', icon: BarChart3 },
  ] as const;

  return (
    <header className="sticky top-0 z-40 w-full border-b border-white/10 bg-[#070a10]/90 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand & Logo */}
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => setActiveTab('dashboard')}>
            <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 text-cyan-400 shadow-lg shadow-cyan-500/10">
              <Shield className="w-5 h-5 text-cyan-400" />
              <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
              </span>
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-display font-bold text-lg tracking-tight text-white">
                  PhishNet <span className="text-cyan-400 font-mono text-sm px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20">V2</span>
                </span>
                <span className="hidden md:inline-flex text-[10px] uppercase font-mono tracking-widest px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/20 text-rose-400">
                  Track 03 • UPI Shield
                </span>
              </div>
              <p className="text-[11px] text-slate-400 hidden sm:block">
                Scale Payment Phishing & Clone Intelligence Engine
              </p>
            </div>
          </div>

          {/* Quick Metrics Bar */}
          <div className="hidden xl:flex items-center space-x-4 px-3 py-1.5 rounded-lg bg-[#0c1017] border border-white/5 text-xs font-mono">
            <div className="flex items-center space-x-1.5">
              <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span>
              <span className="text-slate-400">Active Threats:</span>
              <span className="text-rose-400 font-semibold">{activeThreatCount}</span>
            </div>
            <div className="h-3 w-px bg-white/10" />
            <div className="flex items-center space-x-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
              <span className="text-slate-400">Takedowns:</span>
              <span className="text-emerald-400 font-semibold">{takedownCount}</span>
            </div>
            <div className="h-3 w-px bg-white/10" />
            <div className="flex items-center space-x-1.5">
              <span className="w-2 h-2 rounded-full bg-cyan-500"></span>
              <span className="text-slate-400">CT Ingest:</span>
              <span className="text-cyan-400 font-semibold">{ctLogVelocity} certs/s</span>
            </div>
          </div>

          {/* Action button */}
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setActiveTab('sandbox')}
              className="flex items-center space-x-2 px-3.5 py-1.5 rounded-lg text-xs font-medium bg-cyan-500/10 text-cyan-300 hover:bg-cyan-500/20 border border-cyan-500/30 transition-all shadow-sm shadow-cyan-500/20"
            >
              <Search className="w-3.5 h-3.5 text-cyan-400" />
              <span>Deep Scan URL / SMS</span>
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <nav className="flex space-x-1 overflow-x-auto py-2 border-t border-white/5 scrollbar-none">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id as any)}
                className={`flex items-center space-x-2 px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap transition-all duration-150 ${
                  isActive
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-white/5 border border-transparent'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
                {'badge' in item && item.badge && (
                  <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded-full ${
                    isActive ? 'bg-cyan-500/20 text-cyan-300' : 'bg-white/10 text-slate-400'
                  }`}>
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
};
