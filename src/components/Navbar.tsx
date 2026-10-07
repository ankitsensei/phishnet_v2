import React from 'react';
import { Shield, Radio, Activity, Network, Eye, FileText, Smartphone, BarChart3, Search, Terminal } from 'lucide-react';

interface NavbarProps {
  activeTab: 'sandbox' | 'dashboard' | 'graph' | 'similarity' | 'ctlogs' | 'takedowns' | 'apk' | 'benchmarks';
  setActiveTab: (tab: 'sandbox' | 'dashboard' | 'graph' | 'similarity' | 'ctlogs' | 'takedowns' | 'apk' | 'benchmarks') => void;
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
    { id: 'sandbox', label: 'Fake Source Detector', icon: Search, highlight: true },
    { id: 'dashboard', label: 'Operations Feed', icon: Activity },
    { id: 'graph', label: 'Campaign Graph', icon: Network },
    { id: 'similarity', label: 'Visual AI Studio', icon: Eye },
    { id: 'ctlogs', label: 'CT Log Crawler', icon: Radio, badge: `${ctLogVelocity}/s` },
    { id: 'takedowns', label: 'Takedown Generator', icon: FileText, badge: `${takedownCount}` },
    { id: 'apk', label: 'APK Trojan Lab', icon: Smartphone },
    { id: 'benchmarks', label: 'Metrics & Recall', icon: BarChart3 },
  ] as const;

  return (
    <header className="sticky top-0 z-40 w-full border-b border-[#27272a] bg-[#000000]/95 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand & Logo */}
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => setActiveTab('sandbox')}>
            <div className="flex items-center justify-center w-8 h-8 rounded bg-white text-black font-bold">
              <Shield className="w-4 h-4 text-black" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-base tracking-tight text-white">
                  PhishNet <span className="font-mono text-xs px-1.5 py-0.5 rounded bg-[#27272a] text-[#f4f4f5] border border-[#3f3f46]">V2</span>
                </span>
                <span className="hidden md:inline-flex text-[10px] uppercase font-mono tracking-widest px-2 py-0.5 rounded bg-[#18181b] border border-[#27272a] text-[#a1a1aa]">
                  Track 03 • UPI Shield
                </span>
              </div>
              <p className="text-[11px] text-[#71717a] hidden sm:block">
                Fake UPI & Payment Page and App Detection at Scale
              </p>
            </div>
          </div>

          {/* Quick Metrics Bar */}
          <div className="hidden xl:flex items-center space-x-4 px-3 py-1.5 rounded bg-[#09090b] border border-[#27272a] text-xs font-mono">
            <div className="flex items-center space-x-1.5">
              <span className="w-2 h-2 rounded-full bg-white"></span>
              <span className="text-[#71717a]">Active Clones:</span>
              <span className="text-white font-semibold">{activeThreatCount}</span>
            </div>
            <div className="h-3 w-px bg-[#27272a]" />
            <div className="flex items-center space-x-1.5">
              <span className="text-[#71717a]">Takedowns:</span>
              <span className="text-white font-semibold">{takedownCount}</span>
            </div>
            <div className="h-3 w-px bg-[#27272a]" />
            <div className="flex items-center space-x-1.5">
              <span className="text-[#71717a]">CT Rate:</span>
              <span className="text-white font-semibold">{ctLogVelocity} certs/s</span>
            </div>
          </div>

          {/* Direct Trigger */}
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setActiveTab('sandbox')}
              className="flex items-center space-x-2 px-3.5 py-1.5 rounded text-xs font-semibold bg-white text-black hover:bg-[#e4e4e7] transition-colors"
            >
              <Search className="w-3.5 h-3.5" />
              <span>Detect Source</span>
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <nav className="flex space-x-1 overflow-x-auto py-2 border-t border-[#27272a] scrollbar-none">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id as any)}
                className={`flex items-center space-x-2 px-3 py-1.5 rounded text-xs font-medium whitespace-nowrap transition-colors ${
                  isActive
                    ? 'bg-white text-black font-semibold'
                    : 'text-[#a1a1aa] hover:text-white hover:bg-[#18181b]'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-black' : 'text-[#a1a1aa]'}`} />
                <span>{item.label}</span>
                {'badge' in item && item.badge && (
                  <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded ${
                    isActive ? 'bg-[#27272a] text-white' : 'bg-[#18181b] text-[#71717a]'
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
