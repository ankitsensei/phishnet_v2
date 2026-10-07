import React from 'react';
import { Shield, Search, List, Network, FileText, BarChart2, Smartphone, Radio } from 'lucide-react';

export type TabType = 'detector' | 'apk' | 'ctstream' | 'threats' | 'graph' | 'takedowns' | 'benchmarks';

interface NavbarProps {
  activeTab: TabType;
  setActiveTab: (tab: TabType) => void;
  threatCount: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  threatCount
}) => {
  const tabs = [
    { id: 'detector', label: 'Scanner', icon: Search },
    { id: 'apk', label: 'APK Lab', icon: Smartphone },
    { id: 'ctstream', label: 'CT Stream', icon: Radio },
    { id: 'threats', label: 'Threat Feed', icon: List, badge: `${threatCount}` },
    { id: 'graph', label: 'Campaign Graph', icon: Network },
    { id: 'takedowns', label: 'Takedowns', icon: FileText },
    { id: 'benchmarks', label: 'Metrics', icon: BarChart2 },
  ] as const;

  return (
    <header className="sticky top-0 z-30 border-b border-[#222226] bg-[#000000]/95 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6">
        <div className="flex items-center justify-between h-14">
          {/* Logo */}
          <div
            className="flex items-center space-x-2.5 cursor-pointer select-none"
            onClick={() => setActiveTab('detector')}
          >
            <div className="w-7 h-7 rounded bg-white text-black flex items-center justify-center font-bold">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <span className="font-semibold text-sm text-white tracking-tight">PhishNet V2</span>
              <span className="text-[11px] text-[#71717a] ml-1.5 font-mono">Full-Stack Shield</span>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="flex items-center space-x-1 overflow-x-auto py-1">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as TabType)}
                  className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap transition-all ${
                    isActive
                      ? 'bg-white text-black font-semibold shadow-sm'
                      : 'text-[#888892] hover:text-white hover:bg-[#141416]'
                  }`}
                >
                  <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-black' : 'text-[#888892]'}`} />
                  <span>{tab.label}</span>
                  {'badge' in tab && tab.badge && (
                    <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded-full ${
                      isActive ? 'bg-[#222226] text-white' : 'bg-[#18181b] text-[#71717a]'
                    }`}>
                      {tab.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>
      </div>
    </header>
  );
};
