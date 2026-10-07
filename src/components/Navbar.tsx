import React from 'react';
import { Shield, Search, List, Smartphone, Eye, FileText, BarChart3 } from 'lucide-react';

export type TabType = 'detector' | 'apk' | 'similarity' | 'threats' | 'takedowns' | 'benchmarks';

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
    { id: 'detector', label: 'Threat Scanner', icon: Search, desc: 'URL, SMS & File Ingestion' },
    { id: 'apk', label: 'APK Malice Lab', icon: Smartphone, desc: 'Android App Inspector' },
    { id: 'similarity', label: 'Visual Comparison', icon: Eye, desc: 'Fake Page Clone Diff' },
    { id: 'threats', label: 'Threat Feed', icon: List, badge: `${threatCount}`, desc: 'Active Incident Queue' },
    { id: 'takedowns', label: 'Takedowns', icon: FileText, desc: 'CERT-In & NPCI Notices' },
    { id: 'benchmarks', label: 'Benchmarks', icon: BarChart3, desc: 'Model Performance' },
  ] as const;

  return (
    <header className="sticky top-0 z-30 border-b border-slate-200 bg-white/95 backdrop-blur-md shadow-xs">
      <div className="max-w-7xl mx-auto px-4 sm:px-6">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <div
            className="flex items-center space-x-3 cursor-pointer select-none"
            onClick={() => setActiveTab('detector')}
          >
            <div className="w-9 h-9 rounded-lg bg-indigo-600 flex items-center justify-center shadow-xs">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center space-x-1.5">
                <span className="font-bold text-base text-slate-900 tracking-tight">
                  PhishNet
                </span>
                <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-indigo-50 text-indigo-700 border border-indigo-100 font-mono">
                  v2.0
                </span>
              </div>
              <p className="text-[11px] text-slate-500 font-medium">Fake UPI & Payment Fraud Defense</p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="flex items-center space-x-1.5 overflow-x-auto py-1">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as TabType)}
                  className={`flex items-center space-x-1.5 px-3 py-2 rounded-lg text-xs font-medium whitespace-nowrap transition-all ${
                    isActive
                      ? 'bg-indigo-50 text-indigo-700 font-semibold border border-indigo-200 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                  }`}
                >
                  <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-indigo-600' : 'text-slate-500'}`} />
                  <span>{tab.label}</span>
                  {'badge' in tab && tab.badge && (
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded-full font-semibold ${
                      isActive ? 'bg-indigo-600 text-white' : 'bg-slate-200 text-slate-700'
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
