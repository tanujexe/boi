import React from "react";
import { 
  ShieldAlert, 
  LayoutDashboard, 
  FileSearch, 
  Fingerprint, 
  FileText, 
  TrendingUp, 
  Terminal, 
  Link2,
  X,
  Activity
} from "lucide-react";

export default function Sidebar({ currentPage, jobId, setPage, resetUpload, sidebarOpen, setSidebarOpen }) {
  const navItems = [
    {
      name: "Dashboard",
      icon: LayoutDashboard,
      pageKey: "dashboard",
      disabled: false
    },
    {
      name: "Evidence Explorer",
      icon: FileSearch,
      pageKey: "evidence",
      disabled: false
    },
    {
      name: "Threat Intelligence",
      icon: Fingerprint,
      pageKey: "threat-intel",
      disabled: false
    },
    {
      name: "Investigation Report",
      icon: FileText,
      pageKey: "report",
      disabled: false
    }
  ];

  const globalItems = [
    {
      name: "Campaigns Triage",
      icon: TrendingUp,
      pageKey: "campaigns",
      disabled: false
    },
    {
      name: "API Keys",
      icon: Terminal,
      pageKey: "api-keys",
      disabled: false
    }
  ];

  const v2Items = [
    {
      name: "Sandbox Deployer",
      icon: Terminal,
      pageKey: "v2-upload",
      disabled: false
    },
    {
      name: "Telemetry Trace",
      icon: Activity,
      pageKey: "v2-results",
      disabled: !jobId
    },
    {
      name: "AI Investigation",
      icon: FileText,
      pageKey: "v2-report",
      disabled: !jobId
    }
  ];

  return (
    <aside className={`w-64 border-r border-white/[0.02] bg-[#0a0e13] flex flex-col h-screen fixed left-0 top-0 select-none z-35 transition-transform duration-300 lg:translate-x-0 ${sidebarOpen ? "translate-x-0" : "-translate-x-full"} shadow-[15px_0_40px_rgba(0,0,0,0.95)]`}>
      
      {/* Brand Header */}
      <div className="p-6 border-b border-white/[0.02] flex items-center justify-between">
        <div className="flex items-center space-x-3 cursor-pointer" onClick={resetUpload}>
          <div className="relative">
            <div className="absolute inset-0 bg-[#007A8E]/25 rounded-xl blur-md animate-pulse" />
            <div className="relative bg-[#07080c] p-2.5 rounded-xl border border-[#007A8E]/30 flex items-center justify-center">
              <ShieldAlert className="w-5 h-5 text-[#007A8E]" />
            </div>
          </div>
          <div>
            <h1 className="text-xs font-bold tracking-[0.18em] text-[#E8F5F2] font-mono uppercase">SENTINEL<span className="text-[#007A8E]">_AI</span></h1>
            <span className="text-[7.5px] text-slate-500 font-mono tracking-[0.22em] uppercase block mt-0.5">FORENSIC CORE</span>
          </div>
        </div>
        
        {/* Mobile close button */}
        <button
          onClick={() => setSidebarOpen(false)}
          className="lg:hidden p-1.5 rounded-lg text-slate-450 hover:text-white hover:bg-slate-900/50 transition-all btn-premium-click"
          aria-label="Close sidebar"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Navigation Panels */}
      <div className="flex-1 px-4 py-6 space-y-8 overflow-y-auto">
        
        {/* Active Analysis Info Card */}
        {jobId ? (
          <div className="bracket-card rounded-xl p-3.5 space-y-1 bg-[#0d1217]">
            <div className="text-[7.5px] text-[#007A8E] font-mono uppercase tracking-[0.22em] flex items-center justify-between">
              <span>Active Target</span>
              <span className="w-1.5 h-1.5 rounded-full bg-[#007A8E] animate-pulse" />
            </div>
            <div className="text-[9.5px] font-mono truncate text-slate-350" title={jobId}>
              ID: {jobId}
            </div>
          </div>
        ) : (
          <div className="border border-dashed border-slate-900 rounded-xl p-4 text-center bg-slate-950/10">
            <span className="text-[8px] text-slate-600 font-mono uppercase tracking-[0.2em] block">No Active Target</span>
            <button 
              onClick={resetUpload}
              className="text-[8.5px] text-[#007A8E]/80 hover:text-[#007A8E] font-mono underline mt-1 transition-all btn-premium-click cursor-pointer"
            >
              Analyze APK
            </button>
          </div>
        )}

        {/* Target Analysis Workspace */}
        <div className="space-y-2.5">
          <span className="px-3 text-[8px] uppercase font-bold tracking-[0.22em] text-slate-500 font-mono block">WORKSPACE</span>
          <nav className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentPage === item.pageKey;
              
              if (item.disabled) {
                return (
                  <div
                    key={item.name}
                    className="flex items-center space-x-3 px-3 py-2 rounded-xl text-slate-700 cursor-not-allowed text-xs font-sans opacity-25 select-none"
                  >
                    <Icon className="w-3.5 h-3.5 flex-shrink-0" />
                    <span>{item.name}</span>
                  </div>
                );
              }

              return (
                <button
                  key={item.name}
                  onClick={() => setPage(item.pageKey)}
                  className={`w-full flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-xs transition-all text-left btn-premium-click group relative border ${
                    isActive
                      ? "bg-[#131920] border-white/[0.04] text-[#E8F5F2] font-semibold shadow-[0_4px_15px_rgba(0,0,0,0.6)]"
                      : "border-transparent text-slate-400 hover:text-[#E8F5F2] hover:bg-white/[0.01]"
                  }`}
                >
                  <Icon className={`w-4 h-4 flex-shrink-0 transition-all ${isActive ? "text-[#007A8E]" : "text-slate-500 group-hover:scale-105 group-hover:text-white"}`} />
                  <span className="font-sans">{item.name}</span>
                  {isActive && (
                    <span className="absolute left-0 top-1/3 bottom-1/3 w-0.5 rounded-full bg-[#007A8E]" />
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Sandbox v2 Workspace */}
        <div className="space-y-2.5">
          <span className="px-3 text-[8px] uppercase font-bold tracking-[0.22em] text-slate-500 font-mono block">DYNAMIC SANDBOX (v2)</span>
          <nav className="space-y-1">
            {v2Items.map((item) => {
              const Icon = item.icon;
              const isActive = currentPage === item.pageKey;
              
              if (item.disabled) {
                return (
                  <div
                    key={item.name}
                    className="flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-slate-700 cursor-not-allowed text-xs font-sans opacity-25 select-none"
                  >
                    <Icon className="w-4 h-4 flex-shrink-0" />
                    <span>{item.name}</span>
                  </div>
                );
              }

              return (
                <button
                  key={item.name}
                  onClick={() => setPage(item.pageKey)}
                  className={`w-full flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-xs transition-all text-left btn-premium-click group relative border ${
                    isActive
                      ? "bg-[#131920] border-white/[0.04] text-[#E8F5F2] font-semibold shadow-[0_4px_15px_rgba(0,0,0,0.6)]"
                      : "border-transparent text-slate-400 hover:text-[#E8F5F2] hover:bg-white/[0.01]"
                  }`}
                >
                  <Icon className={`w-4 h-4 flex-shrink-0 transition-all ${isActive ? "text-[#007A8E]" : "text-slate-500 group-hover:scale-105 group-hover:text-white"}`} />
                  <span className="font-sans">{item.name}</span>
                  {isActive && (
                    <span className="absolute left-0 top-1/3 bottom-1/3 w-0.5 rounded-full bg-[#007A8E]" />
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Global Hub Workspace */}
        <div className="space-y-2.5">
          <span className="px-3 text-[8px] uppercase font-bold tracking-[0.22em] text-slate-500 font-mono block">GLOBAL CORE</span>
          <nav className="space-y-1">
            {globalItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentPage === item.pageKey;

              return (
                <button
                  key={item.name}
                  onClick={() => setPage(item.pageKey)}
                  className={`w-full flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-xs transition-all text-left btn-premium-click group relative border ${
                    isActive
                      ? "bg-[#131920] border-white/[0.04] text-[#E8F5F2] font-semibold shadow-[0_4px_15px_rgba(0,0,0,0.6)]"
                      : "border-transparent text-slate-400 hover:text-[#E8F5F2] hover:bg-white/[0.01]"
                  }`}
                >
                  <Icon className={`w-4 h-4 flex-shrink-0 transition-all ${isActive ? "text-[#007A8E]" : "text-slate-500 group-hover:scale-105 group-hover:text-white"}`} />
                  <span className="font-sans">{item.name}</span>
                  {isActive && (
                    <span className="absolute left-0 top-1/3 bottom-1/3 w-0.5 rounded-full bg-[#007A8E]" />
                  )}
                </button>
              );
            })}
          </nav>
        </div>
      </div>

      {/* Footer System Status */}
      <div className="p-4 border-t border-white/[0.02] bg-[#0a0e13] flex items-center justify-between text-[9px] text-slate-500 font-mono">
        <div className="flex items-center space-x-2">
          <span className="relative flex h-1.5 w-1.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#2C5F2D] opacity-75"></span>
            <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-[#2C5F2D]"></span>
          </span>
          <span className="tracking-widest uppercase text-slate-650">SOC_ACTIVE</span>
        </div>
        <button 
          onClick={resetUpload} 
          className="hover:text-white flex items-center space-x-1 cursor-pointer font-mono transition-all border border-white/[0.02] hover:border-white/[0.08] px-2 py-0.5 rounded bg-[#0b0f14] btn-premium-click"
        >
          <Link2 className="w-2.5 h-2.5 text-[#007A8E]" />
          <span>Upload</span>
        </button>
      </div>
    </aside>
  );
}
