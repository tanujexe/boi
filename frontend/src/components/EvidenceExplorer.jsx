import React, { useState, useEffect } from "react";
import { 
  FileCode, 
  Link2, 
  FileSearch, 
  Info,
  ChevronRight,
  ShieldAlert,
  Copy,
  Check
} from "lucide-react";

export default function EvidenceExplorer({ jobId, setPage }) {
  const [job, setJob] = useState(null);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("permissions");
  const [copiedIndex, setCopiedIndex] = useState(null);

  const fetchJobData = async () => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/jobs/${jobId}`);
      if (res.ok) {
        const data = await res.json();
        setJob(data.job);
        setFindings(data.findings);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (jobId) {
      fetchJobData();
    } else {
      setLoading(false);
    }
  }, [jobId]);

  const copyToClipboard = (text, index) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  // Bespoke syntax highlighter for Smali Dalvik bytecode utilizing custom palette
  const highlightSmali = (code) => {
    if (!code) return "";
    let html = code
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
      
    // SMALI opcodes (Steel Blue)
    const opcodes = [
      "invoke-virtual", "invoke-direct", "invoke-static", "invoke-interface", "invoke-super",
      "const-string", "const/4", "const", "move-result", "move-result-object",
      "iget-object", "iput-object", "return-void", "return-object", "return",
      "new-instance", "check-cast", "monitor-enter", "monitor-exit", "goto"
    ];
    
    opcodes.forEach(op => {
      const reg = new RegExp(`\\b(${op})\\b`, "g");
      html = html.replace(reg, '<span class="text-[#4B9CD3] font-semibold">$1</span>');
    });

    // Android descriptor classes (Teal Landroid/...;)
    html = html.replace(/(L[a-zA-Z0-9_/]+;)/g, '<span class="text-[#007A8E] font-mono">$1</span>');
    
    // Method arrows (->methodName in Sky Blue)
    html = html.replace(/(-&gt;[a-zA-Z0-9_]+)/g, '<span class="text-[#A9D6E5] font-semibold">$1</span>');

    // registers (v0, p1, etc in slate)
    html = html.replace(/\b([vp]\d+)\b/g, '<span class="text-slate-500 font-mono">$1</span>');

    // strings (mint-white)
    html = html.replace(/("[^"]*")/g, '<span class="text-[#E8F5F2] font-semibold">$1</span>');

    return <div dangerouslySetInnerHTML={{ __html: html }} />;
  };

  if (!jobId) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center space-y-4 min-h-[50vh] text-center">
        <FileSearch className="w-12 h-12 text-[#007A8E] animate-pulse" />
        <h2 className="text-lg font-bold font-mono text-[#E8F5F2] uppercase tracking-wider">No Active Target Session</h2>
        <p className="text-xs text-slate-500 max-w-sm">
          Please upload an APK file on the Upload page or select a sample from history to view decompiled evidence details.
        </p>
        <button 
          onClick={() => setPage("upload")}
          className="mt-2 px-4 py-2 bg-[#007A8E]/10 text-[#007A8E] hover:bg-[#007A8E] hover:text-white border border-[#007A8E]/20 hover:border-transparent rounded-xl text-xs font-mono transition-all btn-premium-click cursor-pointer"
        >
          Go to Upload Desk
        </button>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center space-y-4 min-h-[50vh]">
        <div className="relative">
          <div className="w-10 h-10 border-4 border-white/[0.04] border-t-[#007A8E] rounded-full animate-spin" />
          <div className="absolute inset-0 bg-[#007A8E]/10 rounded-full blur-md" />
        </div>
        <span className="text-xs font-mono text-[#007A8E] tracking-wider uppercase animate-pulse">Loading Evidence Packages...</span>
      </div>
    );
  }

  const permissionsList = findings.filter(f => f.type === "permission");
  const apisList = findings.filter(f => f.type === "api");
  const urlsList = findings.filter(f => f.type === "url");
  const obfuscationList = findings.filter(f => f.type === "obfuscation");

  return (
    <div className="flex-1 flex flex-col space-y-8 select-none p-4 md:p-6 max-w-7xl mx-auto w-full animate-fade-in">
      
      {/* Title Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-900 pb-5">
        <div>
          <h2 className="text-xl font-bold text-[#E8F5F2] font-sans flex items-center space-x-2.5">
            <FileSearch className="w-5 h-5 text-[#007A8E]" />
            <span className="uppercase tracking-wide font-semibold">Evidence Explorer</span>
          </h2>
          <p className="text-xs text-slate-500 font-mono mt-1.5 leading-relaxed">
            Decompiled variables, Android Manifest configurations, and classes.dex hardcoded links.
          </p>
        </div>
      </div>

      {/* Capsule Pill Navigation */}
      <div className="flex border border-white/[0.03] bg-slate-950/45 p-1 rounded-xl w-fit max-w-full overflow-x-auto whitespace-nowrap scrollbar-none space-x-1">
        <button
          onClick={() => setActiveTab("permissions")}
          className={`px-4 py-2 text-[10px] font-semibold font-mono rounded-lg transition-all btn-premium-click ${
            activeTab === "permissions" 
              ? "bg-[#131920] border border-white/[0.04] text-white shadow-[0_4px_15px_rgba(0,0,0,0.6)]" 
              : "border border-transparent text-slate-500 hover:text-slate-350"
          }`}
        >
          Manifest Permissions ({permissionsList.length})
        </button>
        <button
          onClick={() => setActiveTab("apis")}
          className={`px-4 py-2 text-[10px] font-semibold font-mono rounded-lg transition-all btn-premium-click ${
            activeTab === "apis" 
              ? "bg-[#131920] border border-white/[0.04] text-white shadow-[0_4px_15px_rgba(0,0,0,0.6)]" 
              : "border border-transparent text-slate-500 hover:text-slate-350"
          }`}
        >
          Bytecode APIs ({apisList.length})
        </button>
        <button
          onClick={() => setActiveTab("urls")}
          className={`px-4 py-2 text-[10px] font-semibold font-mono rounded-lg transition-all btn-premium-click ${
            activeTab === "urls" 
              ? "bg-[#131920] border border-white/[0.04] text-white shadow-[0_4px_15px_rgba(0,0,0,0.6)]" 
              : "border border-transparent text-slate-500 hover:text-slate-350"
          }`}
        >
          Network Domains ({urlsList.length})
        </button>
        {obfuscationList.length > 0 && (
          <button
            onClick={() => setActiveTab("obfuscation")}
            className={`px-4 py-2 text-[10px] font-semibold font-mono rounded-lg transition-all btn-premium-click ${
              activeTab === "obfuscation" 
                ? "bg-[#131920] border border-white/[0.04] text-white shadow-[0_4px_15px_rgba(0,0,0,0.6)]" 
                : "border border-transparent text-slate-500 hover:text-slate-350"
            }`}
          >
            Obfuscations ({obfuscationList.length})
          </button>
        )}
      </div>

      {/* Tab Panels */}
      <div className="flex-1 min-h-[40vh]">
        {activeTab === "permissions" && (
          <div className="space-y-5 animate-fade-in">
            <div className="bracket-card p-4 bg-slate-950/20 flex items-start space-x-3 text-xs text-slate-400 leading-relaxed font-mono">
              <Info className="w-4 h-4 text-[#007A8E] flex-shrink-0 mt-0.5" />
              <span>Manifest parameters determine raw Android OS boundaries. Permissions flagged critical indicate access model risk.</span>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {permissionsList.length === 0 ? (
                <div className="col-span-2 text-xs text-slate-600 italic py-10 text-center font-mono">No dangerous permissions flagged.</div>
              ) : (
                permissionsList.map((p) => (
                  <div key={p.id} className="bracket-card p-5 bg-[#0d1217] flex flex-col space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-semibold text-white font-mono truncate max-w-[250px]" title={p.title}>{p.title}</span>
                      <span className={`text-[8px] font-bold font-mono px-2 py-0.5 rounded border ${
                        p.severity === "Critical" ? "text-[#007A8E] bg-[#007A8E]/10 border-[#007A8E]/20" : 
                        "text-[#4B9CD3] bg-[#4B9CD3]/10 border-[#4B9CD3]/20"
                      }`}>
                        {p.severity}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 font-sans leading-relaxed">{p.description}</p>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {activeTab === "apis" && (
          <div className="space-y-5 animate-fade-in">
            <div className="bracket-card p-4 bg-slate-950/20 flex items-start space-x-3 text-xs text-slate-400 leading-relaxed font-mono">
              <FileCode className="w-4 h-4 text-[#007A8E] flex-shrink-0 mt-0.5" />
              <span>Bytecode APIs map static call references identified in bytecode class methods. These capture accessibility abuse and system persistence commands.</span>
            </div>

            <div className="space-y-4">
              {apisList.length === 0 ? (
                <div className="text-xs text-slate-600 italic py-10 text-center font-mono">No sensitive Dalvik API signatures matched.</div>
              ) : (
                apisList.map((api, idx) => (
                  <div key={api.id} className="bracket-card p-5 bg-[#0d1217] flex flex-col space-y-3.5">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="text-xs font-semibold text-white font-mono">{api.title}</span>
                        <span className="px-1.5 py-0.5 rounded text-[8px] font-mono bg-slate-900 border border-slate-850 text-slate-500 uppercase">DALVIK_REF</span>
                      </div>
                      <span className={`text-[9px] font-bold font-mono px-2 py-0.5 rounded border ${
                        api.severity === "Critical" ? "text-[#007A8E] bg-[#007A8E]/10 border-[#007A8E]/20" :
                        "text-[#4B9CD3] bg-[#4B9CD3]/10 border-[#4B9CD3]/20"
                      }`}>
                        {api.severity}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 font-sans leading-relaxed">{api.description}</p>
                    
                    {api.evidence_snippet && (
                      <div className="rounded-xl border border-slate-900 bg-[#070b0f] overflow-hidden shadow-2xl relative group/code select-text">
                        {/* IDE Header */}
                        <div className="flex items-center justify-between border-b border-slate-900 bg-slate-950/80 px-4 py-2">
                          <div className="flex items-center space-x-4">
                            <div className="flex items-center space-x-1.5 flex-shrink-0">
                              <span className="w-2.5 h-2.5 rounded-full bg-slate-850" />
                              <span className="w-2.5 h-2.5 rounded-full bg-slate-850" />
                              <span className="w-2.5 h-2.5 rounded-full bg-slate-850" />
                            </div>
                            <span className="text-[9px] text-slate-600 font-mono tracking-wider">classes.dex // decompiled_indicator.smali</span>
                          </div>
                          <button
                            onClick={() => copyToClipboard(api.evidence_snippet, idx)}
                            className="p-1.5 rounded border border-transparent hover:border-slate-800 hover:bg-slate-900 text-slate-500 hover:text-white transition-all cursor-pointer btn-premium-click"
                            title="Copy code snippet"
                          >
                            {copiedIndex === idx ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                        {/* IDE editor text */}
                        <div className="p-4 font-mono text-[10px] text-slate-355 overflow-x-auto leading-relaxed">
                          <pre>
                            <code>
                              {api.evidence_snippet.split('\n').map((line, lIdx) => (
                                <div key={lIdx} className="flex items-start space-x-3">
                                  <span className="text-slate-700 w-4 text-right select-none pr-1.5">{lIdx + 1}</span>
                                  <span className="font-mono text-left">{highlightSmali(line)}</span>
                                </div>
                              ))}
                            </code>
                          </pre>
                        </div>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* Network URL tab */}
        {activeTab === "urls" && (
          <div className="space-y-5 animate-fade-in">
            <div className="bracket-card p-4 bg-slate-950/20 flex items-start space-x-3 text-xs text-slate-400 leading-relaxed font-mono">
              <Link2 className="w-4 h-4 text-[#007A8E] flex-shrink-0 mt-0.5" />
              <span>Extracted host domains representing callback endpoints for Command & Control (C2) servers.</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {urlsList.length === 0 ? (
                <div className="col-span-2 text-xs text-slate-600 italic py-10 text-center font-mono">No external host callback links found in DEX classes.</div>
              ) : (
                urlsList.map((url) => (
                  <div key={url.id} className="bracket-card p-5 bg-[#0d1217] flex flex-col justify-between space-y-3">
                    <div className="flex items-start justify-between gap-4">
                      <span className="text-[11px] font-semibold text-white font-mono break-all leading-normal select-text">{url.evidence_snippet}</span>
                      <span className="text-[8px] font-bold font-mono px-2 py-0.5 rounded text-amber-400 bg-amber-500/10 border border-amber-500/20 flex-shrink-0">
                        {url.severity}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 font-sans leading-relaxed">{url.description}</p>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* Obfuscations tab */}
        {activeTab === "obfuscation" && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 animate-fade-in">
            {obfuscationList.map((obf) => (
              <div key={obf.id} className="bracket-card p-5 bg-[#0d1217] flex flex-col justify-between space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-semibold text-white font-mono">{obf.title}</span>
                    <span className="px-1.5 py-0.5 rounded text-[8px] font-mono bg-slate-900 border border-slate-850 text-slate-500 uppercase">PACKER</span>
                  </div>
                  <span className="text-[8px] font-bold font-mono px-2 py-0.5 rounded text-amber-400 bg-amber-500/10 border border-amber-500/20">
                    {obf.severity}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-sans leading-relaxed">{obf.description}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Navigation Footer */}
      <div className="flex justify-end pt-4 border-t border-slate-900">
        <button 
          onClick={() => setPage("threat-intel")}
          className="flex items-center space-x-1.5 px-4 py-2 bg-[#007A8E]/10 text-[#007A8E] hover:bg-[#007A8E] hover:text-white rounded-lg text-xs font-semibold font-mono transition-all border border-[#007A8E]/20 hover:border-transparent btn-premium-click cursor-pointer"
        >
          <span>Proceed to Threat Intelligence Matrix</span>
          <ChevronRight className="w-4 h-4" />
        </button>
      </div>

    </div>
  );
}
