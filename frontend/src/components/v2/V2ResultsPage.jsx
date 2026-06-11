import React, { useState, useEffect } from "react";
import { 
  Activity, ShieldAlert, Globe, EyeOff, Key, 
  BookOpen, Clock, Copy, Check, ChevronRight, 
  ArrowLeft, FileText, Smartphone, ShieldCheck
} from "lucide-react";

export default function V2ResultsPage({ jobId, setPage }) {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState(null);
  const [activeTab, setActiveTab] = useState("timeline");
  const [copiedId, setCopiedId] = useState(null);

  useEffect(() => {
    const fetchResults = async () => {
      try {
        const res = await fetch(`http://127.0.0.1:8000/api/v2/jobs/${jobId}`);
        if (res.ok) {
          const detail = await res.json();
          setData(detail);
        }
      } catch (err) {
        console.error("Error fetching job detail:", err);
      } finally {
        setLoading(false);
      }
    };

    if (jobId) {
      fetchResults();
    }
  }, [jobId]);

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  if (loading) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center space-y-4 py-32 font-mono text-xs text-slate-500">
        <div className="w-8 h-8 border-2 border-[#007A8E]/10 border-t-[#007A8E] rounded-full animate-spin" />
        <span className="uppercase tracking-[0.2em] animate-pulse">Loading Sandbox Telemetry Results...</span>
      </div>
    );
  }

  if (!data || !data.job) {
    return (
      <div className="bracket-card p-10 text-center text-slate-400 font-mono text-xs bg-[#0d1217]">
        <p>Forensic job details could not be retrieved.</p>
        <button 
          onClick={() => setPage("v2-upload")}
          className="mt-4 px-4 py-2 rounded-xl bg-slate-900 border border-slate-800 text-[#007A8E] hover:bg-slate-850"
        >
          Return to Sandbox
        </button>
      </div>
    );
  }

  const { job, events, report } = data;
  const isMalicious = job.verdict === "malicious";
  const isSuspicious = job.verdict === "suspicious";

  // Filter events by tab types
  const networkEvents = events.filter(e => e.event_type === "network_request" || e.event_type === "dns_query");
  const evasionEvents = events.filter(e => e.event_type.startsWith("evasion_"));
  const otherEvents = events.filter(e => !["network_request", "dns_query"].includes(e.event_type) && !e.event_type.startsWith("evasion_"));

  return (
    <div className="w-full flex flex-col space-y-6 relative z-10 py-2 mx-auto animate-fade-in">
      
      {/* Top Navigation */}
      <div className="flex items-center justify-between">
        <button 
          onClick={() => setPage("v2-upload")}
          className="flex items-center space-x-2 px-3 py-1.5 rounded-xl border border-white/[0.02] bg-[#0d1217] hover:bg-[#131920] text-slate-400 hover:text-white transition-all text-[10px] font-mono cursor-pointer"
        >
          <ArrowLeft className="w-3.5 h-3.5 text-[#007A8E]" />
          <span>BACK TO DEPLOYER</span>
        </button>

        {report && (
          <button 
            onClick={() => setPage("v2-report")}
            className="flex items-center space-x-2 px-4 py-1.5 rounded-xl bg-[#007A8E]/10 border border-[#007A8E]/40 hover:bg-[#007A8E]/25 text-[10px] font-mono text-white transition-all cursor-pointer shadow-[0_4px_15px_rgba(0,122,142,0.15)]"
          >
            <FileText className="w-3.5 h-3.5 text-[#007A8E]" />
            <span>VIEW AI INVESTIGATION REPORT</span>
          </button>
        )}
      </div>

      {/* Target Profile Card */}
      <div className="bracket-card p-6 bg-[#0d1217] flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
        <div className="space-y-1.5 min-w-0">
          <div className="text-micro-label uppercase tracking-widest text-[#007A8E]">Forensic Target Assessment (v2)</div>
          <h2 className="text-lg font-bold text-white truncate font-sans">{job.filename}</h2>
          <div className="flex flex-wrap items-center gap-3 text-[9.5px] font-mono text-slate-500">
            <span>PKG: {job.package_name || "unknown"}</span>
            <span>•</span>
            <span>SHA256: {job.sha256.slice(0, 16)}...</span>
            <span>•</span>
            <span>SIZE: {(job.file_size / 1024).toFixed(1)} KB</span>
          </div>
        </div>

        {/* Verdict Badge Group */}
        <div className="flex items-center space-x-6 flex-shrink-0">
          <div className="text-left">
            <span className="text-[8px] font-mono text-slate-500 block uppercase tracking-widest">Malware Family</span>
            <span className="text-xs font-bold text-white font-mono">{job.malware_family || "Benign"}</span>
          </div>

          <div className="text-left border-l border-white/[0.04] pl-6">
            <span className="text-[8px] font-mono text-slate-500 block uppercase tracking-widest">Risk Assessment</span>
            <div className="flex items-center space-x-2 mt-0.5">
              <span className={`px-2 py-0.5 rounded text-[9px] font-bold font-mono border uppercase ${
                isMalicious ? "bg-red-500/10 text-red-400 border-red-500/20" :
                isSuspicious ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/20" :
                "bg-[#2C5F2D]/10 text-[#5B9C7D] border-[#2C5F2D]/20"
              }`}>
                {job.verdict || "CLEAN"}
              </span>
              <span className="text-sm font-extrabold text-white font-mono">{job.risk_score}%</span>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs Menu */}
      <div className="flex border-b border-white/[0.02] bg-[#090d12]/50 p-1 rounded-xl">
        {[
          { key: "timeline", name: "Timeline Trace", icon: Clock },
          { key: "network", name: "Network Activity", icon: Globe },
          { key: "evasion", name: "Evasion Attempts", icon: EyeOff },
          { key: "iocs", name: "Extracted IOCs", icon: Key },
          { key: "mitre", name: "MITRE ATT&CK", icon: BookOpen }
        ].map(t => {
          const Icon = t.icon;
          const isActive = activeTab === t.key;
          return (
            <button
              key={t.key}
              onClick={() => setActiveTab(t.key)}
              className={`flex-1 flex items-center justify-center space-x-2 py-2.5 rounded-xl text-[10px] font-mono transition-all cursor-pointer ${
                isActive 
                  ? "bg-[#131920] text-[#007A8E] border border-white/[0.04] font-semibold" 
                  : "text-slate-400 hover:text-white"
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">{t.name}</span>
            </button>
          );
        })}
      </div>

      {/* Tab Contents Frame */}
      <div className="w-full">
        {/* Timeline Tab */}
        {activeTab === "timeline" && (
          <div className="space-y-4">
            <div className="text-micro-label">TELEMETRY TIMELINE CHRONOLOGY</div>
            {events.length === 0 ? (
              <div className="bracket-card p-10 text-center text-slate-500 font-mono text-xs bg-[#0d1217]">
                No runtime telemetry events recorded.
              </div>
            ) : (
              <div className="relative border-l border-[#007A8E]/10 pl-6 ml-4 space-y-6 py-2">
                {events.map((ev, idx) => {
                  const elapsedSecs = (ev.elapsed_ms / 1000).toFixed(2);
                  return (
                    <div key={ev.id} className="relative group">
                      {/* Timeline dot */}
                      <span className={`absolute -left-[31px] top-1.5 w-2.5 h-2.5 rounded-full border-2 ${
                        ev.is_suspicious 
                          ? "bg-red-500 border-red-950 scale-110 shadow-[0_0_8px_rgba(239,68,68,0.5)]" 
                          : "bg-[#007A8E] border-[#070b0f]"
                      }`} />
                      
                      {/* Event row card */}
                      <div className="bracket-card p-4 bg-[#0d1217] border border-white/[0.01] hover:border-white/[0.03] transition-all flex flex-col md:flex-row md:items-center justify-between gap-4">
                        <div className="space-y-1">
                          <div className="flex items-center space-x-2">
                            <span className="text-[10px] font-bold text-white font-mono uppercase">{ev.event_type.replace("_", " ")}</span>
                            <span className="text-[8px] font-mono text-slate-500">elapsed: {elapsedSecs}s</span>
                            {ev.is_suspicious && (
                              <span className="px-1 py-0.5 rounded text-[7px] font-bold font-mono bg-red-500/10 text-red-400 border border-red-500/20">SUSPICIOUS</span>
                            )}
                          </div>
                          <p className="text-[10.5px] text-slate-350 font-mono leading-relaxed bg-slate-950/40 p-2 rounded border border-white/[0.02]">
                            {JSON.stringify(ev.payload)}
                          </p>
                        </div>

                        <div className="flex items-center space-x-4 flex-shrink-0 text-right">
                          <div className="text-left md:text-right">
                            <span className="text-[8px] font-mono text-slate-500 block uppercase">Source</span>
                            <span className="text-[9.5px] font-mono text-[#007A8E] uppercase">{ev.source}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* Network Tab */}
        {activeTab === "network" && (
          <div className="space-y-4">
            <div className="text-micro-label">INTERCEPTED NETWORK OPERATIONS</div>
            {networkEvents.length === 0 ? (
              <div className="bracket-card p-10 text-center text-slate-500 font-mono text-xs bg-[#0d1217]">
                No outbound network requests captured.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left font-mono text-[10px]">
                  <thead>
                    <tr className="border-b border-white/[0.03] text-slate-500 uppercase tracking-wider">
                      <th className="py-2.5 px-3">Timestamp</th>
                      <th className="py-2.5 px-3">Type</th>
                      <th className="py-2.5 px-3">Method</th>
                      <th className="py-2.5 px-3">Endpoint Target</th>
                      <th className="py-2.5 px-3">Source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {networkEvents.map((ev) => (
                      <tr key={ev.id} className="border-b border-white/[0.01] hover:bg-white/[0.01] transition-colors">
                        <td className="py-3 px-3 text-slate-500">{new Date(ev.timestamp).toLocaleTimeString()}</td>
                        <td className="py-3 px-3">
                          <span className={`px-1.5 py-0.5 rounded text-[8px] font-bold ${
                            ev.event_type === "dns_query" ? "bg-purple-500/10 text-purple-400" : "bg-[#007A8E]/10 text-cyan-400"
                          }`}>
                            {ev.event_type.toUpperCase()}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-white font-bold">{ev.payload.method || "—"}</td>
                        <td className="py-3 px-3 text-slate-300 break-all max-w-md">{ev.payload.url || ev.payload.domain}</td>
                        <td className="py-3 px-3 text-slate-400">{ev.source.toUpperCase()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Evasion Tab */}
        {activeTab === "evasion" && (
          <div className="space-y-4">
            <div className="text-micro-label">ANTI-ANALYSIS & EVASION DETECTIONS</div>
            {evasionEvents.length === 0 ? (
              <div className="bracket-card p-10 text-center text-slate-500 font-mono text-xs bg-[#0d1217]">
                No anti-sandbox / anti-debugger checks triggered during execution.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {evasionEvents.map((ev) => (
                  <div key={ev.id} className="bracket-card p-4.5 bg-[#0d1217] space-y-3">
                    <div className="flex items-center justify-between border-b border-white/[0.02] pb-2">
                      <span className="text-[10px] font-bold text-yellow-500 font-mono uppercase">
                        {ev.event_type.replace("_", " ").toUpperCase()}
                      </span>
                      <span className="text-[8px] font-mono text-[#007A8E]">BYPASSED</span>
                    </div>
                    <div className="space-y-1 text-[9.5px] font-mono">
                      <div className="flex justify-between"><span className="text-slate-500">Query Trigger:</span> <span className="text-white">{ev.payload.check_type || "Build check"}</span></div>
                      <div className="flex justify-between"><span className="text-slate-500">Captured Value:</span> <span className="text-slate-350">{ev.payload.indicator || "isDebuggerConnected"}</span></div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* IOCs Tab */}
        {activeTab === "iocs" && (
          <div className="space-y-4">
            <div className="text-micro-label">EXTRACTED INDICATORS OF COMPROMISE</div>
            {!job.iocs || job.iocs.length === 0 ? (
              <div className="bracket-card p-10 text-center text-slate-500 font-mono text-xs bg-[#0d1217]">
                No high-confidence IOCs extracted from execution logs.
              </div>
            ) : (
              <div className="grid grid-cols-1 gap-3">
                {job.iocs.map((ioc, idx) => (
                  <div key={idx} className="bracket-card p-3.5 bg-[#0d1217] flex items-center justify-between font-mono text-[10px]">
                    <div className="flex items-center space-x-3 min-w-0">
                      <span className={`px-2 py-0.5 rounded text-[8px] font-bold uppercase ${
                        ioc.type === "url" || ioc.type === "domain" ? "bg-cyan-500/10 text-cyan-400" :
                        ioc.type === "ip" ? "bg-purple-500/10 text-purple-400" :
                        ioc.type === "phone_number" ? "bg-yellow-500/10 text-yellow-400" :
                        "bg-slate-800 text-slate-400"
                      }`}>
                        {ioc.type}
                      </span>
                      <span className="text-white truncate max-w-lg select-text">{ioc.value}</span>
                    </div>

                    <button
                      onClick={() => copyToClipboard(ioc.value, idx)}
                      className="p-1.5 rounded-lg border border-white/[0.02] bg-[#070b0f] hover:bg-slate-900 transition-all text-slate-400 hover:text-white"
                      title="Copy to clipboard"
                    >
                      {copiedId === idx ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* MITRE Tab */}
        {activeTab === "mitre" && (
          <div className="space-y-4">
            <div className="text-micro-label">MITRE ATT&CK MOBILE TECHNIQUES REGISTERED</div>
            {!job.mitre_mappings || job.mitre_mappings.length === 0 ? (
              <div className="bracket-card p-10 text-center text-slate-500 font-mono text-xs bg-[#0d1217]">
                No adversarial tactics registered in current behavioral findings.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {job.mitre_mappings.map((m, idx) => (
                  <div key={idx} className="bracket-card p-4 bg-[#0d1217] space-y-3 flex flex-col justify-between border border-white/[0.01]">
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-bold text-white font-mono tracking-wider">{m.technique}</span>
                        <span className="px-1.5 py-0.5 rounded text-[8px] font-mono bg-[#007A8E]/10 text-[#007A8E] border border-[#007A8E]/20">{m.id}</span>
                      </div>
                      <div className="text-[8.5px] font-mono text-slate-500 uppercase">Tactic: {m.tactic}</div>
                    </div>
                    
                    <div className="bg-slate-950/40 p-2.5 rounded border border-white/[0.02] text-[9.5px] font-mono text-slate-300">
                      <span className="text-[#007A8E] font-semibold block mb-1">EVIDENCE:</span>
                      {m.evidence}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

    </div>
  );
}
