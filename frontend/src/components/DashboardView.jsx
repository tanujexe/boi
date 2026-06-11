import React, { useState, useEffect, useRef } from "react";
import { 
  ShieldAlert, 
  ChevronRight, 
  Cpu, 
  Clock, 
  Terminal, 
  AlertTriangle,
  FileText,
  Activity,
  Layers,
  Network
} from "lucide-react";
import {
  ResponsiveContainer,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar
} from "recharts";

export default function DashboardView({ jobId, setPage }) {
  const [job, setJob] = useState(null);
  const [findings, setFindings] = useState([]);
  const [wsLogs, setWsLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const consoleEndRef = useRef(null);

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

      // Connect to WebSocket server for log streaming
      const ws = new WebSocket(`ws://127.0.0.1:8000/api/ws/${jobId}`);
      
      ws.onmessage = (event) => {
        const payload = JSON.parse(event.data);
        if (payload.type === "LOG") {
          setWsLogs((prev) => [...prev, payload.message]);
        } else if (payload.type === "STATUS_CHANGE") {
          fetchJobData();
        }
      };

      return () => {
        ws.close();
      };
    } else {
      setLoading(false);
    }
  }, [jobId]);

  useEffect(() => {
    if (consoleEndRef.current) {
      consoleEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [wsLogs]);

  if (!jobId) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center space-y-4 min-h-[50vh] text-center">
        <ShieldAlert className="w-12 h-12 text-[#007A8E] animate-pulse" />
        <h2 className="text-lg font-bold font-mono text-[#E8F5F2] uppercase tracking-wider">No Active Incident</h2>
        <p className="text-xs text-slate-500 max-w-sm">
          Select an Android package signature from history or upload a target APK to begin investigation.
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
        <span className="text-xs font-mono text-[#007A8E] tracking-wider uppercase animate-pulse">Retrieving SOC Investigation State...</span>
      </div>
    );
  }

  if (!job) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center space-y-4 min-h-[50vh]">
        <AlertTriangle className="w-12 h-12 text-[#4B9CD3] animate-bounce" />
        <h2 className="text-lg font-bold font-mono text-white uppercase tracking-wider">Incident Node Not Found</h2>
        <p className="text-xs text-slate-550 max-w-sm text-center">Verify the backend processes are online.</p>
      </div>
    );
  }

  const getSeverityStyle = (sev) => {
    switch(sev) {
      case "Critical": return { border: "border-[#007A8E]/25", bg: "bg-[#007A8E]/10", text: "text-[#007A8E]" };
      case "High": return { border: "border-[#4B9CD3]/25", bg: "bg-[#4B9CD3]/10", text: "text-[#4B9CD3]" };
      case "Medium": return { border: "border-[#5B9C7D]/25", bg: "bg-[#5B9C7D]/10", text: "text-[#5B9C7D]" };
      default: return { border: "border-[#2C5F2D]/25", bg: "bg-[#2C5F2D]/10", text: "text-[#5B9C7D]" };
    }
  };

  const style = getSeverityStyle(job.severity);

  // SVG parameters
  const radius = 68;
  const stroke = 9;
  const normalizedRadius = radius - stroke * 2;
  const circumference = normalizedRadius * 2 * Math.PI;
  const score = job.risk_score !== null ? job.risk_score : 0;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  // Recharts Dynamic Radar data
  const permissionsCount = findings.filter(f => f.type === "permission").length;
  const apisCount = findings.filter(f => f.type === "api").length;
  const urlsCount = findings.filter(f => f.type === "url").length;
  const obfuscationsCount = findings.filter(f => f.type === "obfuscation").length;

  const chartData = [
    { subject: "Permissions", value: permissionsCount || 1 },
    { subject: "Bytecode APIs", value: apisCount || 1 },
    { subject: "Network URLs", value: urlsCount || 1 },
    { subject: "Obfuscations", value: obfuscationsCount || 1 }
  ];

  // Pipeline execution node statuses
  const steps = [
    { key: "RE", label: "RE Extraction", active: job.status === "ANALYZING" && wsLogs.length < 5, done: job.status === "COMPLETED" || wsLogs.length >= 5 },
    { key: "CODE", label: "Dalvik Check", active: job.status === "ANALYZING" && wsLogs.length >= 5 && wsLogs.length < 10, done: job.status === "COMPLETED" || wsLogs.length >= 10 },
    { key: "INTEL", label: "Threat Map", active: job.status === "ANALYZING" && wsLogs.length >= 10 && wsLogs.length < 15, done: job.status === "COMPLETED" || wsLogs.length >= 15 },
    { key: "AI", label: "Forensic Core", active: job.status === "ANALYZING" && wsLogs.length >= 15 && wsLogs.length < 20, done: job.status === "COMPLETED" || wsLogs.length >= 20 },
    { key: "RISK", label: "Risk Index", active: job.status === "ANALYZING" && wsLogs.length >= 20 && wsLogs.length < 25, done: job.status === "COMPLETED" || wsLogs.length >= 25 },
    { key: "COMP", label: "Report Compile", active: job.status === "ANALYZING" && wsLogs.length >= 25, done: job.status === "COMPLETED" }
  ];

  return (
    <div className="flex-1 flex flex-col space-y-8 select-none p-4 md:p-6 max-w-7xl mx-auto w-full animate-fade-in">
      
      {/* Top SOC Status Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-900 pb-5">
        <div>
          <h2 className="text-xl font-bold text-white font-sans flex items-center space-x-2.5">
            <Cpu className="w-5 h-5 text-[#007A8E]" />
            <span className="uppercase tracking-wide font-semibold text-[#E8F5F2]">SOC Incident Investigation</span>
          </h2>
          <div className="text-[9px] text-slate-500 font-mono mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1">
            <span className="flex items-center space-x-1">
              <span className="text-[#007A8E] font-bold">Node ID:</span> 
              <span className="text-slate-350">{job.id}</span>
            </span>
            <span>•</span>
            <span className="flex items-center space-x-1">
              <span className="text-[#007A8E] font-bold">File:</span> 
              <span className="text-slate-350">{job.filename}</span>
            </span>
          </div>
        </div>
        
        <div className="flex items-center space-x-3 md:justify-end">
          <span className="text-[9px] text-slate-500 font-mono tracking-widest uppercase">Pipeline Status:</span>
          <span className={`px-3 py-1 rounded-full text-[9px] font-bold font-mono border ${
            job.status === "COMPLETED" ? "bg-[#2C5F2D]/10 text-[#5B9C7D] border-[#2C5F2D]/20" :
            job.status === "ANALYZING" ? "bg-[#007A8E]/10 text-[#007A8E] border-[#007A8E]/20 animate-pulse" :
            job.status === "FAILED" ? "bg-red-500/10 text-red-400 border-red-500/20" :
            "bg-slate-900 text-slate-400 border-slate-800"
          }`}>
            {job.status}
          </span>
        </div>
      </div>

      {/* Dashboard Top Row Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        
        {/* Glowing circular risk index */}
        <div className="bracket-card p-6 bg-[#0d1217] flex flex-col items-center justify-center text-center relative overflow-hidden min-h-[220px]">
          <div className="absolute top-3 left-4 text-micro-label">Risk Level Gauge</div>
          
          <div className="relative flex items-center justify-center mt-3">
            <div className="absolute w-24 h-24 bg-[#007A8E]/[0.02] rounded-full blur-xl animate-pulse" />
            
            <svg height={radius * 2} width={radius * 2} className="transform -rotate-90">
              <circle
                stroke="rgba(255,255,255,0.015)"
                fill="transparent"
                strokeWidth={stroke}
                r={normalizedRadius}
                cx={radius}
                cy={radius}
              />
              <circle
                stroke={
                  score > 75 ? "#007A8E" : 
                  score > 50 ? "#4B9CD3" : 
                  score > 25 ? "#5B9C7D" : 
                  "#2C5F2D"
                }
                fill="transparent"
                strokeWidth={stroke}
                strokeDasharray={circumference + ' ' + circumference}
                style={{ strokeDashoffset }}
                strokeLinecap="round"
                r={normalizedRadius}
                cx={radius}
                cy={radius}
                className="transition-all duration-1000 ease-out"
              />
            </svg>
            <div className="absolute flex flex-col items-center justify-center font-mono">
              <span className="text-3xl font-extrabold text-[#E8F5F2] leading-none">{score}%</span>
              <span className="text-[7.5px] text-slate-500 uppercase tracking-widest mt-1">Severity</span>
            </div>
          </div>

          <div className="mt-4 space-y-0.5">
            <h4 className="text-xs font-semibold text-white font-sans">Automated Assessment</h4>
            <p className="text-[10px] text-slate-500 font-mono">Dynamic decompilation heuristic rules</p>
          </div>
        </div>

        {/* Dynamic Static Analysis stats */}
        <div className="bracket-card p-6 bg-[#0d1217] flex flex-col justify-between relative min-h-[220px]">
          <div className="absolute top-3 left-4 text-micro-label">Static Heuristics</div>

          <div className="space-y-3.5 mt-5">
            <div className="flex justify-between items-center border-b border-slate-900 pb-2">
              <span className="text-[10px] text-slate-500 font-mono">Malware Family</span>
              <span className="text-xs font-semibold text-[#007A8E] font-mono">{job.malware_family || "Unknown / Generic"}</span>
            </div>
            <div className="flex justify-between items-center border-b border-slate-900 pb-2">
              <span className="text-[10px] text-slate-500 font-mono">Severity Tier</span>
              <span className={`px-2.5 py-0.5 rounded text-[9px] font-bold font-mono border ${style.bg} ${style.text} ${style.border}`}>
                {job.severity || "Low"}
              </span>
            </div>
            <div className="flex justify-between items-center border-b border-slate-900 pb-2">
              <span className="text-[10px] text-slate-500 font-mono">AI Consensus</span>
              <span className="text-xs font-semibold text-white font-mono">{job.confidence !== null ? `${job.confidence}%` : "85%"}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-[10px] text-slate-500 font-mono">Decompile Engine</span>
              <span className="text-xs text-white font-mono flex items-center space-x-1">
                <Clock className="w-3.5 h-3.5 text-slate-600" />
                <span className="text-slate-350">Statically Optimized</span>
              </span>
            </div>
          </div>
        </div>

        {/* Bespoke Recharts Radar Threat Vectors */}
        <div className="bracket-card p-5 bg-[#0d1217] flex flex-col justify-between relative min-h-[220px]">
          <div className="absolute top-3 left-4 text-micro-label">Signature Density Profile</div>
          
          <div className="w-full h-36 mt-4">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart cx="50%" cy="50%" radius="80%" data={chartData}>
                <PolarGrid stroke="rgba(255,255,255,0.01)" />
                <PolarAngleAxis 
                  dataKey="subject" 
                  tick={{ fill: "rgba(148, 163, 184, 0.5)", fontSize: 8.5, fontFamily: "monospace" }} 
                />
                <PolarRadiusAxis 
                  angle={30} 
                  domain={[0, 10]} 
                  tick={false} 
                  axisLine={false} 
                />
                <Radar
                  name="Heuristic Density"
                  dataKey="value"
                  stroke="rgba(75, 156, 211, 0.6)"
                  fill="rgba(75, 156, 211, 0.08)"
                  fillOpacity={0.6}
                />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>

      </div>

      {/* Multi-Agent Node Tracker Graphic */}
      <div className="bracket-card p-6 bg-[#0d1217] relative overflow-hidden">
        <div className="text-micro-label mb-6">Multi-Agent LangGraph Node Tracker</div>
        
        <div className="grid grid-cols-2 md:grid-cols-6 gap-4 relative select-none">
          {steps.map((step, idx) => (
            <div 
              key={step.key} 
              className={`p-3.5 rounded-xl border flex flex-col items-center text-center space-y-1.5 transition-all duration-300 relative ${
                step.done 
                  ? "bg-[#2C5F2D]/[0.02] border-[#2C5F2D]/20 text-[#5B9C7D]" 
                  : step.active 
                    ? "bg-[#007A8E]/[0.04] border-[#007A8E]/30 text-[#007A8E] shadow-[0_0_15px_rgba(0,122,142,0.04)] animate-pulse" 
                    : "bg-slate-950/20 border-slate-900 text-slate-650"
              }`}
            >
              {step.active && (
                <span className="absolute top-1.5 right-1.5 w-1 h-1 rounded-full bg-[#007A8E] animate-ping" />
              )}
              <div className="text-[7.5px] font-mono tracking-widest uppercase text-slate-500 leading-none">NODE_0{idx + 1}</div>
              <div className="text-xs font-semibold font-sans mt-1">{step.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Terminal Viewport */}
      <div className="bracket-card bg-[#0d1217] flex flex-col overflow-hidden shadow-[0_20px_50px_-5px_rgba(0,0,0,0.95)] relative group">
        
        {/* Terminal Header */}
        <div className="flex items-center justify-between border-b border-white/[0.01] bg-slate-950 px-4 py-2.5">
          <div className="flex items-center space-x-6">
            <div className="flex items-center space-x-1.5 flex-shrink-0">
              <span className="w-2 h-2 rounded-full bg-slate-800" />
              <span className="w-2 h-2 rounded-full bg-slate-800" />
              <span className="w-2 h-2 rounded-full bg-slate-800" />
            </div>
            <div className="flex items-center space-x-2 text-[9px] text-slate-500 font-mono">
              <Terminal className="w-3.5 h-3.5 text-[#007A8E] animate-pulse" />
              <span>sentinel-ai-orchestrator@soc:~ ({job.filename})</span>
            </div>
          </div>
          <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[8px] font-mono bg-[#2C5F2D]/10 text-[#5B9C7D] border border-[#2C5F2D]/20 uppercase tracking-widest animate-pulse select-none">STREAM_OK</span>
        </div>

        {/* Terminal logs viewport */}
        <div className="h-56 p-4 font-mono text-[10.5px] text-[#4B9CD3] overflow-y-auto space-y-2 select-text leading-relaxed relative z-0 bg-slate-950/40 crt-terminal">
          {wsLogs.length === 0 ? (
            <div className="text-slate-650 italic font-mono flex items-center space-x-2 py-4">
              <span>&gt;&gt;</span>
              <span>
                {job.status === "COMPLETED" 
                  ? "Reversing complete. Decompile artifacts compiled inside database. Use navigation controls." 
                  : "Awaiting incoming analysis packets from LangGraph orchestrator..."}
              </span>
            </div>
          ) : (
            wsLogs.map((log, index) => (
              <div key={index} className="flex items-start space-x-2.5">
                <span className="text-[#007A8E]/60 select-none">&gt;&gt;</span>
                <span className="text-slate-350 font-mono">{log}</span>
              </div>
            ))
          )}
          <div ref={consoleEndRef} />
        </div>
      </div>

      {/* Risk Score Findings List */}
      <div className="bracket-card p-6 bg-[#0d1217] space-y-4">
        <div className="flex items-center space-x-2 border-b border-slate-900 pb-3.5">
          <ShieldAlert className="w-4 h-4 text-[#007A8E]" />
          <h3 className="text-sm font-semibold text-white font-sans uppercase tracking-wider">Rule Engine Findings</h3>
        </div>

        <div className="space-y-3">
          {findings.length === 0 ? (
            <div className="text-xs text-slate-500 italic py-6 font-mono">No positive static signature detections matched. Target is clean.</div>
          ) : (
            findings.map((f) => (
              <div 
                key={f.id} 
                className="flex items-start justify-between p-4 rounded-xl bg-slate-950/40 border border-slate-900/60 hover:border-slate-800 transition-all duration-300 relative group"
              >
                <div className="space-y-1.5 pr-6">
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-semibold text-white group-hover:text-[#007A8E] transition-colors font-sans">{f.title}</span>
                    <span className="px-1.5 py-0.5 rounded text-[8px] font-mono bg-slate-900 border border-slate-850 text-slate-500 uppercase">{f.type}</span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed font-sans">{f.description}</p>
                </div>
                <div className="text-right flex-shrink-0">
                  <span className={`text-[8px] font-bold font-mono px-2 py-0.5 rounded border ${
                    f.severity === "Critical" ? "text-[#007A8E] bg-[#007A8E]/10 border-[#007A8E]/20" :
                    f.severity === "High" ? "text-[#4B9CD3] bg-[#4B9CD3]/10 border-[#4B9CD3]/20" :
                    f.severity === "Medium" ? "text-[#5B9C7D] bg-[#5B9C7D]/10 border-[#5B9C7D]/20" :
                    "text-[#5B9C7D] bg-[#2C5F2D]/10 border-[#2C5F2D]/20"
                  }`}>
                    {f.severity}
                  </span>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Footer Navigation */}
        {job.status === "COMPLETED" && (
          <div className="flex justify-end pt-2">
            <button 
              onClick={() => setPage("evidence")}
              className="flex items-center space-x-1.5 px-4 py-2 bg-[#007A8E]/10 text-[#007A8E] hover:bg-[#007A8E] hover:text-white rounded-lg text-xs font-semibold font-mono transition-all border border-[#007A8E]/20 hover:border-transparent btn-premium-click cursor-pointer"
            >
              <span>Explore Decompile Evidence</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>

    </div>
  );
}
