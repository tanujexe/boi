import React, { useState, useEffect } from "react";
import { 
  ArrowLeft, FileText, Download, Shield, Cpu, 
  Check, Copy, Terminal, AlertTriangle, ListFilter
} from "lucide-react";

export default function V2ReportView({ jobId, setPage }) {
  const [loading, setLoading] = useState(true);
  const [report, setReport] = useState(null);
  const [activeTab, setActiveTab] = useState("executive");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const fetchReport = async () => {
      try {
        const res = await fetch(`http://127.0.0.1:8000/api/v2/jobs/${jobId}/report`);
        if (res.ok) {
          const reportData = await res.json();
          setReport(reportData);
        }
      } catch (err) {
        console.error("Error fetching report:", err);
      } finally {
        setLoading(false);
      }
    };

    if (jobId) {
      fetchReport();
    }
  }, [jobId]);

  const copyReportMarkdown = () => {
    if (!report) return;
    
    const fullMarkdown = `
# SENTINELAI v2 SECURITY INVESTIGATION REPORT
Target Job ID: ${jobId}
Generated At: ${new Date(report.generated_at).toLocaleString()}
Model Engine: ${report.ai_model_used}

---

## EXECUTIVE SUMMARY
${report.executive_summary}

---

## TECHNICAL SANDBOX ANALYSIS
${report.technical_report}

---

## BEHAVIORAL TELEMETRY SUMMARY
${report.behavioral_summary}

---

## REMEDIATION & MITIGATION RECOMMENDATIONS
${report.remediation}
    `;

    navigator.clipboard.writeText(fullMarkdown.trim());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (loading) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center space-y-4 py-32 font-mono text-xs text-slate-500">
        <div className="w-8 h-8 border-2 border-[#007A8E]/10 border-t-[#007A8E] rounded-full animate-spin" />
        <span className="uppercase tracking-[0.2em] animate-pulse">Synthesizing AI Forensic Report...</span>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="bracket-card p-10 text-center text-slate-400 font-mono text-xs bg-[#0d1217]">
        <p>Investigation report could not be compiled. Check if dynamic sandbox run completed.</p>
        <button 
          onClick={() => setPage("v2-results")}
          className="mt-4 px-4 py-2 rounded-xl bg-slate-900 border border-slate-800 text-[#007A8E] hover:bg-slate-850"
        >
          Return to Telemetry Results
        </button>
      </div>
    );
  }

  // Helper to format/render markdown headers & lists to basic styled HTML elements
  const renderFormattedText = (text) => {
    if (!text) return null;
    
    const lines = text.split("\n");
    return lines.map((line, idx) => {
      // Headers
      if (line.startsWith("### ")) {
        return <h4 key={idx} className="text-xs font-bold text-white font-mono uppercase tracking-wider mt-4 mb-2 border-b border-white/[0.02] pb-1.5">{line.substring(4)}</h4>;
      }
      if (line.startsWith("## ")) {
        return <h3 key={idx} className="text-sm font-bold text-white font-mono uppercase tracking-widest mt-6 mb-3 text-[#007A8E]">{line.substring(3)}</h3>;
      }
      if (line.startsWith("# ")) {
        return <h2 key={idx} className="text-base font-extrabold text-white font-sans uppercase tracking-wider mt-6 mb-4">{line.substring(2)}</h2>;
      }
      
      // Bullet items
      if (line.startsWith("- ")) {
        const content = line.substring(2);
        // Check for bold prefixes e.g. - **Item:** description
        const boldMatch = content.match(/^\*\*(.*?)\*\*(.*)/);
        if (boldMatch) {
          return (
            <div key={idx} className="flex items-start space-x-2.5 font-sans text-[11px] text-slate-350 ml-3 mb-2 leading-relaxed">
              <span className="text-[#007A8E] mt-1">•</span>
              <span>
                <strong className="text-white font-semibold">{boldMatch[1]}</strong>
                {boldMatch[2]}
              </span>
            </div>
          );
        }
        return (
          <div key={idx} className="flex items-start space-x-2.5 font-sans text-[11px] text-slate-350 ml-3 mb-2 leading-relaxed">
            <span className="text-[#007A8E] mt-1">•</span>
            <span>{content}</span>
          </div>
        );
      }

      // Number list items
      if (line.match(/^\d+\.\s/)) {
        const content = line.replace(/^\d+\.\s/, "");
        return (
          <div key={idx} className="flex items-start space-x-2.5 font-sans text-[11px] text-slate-350 ml-3 mb-2 leading-relaxed">
            <span className="text-[#007A8E] font-mono font-bold mt-0.5">{line.match(/^\d+/)[0]}.</span>
            <span>{content}</span>
          </div>
        );
      }

      // Warning blockquotes or highlight boxes
      if (line.startsWith("> ")) {
        return (
          <blockquote key={idx} className="border-l-2 border-yellow-500/40 bg-yellow-500/[0.02] p-3 rounded-r-xl font-mono text-[9.5px] text-yellow-500/85 my-4 leading-relaxed">
            {line.substring(2)}
          </blockquote>
        );
      }

      // Empty space
      if (line.trim() === "") {
        return <div key={idx} className="h-2" />;
      }

      // Normal paragraph text
      // Replace **bold** occurrences in normal line
      const boldParts = line.split(/\*\*(.*?)\*\*/g);
      if (boldParts.length > 1) {
        return (
          <p key={idx} className="font-sans text-[11px] text-slate-350 leading-relaxed mb-3">
            {boldParts.map((part, i) => i % 2 === 1 ? <strong key={i} className="text-white font-semibold">{part}</strong> : part)}
          </p>
        );
      }

      return (
        <p key={idx} className="font-sans text-[11px] text-slate-350 leading-relaxed mb-3">
          {line}
        </p>
      );
    });
  };

  const getActiveContent = () => {
    switch (activeTab) {
      case "executive":
        return renderFormattedText(report.executive_summary);
      case "technical":
        return renderFormattedText(report.technical_report);
      case "behavioral":
        return renderFormattedText(report.behavioral_summary);
      case "remediation":
        return renderFormattedText(report.remediation);
      default:
        return null;
    }
  };

  return (
    <div className="w-full flex flex-col space-y-6 relative z-10 py-2 mx-auto animate-fade-in">

      {/* Top Bar */}
      <div className="flex items-center justify-between">
        <button 
          onClick={() => setPage("v2-results")}
          className="flex items-center space-x-2 px-3 py-1.5 rounded-xl border border-white/[0.02] bg-[#0d1217] hover:bg-[#131920] text-slate-400 hover:text-white transition-all text-[10px] font-mono cursor-pointer"
        >
          <ArrowLeft className="w-3.5 h-3.5 text-[#007A8E]" />
          <span>BACK TO TELEMETRY</span>
        </button>

        <div className="flex space-x-2">
          <button 
            onClick={copyReportMarkdown}
            className="flex items-center space-x-2 px-4 py-1.5 rounded-xl bg-slate-950 border border-white/[0.03] hover:border-slate-800 text-[10px] font-mono text-slate-300 hover:text-white transition-all cursor-pointer"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-green-400" />
                <span>COPIED MARKDOWN</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5 text-[#007A8E]" />
                <span>COPY MARKDOWN</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Report Info Metadata */}
      <div className="bracket-card p-5 bg-[#0d1217] flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div className="flex items-center space-x-3.5">
          <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-900 text-[#007A8E]">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-xs font-bold text-white font-mono uppercase tracking-widest">AI Threat Investigation Report</h2>
            <div className="flex items-center space-x-2 mt-1 text-[9.5px] font-mono text-slate-500">
              <span>ENGINE: {report.ai_model_used}</span>
              <span>•</span>
              <span>DATE: {new Date(report.generated_at).toLocaleString()}</span>
            </div>
          </div>
        </div>

        <div className="text-[9.5px] font-mono text-slate-500 bg-slate-950/40 border border-slate-900 px-3 py-1.5 rounded-xl flex items-center space-x-2 uppercase">
          <Cpu className="w-3 h-3 text-[#007A8E] animate-pulse" />
          <span>v2 SECURE_COMPILING</span>
        </div>
      </div>

      {/* Double Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        
        {/* Left Side: Navigation Menu */}
        <div className="lg:col-span-1 flex flex-col space-y-2.5">
          <div className="px-2 text-micro-label uppercase tracking-widest text-slate-500">Report Outline</div>
          
          {[
            { key: "executive", name: "Executive Summary" },
            { key: "technical", name: "Technical Sandbox" },
            { key: "behavioral", name: "Behavioral Telemetry" },
            { key: "remediation", name: "Remediation & Mitigation" }
          ].map(outline => {
            const isActive = activeTab === outline.key;
            return (
              <button
                key={outline.key}
                onClick={() => setActiveTab(outline.key)}
                className={`w-full text-left px-4 py-3 rounded-xl text-[10.5px] font-mono transition-all flex items-center justify-between border cursor-pointer ${
                  isActive 
                    ? "bg-[#131920] border-[#007A8E]/40 text-[#007A8E] font-bold shadow-[0_4px_15px_rgba(0,0,0,0.6)]" 
                    : "border-transparent text-slate-400 hover:text-white hover:bg-white/[0.01]"
                }`}
              >
                <span>{outline.name.toUpperCase()}</span>
                <Terminal className={`w-3 h-3 ${isActive ? "text-[#007A8E]" : "text-slate-600"}`} />
              </button>
            );
          })}
        </div>

        {/* Right Side: Render Panel */}
        <div className="lg:col-span-3">
          <div className="bracket-card p-7 bg-[#090d12]/60 min-h-[400px] border border-white/[0.01] relative overflow-hidden select-text">
            {/* Scanline overlay for matching styling theme */}
            <div className="absolute inset-0 pointer-events-none crt-scanlines opacity-5 z-20" />
            
            {/* Content container */}
            <div className="relative z-10 space-y-4">
              {getActiveContent()}
            </div>
          </div>
        </div>

      </div>

    </div>
  );
}
