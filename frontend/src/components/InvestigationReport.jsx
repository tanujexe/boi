import React, { useState, useEffect } from "react";
import { 
  FileText, 
  Download, 
  Printer, 
  ShieldCheck, 
  AlertOctagon,
  ArrowUpRight,
  ShieldAlert,
  Terminal,
  Layers
} from "lucide-react";

export default function InvestigationReport({ jobId, setPage }) {
  const [job, setJob] = useState(null);
  const [findings, setFindings] = useState([]);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchJobData = async () => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/jobs/${jobId}`);
      if (res.ok) {
        const data = await res.json();
        setJob(data.job);
        setFindings(data.findings);
        setReport(data.report);
      }
    } catch (err) {
      console.error("Error loading job report:", err);
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

  const handleDownloadJson = () => {
    if (!job) return;
    const reportData = {
      job_metadata: job,
      findings_list: findings,
      report_narratives: report
    };
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `SentinelAI_Report_${job.filename.replace(/\s+/g, "_")}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handlePrint = () => {
    window.print();
  };

  const renderMarkdown = (text) => {
    if (!text) return "";
    
    // Simple sanitization & replacement engine
    let html = text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
      
    // Headings
    html = html.replace(/^### (.*$)/gim, '<h3 class="text-xs font-bold text-[#007A8E] font-mono tracking-widest uppercase mt-5 mb-2.5">$1</h3>');
    html = html.replace(/^## (.*$)/gim, '<h2 class="text-[13px] font-bold text-white font-sans mt-7 mb-3.5 border-b border-slate-900 pb-2 flex items-center tracking-wide">$1</h2>');
    html = html.replace(/^# (.*$)/gim, '<h1 class="text-lg font-extrabold text-white font-sans mt-8 mb-5">$1</h1>');
    
    // Bold / Italic
    html = html.replace(/\*\*(.*?)\*\*/gim, '<strong class="text-white font-semibold">$1</strong>');
    html = html.replace(/\*(.*?)\*/gim, '<em class="text-slate-400">$1</em>');
    
    // Unordered list
    html = html.replace(/^\- (.*$)/gim, '<li class="ml-4 list-disc text-slate-350 pl-1 py-1 text-xs">$1</li>');
    
    // Code block lines
    html = html.replace(/`(.*?)`/gim, '<code class="bg-[#070b0f] border border-[#2C3E50]/40 px-2 py-0.5 rounded text-[#4B9CD3] font-mono text-[10px]">$1</code>');
    
    // Split and map into paragraphs
    html = html.split('\n\n').map(p => {
      const trimmed = p.trim();
      if (trimmed.startsWith('<h') || trimmed.startsWith('<li') || trimmed.startsWith('<ul')) {
        return p;
      }
      return `<p class="text-slate-400 font-sans leading-relaxed text-xs py-2 select-text">${p}</p>`;
    }).join('\n');
    
    return <div dangerouslySetInnerHTML={{ __html: html }} />;
  };

  if (!jobId) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center space-y-4 min-h-[50vh] text-center">
        <FileText className="w-12 h-12 text-[#007A8E] animate-pulse" />
        <h2 className="text-lg font-bold font-mono text-[#E8F5F2] uppercase tracking-wider">No Report Selected</h2>
        <p className="text-xs text-slate-500 max-w-sm">
          Please select an APK decompile session from history or run an upload to view the Compiled AI Forensic Report.
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
        <span className="text-xs font-mono text-[#007A8E] tracking-wider uppercase animate-pulse">Compiling AI Forensic Report...</span>
      </div>
    );
  }

  if (!job || !report) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center space-y-4 min-h-[50vh]">
        <AlertOctagon className="w-12 h-12 text-[#007A8E] animate-bounce" />
        <h2 className="text-lg font-bold font-mono text-white">No Report Compiled</h2>
        <p className="text-xs text-slate-500 max-w-sm text-center">
          Analysis is either pending or encountered a system exception. Verify status on the Dashboard.
        </p>
      </div>
    );
  }

  const isThreat = job.severity === "Critical" || job.severity === "High";

  return (
    <div className="flex-1 flex flex-col space-y-8 p-4 md:p-6 max-w-7xl mx-auto w-full animate-fade-in print:bg-[#070b0e] print:text-slate-100 print:p-0">
      
      {/* Title & Actions Bar */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between border-b border-slate-900 pb-5 print:hidden gap-4">
        <div>
          <h2 className="text-xl font-bold text-white font-sans flex items-center space-x-2.5">
            <FileText className="w-5 h-5 text-[#007A8E]" />
            <span className="uppercase tracking-wide font-semibold text-white">Forensic Investigation Report</span>
          </h2>
          <p className="text-xs text-slate-500 font-mono mt-1.5">
            Explainable audit trail compile summarizing multi-agent static reversing logic.
          </p>
        </div>

        <div className="flex items-center space-x-3 md:justify-end">
          <button 
            onClick={handleDownloadJson}
            className="flex items-center space-x-1.5 px-3 py-2 bg-slate-950 hover:bg-slate-900 border border-slate-850 text-slate-400 hover:text-white rounded-lg text-xs font-mono transition-all btn-premium-click cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>
          
          <button 
            onClick={handlePrint}
            className="flex items-center space-x-1.5 px-3 py-2 bg-[#007A8E]/10 text-[#007A8E] hover:bg-[#007A8E] hover:text-white border border-[#007A8E]/20 hover:border-transparent rounded-lg text-xs font-mono transition-all btn-premium-click cursor-pointer"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print PDF Audit</span>
          </button>
        </div>
      </div>

      {/* Target Security Banner */}
      <div className="bracket-card p-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-5 border-slate-850 bg-[#0d1217] relative overflow-hidden">
        {/* Glow ambient background depending on threat */}
        <div className={`absolute top-0 right-0 w-24 h-24 rounded-full blur-3xl opacity-20 pointer-events-none ${
          isThreat ? "bg-[#007A8E]" : "bg-[#2C5F2D]"
        }`} />
        
        <div className="flex items-center space-x-4">
          <div className={`p-3 rounded-xl border flex-shrink-0 ${
            isThreat 
              ? "bg-[#007A8E]/10 border-[#007A8E]/20 text-[#007A8E]" 
              : job.severity === "Medium" 
                ? "bg-[#5B9C7D]/10 border-[#5B9C7D]/20 text-[#5B9C7D]" 
                : "bg-[#2C5F2D]/10 border-[#2C5F2D]/20 text-[#5B9C7D]"
          }`}>
            {isThreat ? (
              <AlertOctagon className="w-6 h-6 animate-pulse" />
            ) : (
              <ShieldCheck className="w-6 h-6" />
            )}
          </div>
          <div className="min-w-0">
            <div className="text-md font-bold text-white font-sans truncate pr-2">{job.filename}</div>
            <div className="text-[10px] text-slate-500 font-mono mt-1 flex flex-wrap items-center gap-x-3 gap-y-1">
              <span className="truncate max-w-[250px]">SHA256: {job.sha256}</span>
              <span>•</span>
              <span>Classification: {job.malware_family || "Unknown / Generic"}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-6 pr-2 flex-shrink-0">
          <div className="text-left font-mono">
            <span className="text-[9px] text-slate-500 block uppercase tracking-widest">Risk Index</span>
            <span className={`text-xl font-bold block leading-none mt-1.5 ${
              job.risk_score > 75 ? "text-[#007A8E]" :
              job.risk_score > 50 ? "text-[#4B9CD3]" :
              job.risk_score > 25 ? "text-[#5B9C7D]" : "text-[#5B9C7D]"
            }`}>
              {job.risk_score}%
            </span>
          </div>
          <div className="text-left font-mono">
            <span className="text-[9px] text-slate-500 block uppercase tracking-widest">AI Confidence</span>
            <span className="text-xl font-bold text-white block leading-none mt-1.5">{job.confidence || 85}%</span>
          </div>
        </div>
      </div>

      {/* Main Report Sections */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        
        {/* Left column - Executive Summary & Technical report (takes 2/3 space) */}
        <div className="lg:col-span-2 space-y-6">
          
          {/* Executive Summary */}
          <div className="bracket-card p-6 bg-[#0d1217] print:border-none print:p-0">
            <div className="flex items-center space-x-2 border-b border-slate-900 pb-3 mb-5">
              <FileText className="w-4 h-4 text-[#007A8E]" />
              <h3 className="text-xs font-bold text-white font-mono uppercase tracking-widest">Executive Assessment Summary</h3>
            </div>
            <div className="prose prose-invert max-w-none">
              {renderMarkdown(report.executive_summary)}
            </div>
          </div>

          {/* Technical Report */}
          <div className="bracket-card p-6 bg-[#0d1217] print:border-none print:p-0">
            <div className="flex items-center space-x-2 border-b border-slate-900 pb-3 mb-5">
              <Terminal className="w-4 h-4 text-[#007A8E]" />
              <h3 className="text-xs font-bold text-white font-mono uppercase tracking-widest">Technical Investigation Details</h3>
            </div>
            <div className="prose prose-invert max-w-none">
              {renderMarkdown(report.technical_report)}
            </div>
          </div>
        </div>

        {/* Right column - Remediation Playbook (takes 1/3 space) */}
        <div className="space-y-6">
          <div className="bracket-card p-6 bg-[#0d1217] print:border-none print:p-0 relative overflow-hidden">
            {/* Ambient background accent */}
            <div className="absolute top-0 right-0 w-24 h-24 bg-[#007A8E]/5 rounded-full blur-2xl pointer-events-none" />
            
            <h3 className="text-xs font-bold text-white font-mono uppercase tracking-wider mb-5 border-b border-slate-900 pb-3 flex items-center space-x-2">
              <ShieldAlert className="w-4 h-4 text-[#007A8E]" />
              <span>Remediation Playbook</span>
            </h3>
            
            <div className="prose prose-invert max-w-none">
              {renderMarkdown(report.remediation_guidance)}
            </div>

            {/* Quick SOC Actions */}
            <div className="mt-7 pt-5 border-t border-slate-900 space-y-3.5 print:hidden">
              <span className="text-[9px] font-mono text-slate-500 uppercase tracking-widest block">SOC Command Actions</span>
              
              <button 
                onClick={() => setPage("campaigns")}
                className="w-full flex items-center justify-between p-3 rounded-xl bg-slate-950/60 border border-slate-900 hover:border-[#007A8E]/30 hover:bg-slate-900/60 text-left transition-all text-xs font-mono text-slate-400 hover:text-[#007A8E] group btn-premium-click cursor-pointer"
              >
                <span>Correlate Campaign Clusters</span>
                <ArrowUpRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-[#007A8E] transition-colors" />
              </button>
            </div>
          </div>
        </div>

      </div>

    </div>
  );
}
