import React, { useState, useEffect } from "react";
import { 
  Upload, 
  ShieldAlert, 
  Terminal, 
  Play, 
  Trash2, 
  FileText,
  Clock,
  Cpu,
  Layers,
  Network,
  Activity,
  UserCheck,
  ShieldCheck,
  AlertTriangle
} from "lucide-react";

export default function UploadPage({ onSelectJob, onStartLoading, onStopLoading, loading }) {
  const [dragActive, setDragActive] = useState(false);
  const [file, setFile] = useState(null);
  const [jobs, setJobs] = useState([]);
  const [apiKeysCount, setApiKeysCount] = useState(0);

  const fetchJobs = async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/jobs");
      if (res.ok) {
        const data = await res.json();
        setJobs(data);
      }
    } catch (err) {
      console.error("Error fetching jobs list:", err);
    }
  };

  const fetchKeys = async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/api-keys");
      if (res.ok) {
        const data = await res.json();
        setApiKeysCount(data.length);
      }
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchJobs();
    fetchKeys();
  }, []);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = async (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const droppedFile = e.dataTransfer.files[0];
      setFile(droppedFile);
      await uploadFile(droppedFile);
    }
  };

  const handleFileChange = async (e) => {
    if (e.target.files && e.target.files[0]) {
      const selectedFile = e.target.files[0];
      setFile(selectedFile);
      await uploadFile(selectedFile);
    }
  };

  const uploadFile = async (selectedFile) => {
    onStartLoading();
    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const res = await fetch("http://127.0.0.1:8000/api/jobs/upload", {
        method: "POST",
        body: formData,
      });

      if (res.ok) {
        const data = await res.json();
        onSelectJob(data.job_id);
      } else {
        alert("File upload failed. Verify the FastAPI backend is running.");
      }
    } catch (err) {
      console.error("Upload error:", err);
      alert("Backend connection failed. Start FastAPI server.");
    } finally {
      onStopLoading();
    }
  };

  const handleSampleTrigger = async (sampleKey) => {
    onStartLoading();
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/upload-sample?sample_key=${sampleKey}`, {
        method: "POST"
      });
      if (res.ok) {
        const data = await res.json();
        onSelectJob(data.job_id);
      } else {
        alert("Failed to queue sample run.");
      }
    } catch (err) {
      console.error(err);
      alert("Error contacting analysis server.");
    } finally {
      onStopLoading();
    }
  };

  const handleDeleteJob = async (jobId, e) => {
    e.stopPropagation();
    if (confirm("Delete this analysis record?")) {
      try {
        const res = await fetch(`http://127.0.0.1:8000/api/jobs/${jobId}`, {
          method: "DELETE"
        });
        if (res.ok) {
          fetchJobs();
        }
      } catch (err) {
        console.error(err);
      }
    }
  };

  return (
    <div className="w-full max-w-5xl flex flex-col space-y-10 relative z-10 py-6 mx-auto animate-fade-in">

      {/* Top Capsule Badge */}
      <div className="mx-auto bg-[#0d1217] border border-white/[0.03] px-4 py-1.5 rounded-full text-[9px] font-mono text-slate-500 tracking-[0.25em] flex items-center space-x-2.5 w-fit shadow-[0_4px_20px_rgba(0,0,0,0.8)] uppercase">
        <span className="relative flex h-1.5 w-1.5">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#007A8E] opacity-75"></span>
          <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-[#007A8E]"></span>
        </span>
        <span>AUTONOMOUS FORENSIC DECOMPILER</span>
      </div>
      
      {/* Brand Header */}
      <div className="text-center flex flex-col items-center space-y-2.5">
        <div>
          <h1 className="text-6xl font-display tracking-tighter text-white py-1">
            SENTINEL<span className="text-[#007A8E]">_AI</span>
          </h1>
          <div className="laser-line-teal w-48 mx-auto mt-2 opacity-50" />
        </div>
      </div>

      {/* Stats Counter Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
        <div className="bracket-card p-5 flex items-center space-x-4 bg-[#0d1217]">
          <div className="bg-[#2C5F2D]/5 p-3 rounded-xl border border-[#2C5F2D]/10 flex items-center justify-center">
            <FileText className="w-5 h-5 text-[#5B9C7D]" />
          </div>
          <div>
            <div className="text-2xl font-bold font-mono text-[#E8F5F2] leading-none">{jobs.length}</div>
            <div className="text-micro-label mt-1.5">Audit Reports</div>
          </div>
        </div>
        
        <div className="bracket-card p-5 flex items-center space-x-4 bg-[#0d1217]">
          <div className="bg-[#007A8E]/5 p-3 rounded-xl border border-[#007A8E]/10 flex items-center justify-center">
            <ShieldAlert className="w-5 h-5 text-[#007A8E] animate-pulse" />
          </div>
          <div>
            <div className="text-2xl font-bold font-mono text-[#007A8E] leading-none">
              {jobs.filter(j => j.severity === "Critical" || j.severity === "High").length}
            </div>
            <div className="text-micro-label mt-1.5">Threats Tagged</div>
          </div>
        </div>

        <div className="bracket-card p-5 flex items-center space-x-4 bg-[#0d1217]">
          <div className="bg-[#4B9CD3]/5 p-3 rounded-xl border border-[#4B9CD3]/10 flex items-center justify-center">
            <Terminal className="w-5 h-5 text-[#4B9CD3]" />
          </div>
          <div>
            <div className="text-2xl font-bold font-mono text-[#E8F5F2] leading-none">{apiKeysCount}</div>
            <div className="text-micro-label mt-1.5">API Keys Playground</div>
          </div>
        </div>
      </div>

      {/* Interactive Multi-Agent Network Visualizer */}
      <div className="bracket-card p-6 bg-[#0d1217] flex flex-col justify-between items-center text-center relative overflow-hidden min-h-[300px]">
        <div className="absolute top-3 left-4 text-micro-label">Multi-Agent Orchestration Topology</div>
        
        {/* Animated Network SVG Graph */}
        <div className="w-full max-w-2xl h-52 mt-8 relative select-none">
          <svg viewBox="0 0 600 220" className="w-full h-full">
            {/* Connection lines back to central core */}
            <path d="M 300 110 L 100 50" stroke="rgba(0, 122, 142, 0.15)" strokeWidth="1.5" fill="none" />
            <path d="M 300 110 L 100 50" stroke="rgba(0, 122, 142, 0.5)" strokeWidth="1" fill="none" className="path-data-pulse" />

            <path d="M 300 110 L 300 40" stroke="rgba(0, 122, 142, 0.15)" strokeWidth="1.5" fill="none" />
            <path d="M 300 110 L 300 40" stroke="rgba(0, 122, 142, 0.5)" strokeWidth="1" fill="none" className="path-data-pulse" />

            <path d="M 300 110 L 500 50" stroke="rgba(0, 122, 142, 0.15)" strokeWidth="1.5" fill="none" />
            <path d="M 300 110 L 500 50" stroke="rgba(0, 122, 142, 0.5)" strokeWidth="1" fill="none" className="path-data-pulse" />

            <path d="M 300 110 L 100 170" stroke="rgba(0, 122, 142, 0.15)" strokeWidth="1.5" fill="none" />
            <path d="M 300 110 L 100 170" stroke="rgba(0, 122, 142, 0.5)" strokeWidth="1" fill="none" className="path-data-pulse" />

            <path d="M 300 110 L 300 180" stroke="rgba(0, 122, 142, 0.15)" strokeWidth="1.5" fill="none" />
            <path d="M 300 110 L 300 180" stroke="rgba(0, 122, 142, 0.5)" strokeWidth="1" fill="none" className="path-data-pulse" />

            <path d="M 300 110 L 500 170" stroke="rgba(0, 122, 142, 0.15)" strokeWidth="1.5" fill="none" />
            <path d="M 300 110 L 500 170" stroke="rgba(0, 122, 142, 0.5)" strokeWidth="1" fill="none" className="path-data-pulse" />

            {/* Center Core node */}
            <circle cx="300" cy="110" r="22" fill="#070b0f" stroke="rgba(0, 122, 142, 0.5)" strokeWidth="2" />
            <circle cx="300" cy="110" r="14" fill="rgba(0, 122, 142, 0.08)" stroke="rgba(0, 122, 142, 0.2)" />

            {/* Agent Nodes */}
            <g transform="translate(100, 50)">
              <circle cx="0" cy="0" r="16" fill="#070b0f" stroke="rgba(75,156,211,0.15)" strokeWidth="1.5" />
              <text x="0" y="3" textAnchor="middle" fill="rgba(232,245,242,0.85)" fontSize="7" fontFamily="monospace">RE</text>
              <text x="0" y="-22" textAnchor="middle" fill="rgba(164,181,198,0.7)" fontSize="7" fontFamily="sans-serif">1. RE Decompiler</text>
            </g>
            <g transform="translate(300, 40)">
              <circle cx="0" cy="0" r="16" fill="#070b0f" stroke="rgba(75,156,211,0.15)" strokeWidth="1.5" />
              <text x="0" y="3" textAnchor="middle" fill="rgba(232,245,242,0.85)" fontSize="7" fontFamily="monospace">CODE</text>
              <text x="0" y="-22" textAnchor="middle" fill="rgba(164,181,198,0.7)" fontSize="7" fontFamily="sans-serif">2. Heuristics Code</text>
            </g>
            <g transform="translate(500, 50)">
              <circle cx="0" cy="0" r="16" fill="#070b0f" stroke="rgba(75,156,211,0.15)" strokeWidth="1.5" />
              <text x="0" y="3" textAnchor="middle" fill="rgba(232,245,242,0.85)" fontSize="7" fontFamily="monospace">INTEL</text>
              <text x="0" y="-22" textAnchor="middle" fill="rgba(164,181,198,0.7)" fontSize="7" fontFamily="sans-serif">3. Threat Intel</text>
            </g>
            <g transform="translate(100, 170)">
              <circle cx="0" cy="0" r="16" fill="#070b0f" stroke="rgba(75,156,211,0.15)" strokeWidth="1.5" />
              <text x="0" y="3" textAnchor="middle" fill="rgba(232,245,242,0.85)" fontSize="7" fontFamily="monospace">SOC</text>
              <text x="0" y="24" textAnchor="middle" fill="rgba(164,181,198,0.7)" fontSize="7" fontFamily="sans-serif">4. AI Forensics</text>
            </g>
            <g transform="translate(300, 180)">
              <circle cx="0" cy="0" r="16" fill="#070b0f" stroke="rgba(75,156,211,0.15)" strokeWidth="1.5" />
              <text x="0" y="3" textAnchor="middle" fill="rgba(232,245,242,0.85)" fontSize="7" fontFamily="monospace">RISK</text>
              <text x="0" y="24" textAnchor="middle" fill="rgba(164,181,198,0.7)" fontSize="7" fontFamily="sans-serif">5. Risk Engine</text>
            </g>
            <g transform="translate(500, 170)">
              <circle cx="0" cy="0" r="16" fill="#070b0f" stroke="rgba(75,156,211,0.15)" strokeWidth="1.5" />
              <text x="0" y="3" textAnchor="middle" fill="rgba(232,245,242,0.85)" fontSize="7" fontFamily="monospace">REP</text>
              <text x="0" y="24" textAnchor="middle" fill="rgba(164,181,198,0.7)" fontSize="7" fontFamily="sans-serif">6. Compiler</text>
            </g>
          </svg>
          
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <Cpu className="w-5 h-5 text-[#007A8E] animate-spin" style={{ animationDuration: '6s' }} />
          </div>
        </div>

        <p className="text-[10px] text-slate-500 font-mono mt-4 leading-relaxed max-w-lg">
          The 6-agent system compiles static reversing outputs using LangGraph, passing telemetry packets through local modules and Groq LLMs concurrently.
        </p>
      </div>

      {/* Upload Dropzone & Sandbox simulation */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        
        {/* APK Dropzone Scanner Box */}
        <div 
          onDragEnter={handleDrag}
          onDragOver={handleDrag}
          onDragLeave={handleDrag}
          onDrop={handleDrop}
          className={`bracket-card p-8 flex flex-col items-center justify-center text-center space-y-5 transition-all relative overflow-hidden min-h-[260px] ${
            dragActive 
              ? "border-[#007A8E] bg-[#007A8E]/[0.03] scale-[1.01] shadow-[0_0_40px_rgba(0,122,142,0.08)]" 
              : "bg-[#0d1217]"
          }`}
        >
          <input 
            type="file" 
            accept=".apk,.zip" 
            className="absolute inset-0 opacity-0 cursor-pointer z-10"
            onChange={handleFileChange}
            disabled={loading}
          />
          
          <div className="relative">
            <div className="absolute inset-0 bg-[#007A8E]/15 rounded-full blur-md" />
            <div className="relative bg-[#070b0f] p-4.5 rounded-full border border-[#007A8E]/25 text-[#007A8E]">
              <Upload className="w-6 h-6" />
            </div>
          </div>

          <div className="space-y-1.5">
            <h3 className="text-xs font-semibold text-white font-sans uppercase tracking-wider">Submit Suspicious Android Package</h3>
            <p className="text-[10px] text-slate-500 font-mono leading-relaxed">
              Drag & drop APK binary, or click to browse filesystem<br />
              <span className="text-[#007A8E]/75 font-semibold">(Supports APK and ZIP files up to 500MB)</span>
            </p>
          </div>

          {loading && (
            <div className="absolute inset-0 bg-[#070b0f]/98 rounded-2xl flex flex-col items-center justify-center space-y-4 backdrop-blur-md z-20 animate-fade-in">
              <div className="relative">
                <div className="w-8 h-8 border-2 border-[#007A8E]/10 border-t-[#007A8E] rounded-full animate-spin" />
                <div className="absolute inset-0 bg-[#007A8E]/10 rounded-full blur-md animate-pulse" />
              </div>
              <span className="text-[9px] font-mono text-[#007A8E] tracking-[0.2em] uppercase animate-pulse">Running Bytecode Decompiler...</span>
            </div>
          )}
        </div>

        {/* Malware Sandbox Simulator */}
        <div className="bracket-card p-6 bg-[#0d1217] flex flex-col justify-between space-y-5">
          <div>
            <h3 className="text-xs font-bold text-white font-mono uppercase tracking-[0.2em] flex items-center space-x-2">
              <Terminal className="w-4 h-4 text-[#007A8E]" />
              <span>Malware Simulation Desk</span>
            </h3>
            <p className="text-[10px] text-slate-500 font-mono mt-1 leading-relaxed">
              Inject standard signatures dynamically to compile investigation pipelines instantly:
            </p>
          </div>

          <div className="space-y-2.5">
            <button 
              onClick={() => handleSampleTrigger("anubis")}
              className="w-full flex items-center justify-between p-3.5 rounded-xl bg-slate-950/60 border border-slate-900 hover:border-[#007A8E]/30 hover:bg-[#007A8E]/[0.02] hover:shadow-[0_0_15px_rgba(0,122,142,0.03)] transition-all duration-300 group btn-premium-click cursor-pointer"
            >
              <div className="space-y-1 text-left">
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-semibold text-white group-hover:text-[#007A8E] transition-colors font-sans">Anubis Trojan</span>
                  <span className="px-1.5 py-0.5 rounded text-[8px] font-mono bg-[#007A8E]/10 text-[#007A8E] border border-[#007A8E]/20">Critical</span>
                </div>
                <div className="text-[9px] text-slate-500 font-mono">Accessibility abuse & SMS interceptor simulation</div>
              </div>
              <div className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-500 group-hover:text-[#007A8E] group-hover:border-[#007A8E]/25 transition-all">
                <Play className="w-3 h-3 fill-current" />
              </div>
            </button>

            <button 
              onClick={() => handleSampleTrigger("sharkbot")}
              className="w-full flex items-center justify-between p-3.5 rounded-xl bg-slate-950/60 border border-slate-900 hover:border-[#007A8E]/30 hover:bg-[#007A8E]/[0.02] hover:shadow-[0_0_15px_rgba(0,122,142,0.03)] transition-all duration-300 group btn-premium-click cursor-pointer"
            >
              <div className="space-y-1 text-left">
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-semibold text-white group-hover:text-[#007A8E] transition-colors font-sans">SharkBot Dropper</span>
                  <span className="px-1.5 py-0.5 rounded text-[8px] font-mono bg-[#4B9CD3]/10 text-[#4B9CD3] border border-[#4B9CD3]/20">High Risk</span>
                </div>
                <div className="text-[9px] text-slate-500 font-mono">Phishing overlays & dynamic dex execution modules</div>
              </div>
              <div className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-500 group-hover:text-[#007A8E] group-hover:border-[#007A8E]/25 transition-all">
                <Play className="w-3 h-3 fill-current" />
              </div>
            </button>

            <button 
              onClick={() => handleSampleTrigger("cerberus")}
              className="w-full flex items-center justify-between p-3.5 rounded-xl bg-slate-950/60 border border-slate-900 hover:border-[#007A8E]/30 hover:bg-[#007A8E]/[0.02] hover:shadow-[0_0_15px_rgba(0,122,142,0.03)] transition-all duration-300 group btn-premium-click cursor-pointer"
            >
              <div className="space-y-1 text-left">
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-semibold text-white group-hover:text-[#007A8E] transition-colors font-sans">Cerberus Agent</span>
                  <span className="px-1.5 py-0.5 rounded text-[8px] font-mono bg-[#4B9CD3]/10 text-[#4B9CD3] border border-[#4B9CD3]/20">High Risk</span>
                </div>
                <div className="text-[9px] text-slate-500 font-mono">Boot event broadcast triggers & remote logs persistence</div>
              </div>
              <div className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-500 group-hover:text-[#007A8E] group-hover:border-[#007A8E]/25 transition-all">
                <Play className="w-3 h-3 fill-current" />
              </div>
            </button>
          </div>
        </div>
      </div>

      {/* Incident Investigation History Log (Obsidian Cards) */}
      <div className="space-y-3.5">
        <div className="flex items-center justify-between px-2">
          <span className="text-micro-label">Incident Investigation History</span>
          <span className="text-[9px] text-slate-500 font-mono tracking-widest uppercase">{jobs.length} logs completed</span>
        </div>

        <div className="space-y-3">
          {jobs.length === 0 ? (
            <div className="bracket-card rounded-xl p-10 text-center text-slate-500 text-xs italic font-mono bg-[#0d1217]">
              No active forensic logs found. Upload an APK or trigger a Trojan simulation above.
            </div>
          ) : (
            jobs.map((job) => (
              <div 
                key={job.id} 
                onClick={() => onSelectJob(job.id)}
                className="bracket-card p-4 bg-[#0d1217]/80 border border-white/[0.01] hover:border-[#007A8E]/15 hover:bg-[#131920] transition-all duration-350 cursor-pointer group flex flex-col sm:flex-row sm:items-center justify-between gap-4"
              >
                <div className="flex items-center space-x-4 min-w-0">
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-850 text-slate-500 group-hover:text-[#007A8E] group-hover:border-[#007A8E]/20 transition-all flex-shrink-0">
                    <FileText className="w-4 h-4" />
                  </div>
                  <div className="min-w-0">
                    <div className="text-xs font-semibold text-white group-hover:text-[#007A8E] transition-colors truncate font-sans" title={job.filename}>
                      {job.filename}
                    </div>
                    <div className="text-[9px] text-slate-500 font-mono mt-1 flex items-center space-x-2.5">
                      <span>FAMILY: {job.malware_family || "Unknown"}</span>
                      <span>•</span>
                      <span>ID: {job.id.slice(0, 8)}...</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center justify-between sm:justify-end gap-6 flex-shrink-0">
                  <div className="flex items-center space-x-1.5 text-[9px] text-slate-500 font-mono">
                    <Clock className="w-3 h-3" />
                    <span>
                      {job.completed_at 
                        ? new Date(job.completed_at).toLocaleDateString() 
                        : new Date(job.created_at).toLocaleDateString()
                      }
                    </span>
                  </div>

                  <span className={`px-2 py-0.5 rounded text-[8px] font-bold font-mono border ${
                    job.severity === "Critical" ? "bg-[#007A8E]/10 text-[#007A8E] border-[#007A8E]/20" :
                    job.severity === "High" ? "bg-[#4B9CD3]/10 text-[#4B9CD3] border-[#4B9CD3]/20" :
                    job.severity === "Medium" ? "bg-[#5B9C7D]/10 text-[#5B9C7D] border-[#5B9C7D]/20" :
                    "bg-[#2C5F2D]/10 text-[#5B9C7D] border-[#2C5F2D]/20"
                  }`}>
                    {job.severity || "QUEUED"}
                  </span>

                  <div className="flex items-center space-x-4">
                    <div className="text-right font-mono min-w-[32px]">
                      <span className="text-xs font-extrabold text-white">{job.risk_score !== null ? `${job.risk_score}%` : "—"}</span>
                    </div>
                    
                    <button 
                      onClick={(e) => handleDeleteJob(job.id, e)}
                      className="text-slate-500 hover:text-[#007A8E] p-1.5 rounded-lg border border-transparent hover:border-slate-800 hover:bg-slate-900 transition-all btn-premium-click cursor-pointer"
                      title="Purge analysis record"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

              </div>
            ))
          )}
        </div>
      </div>

    </div>
  );
}
