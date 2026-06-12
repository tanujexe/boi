import React, { useState, useEffect, useRef } from "react";
import { 
  Upload, Play, Terminal, Trash2, Eye, Cpu, 
  Activity, Clock, AlertTriangle, ShieldCheck, 
  Settings, Server, Info, ArrowRight, CheckCircle2
} from "lucide-react";

export default function V2UploadPage({ onSelectJob, onStartLoading, onStopLoading }) {
  const [dragActive, setDragActive] = useState(false);
  const [analysisMode, setAnalysisMode] = useState("full");
  const [timeoutSeconds, setTimeoutSeconds] = useState(180);
  const [jobs, setJobs] = useState([]);
  
  // Active running job state for live telemetry
  const [activeJob, setActiveJob] = useState(null);
  const [liveLogs, setLiveLogs] = useState([]);
  const [progress, setProgress] = useState(0);
  const [stage, setStage] = useState("");
  
  const terminalEndRef = useRef(null);
  const terminalContainerRef = useRef(null);
  
  // Buffering queue for WebSocket telemetry events
  const logQueue = useRef([]);
  const animationFrameId = useRef(null);

  const fetchJobs = async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/v2/jobs");
      if (res.ok) {
        const data = await res.json();
        setJobs(data);
      }
    } catch (err) {
      console.error("Error fetching v2 jobs:", err);
    }
  };

  useEffect(() => {
    fetchJobs();
  }, []);

  // Log throttling and capping at 200 logs
  useEffect(() => {
    const flushLogs = () => {
      if (logQueue.current.length > 0) {
        const nextLogs = [...logQueue.current];
        logQueue.current = [];
        setLiveLogs(prev => {
          const combined = [...prev, ...nextLogs];
          if (combined.length > 200) {
            return combined.slice(combined.length - 200);
          }
          return combined;
        });
      }
      animationFrameId.current = requestAnimationFrame(flushLogs);
    };
    animationFrameId.current = requestAnimationFrame(flushLogs);
    return () => {
      if (animationFrameId.current) {
        cancelAnimationFrame(animationFrameId.current);
      }
    };
  }, []);

  // Auto scroll terminal logs only when user is near bottom
  useEffect(() => {
    const el = terminalContainerRef.current;
    if (!el) return;
    const isNearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 120;
    if (isNearBottom) {
      el.scrollTop = el.scrollHeight;
    }
  }, [liveLogs]);

  // WebSocket connection for live analysis tracking
  useEffect(() => {
    if (!activeJob) return;

    let ws = null;
    let isMounted = true;

    // Reset log buffer queue for a new run
    logQueue.current = [];
    setLiveLogs([]);

    const connectWS = () => {
      ws = new WebSocket(`ws://127.0.0.1:8000/api/v2/ws/${activeJob.id}`);
      
      ws.onopen = () => {
        if (!isMounted) return;
        logQueue.current.push({ type: "SYSTEM", text: "[SOCKET] Connected to dynamic analysis telemetry channel." });
      };
      
      ws.onmessage = (event) => {
        if (!isMounted) return;
        try {
          const data = JSON.parse(event.data);
          
          if (data.type === "STATUS_CHANGE") {
            setStage(data.status);
            if (data.status === "COMPLETED") {
              setProgress(100);
              logQueue.current.push({ type: "SYSTEM", text: `[COMPLETE] Sandbox execution finished. Risk: ${data.risk_score} (${data.severity})` });
              fetchJobs(); // Refresh job list
            } else if (data.status === "FAILED") {
              logQueue.current.push({ type: "ERROR", text: `[CRITICAL_FAIL] Pipeline halted: ${data.error || "Unknown error"}` });
              fetchJobs();
            } else if (data.status === "CANCELLED") {
              logQueue.current.push({ type: "WARN", text: `[CANCELLED] Sandbox analysis terminated by user request.` });
              fetchJobs();
            }
          } else if (data.type === "LOG" || data.type === "SYSTEM") {
            let logType = "INFO";
            const text = data.message || "";
            if (text.includes("[SMS_SEND]") || text.includes("[DEX_LOAD]") || text.includes("exfiltration") || text.includes("SMS transmission")) {
              logType = "ALERT";
            } else if (text.includes("[EVASION") || text.includes("evade") || text.includes("root_existence_check")) {
              logType = "WARN";
            } else if (text.includes("Frida:") || text.includes("attached")) {
              logType = "FRIDA";
            } else if (text.includes("[SYSTEM") || text.includes("System:")) {
              logType = "SYSTEM";
            }
            logQueue.current.push({ type: logType, text });
          }
        } catch (err) {
          console.error("Failed to parse WS payload:", err);
        }
      };

      ws.onclose = () => {
        if (!isMounted) return;
        logQueue.current.push({ type: "SYSTEM", text: "[SOCKET] Connection closed." });
      };

      ws.onerror = (err) => {
        console.error("WebSocket error:", err);
      };
    };

    connectWS();

    // Poll status fallback in case WebSocket fails
    const statusInterval = setInterval(async () => {
      try {
        const res = await fetch(`http://127.0.0.1:8000/api/v2/jobs/${activeJob.id}/status`);
        if (res.ok) {
          const statusData = await res.json();
          if (!isMounted) return;
          setProgress(statusData.progress);
          setStage(statusData.status);
          if (statusData.status === "COMPLETED" || statusData.status === "FAILED" || statusData.status === "TIMEOUT" || statusData.status === "CANCELLED") {
            clearInterval(statusInterval);
            if (ws) ws.close();
            fetchJobs();
          }
        }
      } catch (err) {
        console.error(err);
      }
    }, 4000);

    return () => {
      isMounted = false;
      clearInterval(statusInterval);
      if (ws) ws.close();
    };
  }, [activeJob]);

  const handleCancelJob = async () => {
    if (!activeJob) return;
    if (confirm("Are you sure you want to cancel the active analysis sandbox run?")) {
      try {
        const res = await fetch(`http://127.0.0.1:8000/api/v2/jobs/${activeJob.id}/cancel`, {
          method: "POST"
        });
        if (res.ok) {
          setStage("CANCELLED");
          logQueue.current.push({ type: "SYSTEM", text: "[USER_ACTION] Cancellation signal dispatched to backend." });
          fetchJobs();
        }
      } catch (err) {
        console.error("Error cancelling job:", err);
      }
    }
  };


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
      await uploadFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = async (e) => {
    if (e.target.files && e.target.files[0]) {
      await uploadFile(e.target.files[0]);
    }
  };

  const uploadFile = async (fileToUpload) => {
    onStartLoading();
    setLiveLogs([]);
    setProgress(5);
    setStage("QUEUED");

    const formData = new FormData();
    formData.append("file", fileToUpload);

    try {
      const res = await fetch(`http://127.0.0.1:8000/api/v2/jobs?analysis_mode=${analysisMode}&timeout_seconds=${timeoutSeconds}`, {
        method: "POST",
        body: formData,
      });

      if (res.ok) {
        const jobData = await res.json();
        setActiveJob(jobData);
        setStage(jobData.status);
        setProgress(jobData.progress);
        
        setLiveLogs([
          { type: "SYSTEM", text: `[UPLOAD] File '${fileToUpload.name}' uploaded successfully.` },
          { type: "SYSTEM", text: `[JOB_INIT] Queued sandbox execution ID: ${jobData.id}` }
        ]);

        if (jobData.status === "COMPLETED") {
          // Cached response
          setProgress(100);
          setLiveLogs(prev => [...prev, { type: "SYSTEM", text: "[CACHE_HIT] Report retrieved from database cache. Instantly available." }]);
          fetchJobs();
        }
      } else {
        alert("Sandbox analysis submission failed. Check backend status.");
      }
    } catch (err) {
      console.error(err);
      alert("Error contacting the Sandbox orchestrator.");
    } finally {
      onStopLoading();
    }
  };

  const handleSampleTrigger = async (sampleKey) => {
    onStartLoading();
    setLiveLogs([]);
    setProgress(5);
    setStage("QUEUED");

    try {
      // Simulate file upload logic for default samples
      const mockFile = new File(["simulation"], `simulated_${sampleKey}.apk`, { type: "application/vnd.android.package-archive" });
      await uploadFile(mockFile);
    } catch (err) {
      console.error(err);
      alert("Error submitting Trojan simulation.");
      onStopLoading();
    }
  };

  const handleDeleteJob = async (jobId, e) => {
    e.stopPropagation();
    if (confirm("Permanently purge this sandbox analysis log?")) {
      try {
        const res = await fetch(`http://127.0.0.1:8000/api/v2/jobs/${jobId}`, {
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
    <div className="w-full flex flex-col space-y-8 relative z-10 py-4 mx-auto animate-fade-in">

      {/* Title Header */}
      <div className="flex items-center justify-between border-b border-white/[0.02] pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-[0.2em] text-[#E8F5F2] font-mono">
            DYNAMIC_SANDBOX<span className="text-[#007A8E]">_V2</span>
          </h1>
          <p className="text-[10px] text-slate-500 font-mono mt-1 uppercase tracking-wider">
            Active Instrumentation Telemetry & Dynamic Behavioral Analysis
          </p>
        </div>
        
        <div className="flex items-center space-x-2 bg-[#0d1217] border border-white/[0.03] px-3.5 py-1.5 rounded-xl text-[9px] font-mono text-slate-400">
          <Server className="w-3 h-3 text-[#007A8E]" />
          <span>AVD TARGET: API 30 x86_64</span>
        </div>
      </div>

      {/* Config Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Analysis Settings */}
        <div className="bracket-card p-5 bg-[#0d1217] flex flex-col justify-between space-y-4 md:col-span-2">
          <div>
            <div className="text-micro-label flex items-center space-x-2">
              <Settings className="w-3.5 h-3.5 text-[#007A8E]" />
              <span>ORCHESTRATOR SANDBOX CONFIGURATION</span>
            </div>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 mt-4">
              <div>
                <label className="text-[9px] font-mono text-slate-500 uppercase tracking-widest block mb-2">Analysis Level</label>
                <div className="flex space-x-2">
                  <button 
                    onClick={() => setAnalysisMode("full")}
                    className={`flex-1 py-2 rounded-xl text-[10px] font-mono border transition-all ${
                      analysisMode === "full" 
                        ? "bg-[#007A8E]/10 border-[#007A8E]/55 text-white" 
                        : "bg-slate-950 border-slate-900 text-slate-400 hover:border-slate-800"
                    }`}
                  >
                    FULL (STATIC+DYNAMIC)
                  </button>
                  <button 
                    onClick={() => setAnalysisMode("static_only")}
                    className={`flex-1 py-2 rounded-xl text-[10px] font-mono border transition-all ${
                      analysisMode === "static_only" 
                        ? "bg-[#007A8E]/10 border-[#007A8E]/55 text-white" 
                        : "bg-slate-950 border-slate-900 text-slate-400 hover:border-slate-800"
                    }`}
                  >
                    STATIC ONLY
                  </button>
                </div>
              </div>

              <div>
                <label className="text-[9px] font-mono text-slate-500 uppercase tracking-widest block mb-2">Sandbox Tracing Window</label>
                <div className="flex space-x-1">
                  {[60, 120, 180, 300].map(s => (
                    <button
                      key={s}
                      onClick={() => setTimeoutSeconds(s)}
                      className={`flex-1 py-2 rounded-xl text-[10px] font-mono border transition-all ${
                        timeoutSeconds === s
                          ? "bg-[#007A8E]/10 border-[#007A8E]/55 text-white"
                          : "bg-slate-950 border-slate-900 text-slate-400 hover:border-slate-800"
                      }`}
                    >
                      {s}s
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-2 text-[9px] text-slate-500 font-mono border-t border-white/[0.02] pt-3">
            <Info className="w-3.5 h-3.5 text-[#007A8E] flex-shrink-0" />
            <span>Full mode boots the emulator, attaches Frida hooks dynamically, and monitors system calls.</span>
          </div>
        </div>

        {/* Demo Quick Samples */}
        <div className="bracket-card p-5 bg-[#0d1217] flex flex-col justify-between space-y-4">
          <div>
            <div className="text-micro-label">TROJAN SIMULATORS (DEMO STACK)</div>
            <p className="text-[9px] text-slate-500 font-mono mt-1.5 leading-relaxed">
              Instantly fire high-fidelity Trojan behavioral simulations to review the v2 instrumentation pipeline:
            </p>
          </div>

          <div className="flex flex-col space-y-2">
            {["Anubis", "SharkBot", "Cerberus"].map(trojan => (
              <button
                key={trojan}
                onClick={() => handleSampleTrigger(trojan.toLowerCase())}
                className="flex items-center justify-between px-3 py-2 rounded-xl bg-slate-950/60 border border-slate-900 hover:border-[#007A8E]/30 hover:bg-[#007A8E]/[0.02] text-[10px] font-mono text-slate-350 transition-all cursor-pointer group"
              >
                <span>SIMULATE_{trojan.toUpperCase()}_RUN</span>
                <Play className="w-2.5 h-2.5 fill-current text-slate-500 group-hover:text-[#007A8E] transition-colors" />
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main interaction frame: Upload / Live Monitor */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left pane: Upload Dropzone */}
        <div className="lg:col-span-1 flex flex-col space-y-6">
          <div 
            onDragEnter={handleDrag}
            onDragOver={handleDrag}
            onDragLeave={handleDrag}
            onDrop={handleDrop}
            className={`bracket-card p-8 flex flex-col items-center justify-center text-center space-y-6 transition-all relative overflow-hidden min-h-[320px] ${
              dragActive 
                ? "border-[#007A8E] bg-[#007A8E]/[0.03] scale-[1.01]" 
                : "bg-[#0d1217]"
            }`}
          >
            <input 
              type="file" 
              accept=".apk,.zip" 
              className="absolute inset-0 opacity-0 cursor-pointer z-10"
              onChange={handleFileChange}
            />
            
            <div className="relative">
              <div className="absolute inset-0 bg-[#007A8E]/15 rounded-full blur-md" />
              <div className="relative bg-[#070b0f] p-4.5 rounded-full border border-[#007A8E]/25 text-[#007A8E]">
                <Upload className="w-6 h-6" />
              </div>
            </div>

            <div className="space-y-1.5">
              <h3 className="text-xs font-semibold text-white font-sans uppercase tracking-wider">DEPLOY TARGET APK</h3>
              <p className="text-[9.5px] text-slate-500 font-mono leading-relaxed">
                Drag & drop APK binary, or click to browse files<br />
                <span className="text-[#007A8E] font-semibold">Ready for instrumentation</span>
              </p>
            </div>
          </div>
        </div>

        {/* Right pane: CRT Live Telemetry Monitor */}
        <div className="lg:col-span-2 flex flex-col">
          <div className="bracket-card bg-[#090d12] flex flex-col flex-1 min-h-[320px] border border-white/[0.01] relative overflow-hidden">
            
            {/* Terminal Header */}
            <div className="h-10 border-b border-white/[0.02] bg-[#0c1117] flex items-center justify-between px-4">
              <div className="flex items-center space-x-2 font-mono text-[9px] text-[#007A8E] uppercase tracking-widest font-semibold">
                <Terminal className="w-3.5 h-3.5 text-[#007A8E] animate-pulse" />
                <span>SANDBOX_TELEMETRY_LOGS</span>
              </div>
              
              {stage && (
                <div className="flex items-center space-x-2 font-mono text-[9px]">
                  <span className="text-slate-500 uppercase">STAGE:</span>
                  <span className="text-white px-2 py-0.5 rounded bg-slate-900 border border-white/[0.04]">{stage}</span>
                </div>
              )}
            </div>

            {/* CRT Screen scanline overlay */}
            <div className="absolute inset-0 pointer-events-none crt-scanlines opacity-5 z-20" />

            {/* Terminal Screen content */}
            <div 
              ref={terminalContainerRef}
              className="flex-1 p-4 overflow-y-auto max-h-[300px] font-mono text-[10px] space-y-2 bg-[#06090d] text-slate-350 select-text"
            >
              {liveLogs.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-center text-slate-600 italic py-16">
                  <Activity className="w-6 h-6 text-slate-700 mb-2 animate-pulse" />
                  <span>Awaiting Sandbox target initialization...</span>
                </div>
              ) : (
                liveLogs.map((log, idx) => {
                  let colorClass = "text-slate-400";
                  let prefix = "[*] ";
                  
                  if (log.type === "SYSTEM") {
                    colorClass = "text-cyan-400 font-semibold";
                    prefix = "[SYS] ";
                  } else if (log.type === "ALERT") {
                    colorClass = "text-red-500 font-bold animate-pulse";
                    prefix = "[ALERT] ";
                  } else if (log.type === "WARN") {
                    colorClass = "text-yellow-500 font-semibold";
                    prefix = "[WARN] ";
                  } else if (log.type === "FRIDA") {
                    colorClass = "text-[#007A8E] font-semibold";
                    prefix = "[FRIDA] ";
                  } else if (log.type === "ERROR") {
                    colorClass = "text-red-600 font-extrabold";
                    prefix = "[ERR] ";
                  }

                  return (
                    <div key={idx} className={`leading-relaxed whitespace-pre-wrap ${colorClass}`}>
                      {prefix}{log.text}
                    </div>
                  );
                })
              )}
              <div ref={terminalEndRef} />
            </div>

            {/* Progress Bar Row */}
            {activeJob && (
              <div className="p-4 bg-[#0c1117] border-t border-white/[0.02] flex items-center justify-between gap-6">
                <div className="flex-1">
                  <div className="flex items-center justify-between text-[9px] font-mono text-slate-500 mb-1">
                    <span>SANDBOX TELEMETRY TRACE</span>
                    <span>{progress}%</span>
                  </div>
                  <div className="w-full bg-slate-950 h-2.5 rounded-full overflow-hidden border border-white/[0.02] relative">
                    <div 
                      className={`h-full rounded-full transition-all duration-500 ${
                        stage === "CANCELLED"
                          ? "bg-slate-700"
                          : stage === "FAILED"
                          ? "bg-red-650"
                          : "bg-gradient-to-r from-[#007A8E] to-cyan-500"
                      }`}
                      style={{ width: `${progress}%` }}
                    />
                  </div>
                </div>
                
                {stage === "COMPLETED" && (
                  <button
                    onClick={() => onSelectJob(activeJob.id)}
                    className="flex-shrink-0 flex items-center space-x-2 px-4 py-2 rounded-xl bg-[#007A8E]/10 border border-[#007A8E]/40 hover:bg-[#007A8E]/20 text-[10px] font-mono text-white transition-all cursor-pointer animate-fade-in"
                  >
                    <span>VIEW REPORT</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                )}

                {stage !== "COMPLETED" && stage !== "FAILED" && stage !== "CANCELLED" && (
                  <button
                    onClick={handleCancelJob}
                    className="flex-shrink-0 flex items-center space-x-2 px-4 py-2 rounded-xl bg-red-950/20 border border-red-900/60 hover:bg-red-950/40 text-[10px] font-mono text-red-400 transition-all cursor-pointer animate-fade-in"
                  >
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>CANCEL RUN</span>
                  </button>
                )}
              </div>
            )}

          </div>
        </div>

      </div>

      {/* Historical sandbox runs (V2 logs) */}
      <div className="space-y-4 pt-4">
        <div className="flex items-center justify-between px-2">
          <span className="text-micro-label">Dynamic Sandbox Investigation Logs (v2)</span>
          <span className="text-[9px] text-slate-500 font-mono uppercase tracking-widest">{jobs.length} completed sessions</span>
        </div>

        <div className="space-y-3">
          {jobs.length === 0 ? (
            <div className="bracket-card rounded-xl p-10 text-center text-slate-500 text-xs italic font-mono bg-[#0d1217]">
              No v2 sandbox traces found. Submit an APK above to execute dynamic analysis.
            </div>
          ) : (
            jobs.map((j) => (
              <div 
                key={j.id} 
                onClick={() => onSelectJob(j.id)}
                className="bracket-card p-4.5 bg-[#0d1217] border border-white/[0.01] hover:border-[#007A8E]/20 hover:bg-[#131920] transition-all duration-300 cursor-pointer group flex flex-col sm:flex-row sm:items-center justify-between gap-4"
              >
                <div className="flex items-center space-x-4 min-w-0">
                  <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-900 text-slate-500 group-hover:text-[#007A8E] group-hover:border-[#007A8E]/25 transition-all flex-shrink-0">
                    <Terminal className="w-4 h-4" />
                  </div>
                  <div className="min-w-0">
                    <div className="text-xs font-semibold text-white group-hover:text-[#007A8E] transition-colors truncate font-sans">
                      {j.filename}
                    </div>
                    <div className="text-[9px] text-slate-500 font-mono mt-1 flex items-center space-x-2.5">
                      <span>PACKAGE: {j.package_name || "unknown"}</span>
                      <span>•</span>
                      <span>MODE: {j.analysis_mode.toUpperCase()}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center justify-between sm:justify-end gap-6 flex-shrink-0">
                  <div className="flex items-center space-x-1.5 text-[9px] text-slate-500 font-mono">
                    <Clock className="w-3 h-3" />
                    <span>{new Date(j.created_at).toLocaleDateString()}</span>
                  </div>

                  {j.verdict && (
                    <span className={`px-2 py-0.5 rounded text-[8px] font-bold font-mono border uppercase ${
                      j.verdict === "malicious" ? "bg-red-500/10 text-red-400 border-red-500/20" :
                      j.verdict === "suspicious" ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/20" :
                      "bg-[#2C5F2D]/10 text-[#5B9C7D] border-[#2C5F2D]/20"
                    }`}>
                      {j.verdict}
                    </span>
                  )}

                  <div className="flex items-center space-x-4">
                    <div className="text-right font-mono min-w-[32px]">
                      <span className="text-xs font-extrabold text-white">{j.risk_score !== null ? `${j.risk_score}%` : "—"}</span>
                    </div>
                    
                    <button 
                      onClick={(e) => handleDeleteJob(j.id, e)}
                      className="text-slate-500 hover:text-red-400 p-1.5 rounded-lg border border-transparent hover:border-slate-800 hover:bg-slate-900 transition-all btn-premium-click cursor-pointer"
                      title="Purge trace logs"
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
