import React, { useState, useEffect } from "react";
import { 
  Fingerprint, 
  ChevronRight, 
  Map,
  Shield,
  HelpCircle,
  Activity,
  Layers,
  Terminal,
  Server,
  ShieldAlert
} from "lucide-react";

export default function ThreatIntel({ jobId, setPage }) {
  const [job, setJob] = useState(null);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedMitre, setSelectedMitre] = useState(null);

  // MITRE ATT&CK Mobile Matrix layout
  const mitreBaseTactics = [
    {
      tactic: "Initial Access",
      techniques: [
        { name: "Deliver Malicious App", id: "T1474", desc: "Delivery of a malicious application to the device through app stores or side-loading.", mitigation: "Use official app vetting, verify developer certificates, and monitor side-loading flags." },
        { name: "Drive-by Download", id: "T1456", desc: "Download triggered without user interaction, abusing browser vulnerabilities.", mitigation: "Enforce network firewalls and browser security updates." }
      ]
    },
    {
      tactic: "Execution",
      techniques: [
        { name: "Dynamic Loading", id: "T1407", desc: "Loading dynamic executable code at runtime (DexClassLoader/dalvik system commands).", mitigation: "Restrict read/write on internal storage classes and audit dynamic class invocations." },
        { name: "System Broadcast", id: "T1628", desc: "Triggering execution via system broadcast receivers (e.g., RECEIVE_BOOT_COMPLETED).", mitigation: "Audit receiver declarations inside AndroidManifest.xml and prevent unsolicited launches." }
      ]
    },
    {
      tactic: "Defense Evasion",
      techniques: [
        { name: "Software Packing", id: "T1406", desc: "Obfuscating files or packing payloads to prevent scanner lookups.", mitigation: "Enforce unpacking rules, dynamic debugging monitors, and memory scanners." },
        { name: "Obfuscated Info", id: "T1612", desc: "Using reflection or encrypted strings to hide behavior intent.", mitigation: "De-obfuscate string dictionaries and trace reflection API hooks statically." }
      ]
    },
    {
      tactic: "Credential Access",
      techniques: [
        { name: "Overlay Phishing", id: "T1417.002", desc: "Drawing transparent or custom UI layers over banking inputs to steal credentials.", mitigation: "Disable SYSTEM_ALERT_WINDOW permissions or verify window visibility tags dynamically." },
        { name: "Keylogging", id: "T1417.001", desc: "Programmatic capture of keystrokes utilizing Accessibility services.", mitigation: "Audit accessibility service requests and restrict access to system inputs." }
      ]
    },
    {
      tactic: "Collection",
      techniques: [
        { name: "SMS Interception", id: "T1636.004", desc: "Interception of incoming SMS transaction and OTP verification tokens.", mitigation: "Block access to RECEIVE_SMS and READ_SMS APIs unless critical." },
        { name: "Data Exfiltration", id: "T1646", desc: "Exfiltration of captured data packages back to C2 servers.", mitigation: "Inspect host callbacks dynamically, analyze traffic streams, and block listed C2 IP nodes." }
      ]
    }
  ];

  const fetchJobData = async () => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/jobs/${jobId}`);
      if (res.ok) {
        const data = await res.json();
        setJob(data.job);
        setReport(data.report);
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

  if (!jobId) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center space-y-4 min-h-[50vh] text-center">
        <Fingerprint className="w-12 h-12 text-[#007A8E] animate-pulse" />
        <h2 className="text-lg font-bold font-mono text-[#E8F5F2] uppercase tracking-wider">No Active Threat Profile</h2>
        <p className="text-xs text-slate-500 max-w-sm">
          Select an Android package signature from history or upload a target APK to view threat intelligence mapping.
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
        <span className="text-xs font-mono text-[#007A8E] tracking-wider uppercase animate-pulse">Mapping Threat Frameworks...</span>
      </div>
    );
  }

  const isTechniqueFlagged = (techId) => {
    if (!report || !report.mitre_mapping) return false;
    const mappedIds = report.mitre_mapping.map(m => m.id);
    
    // Fallback UI helper mapping matching malware families
    const family = job?.malware_family || "";
    if (techId === "T1417.001" && (family.includes("Anubis") || family.includes("Cerberus"))) return true;
    if (techId === "T1417.002" && (family.includes("Anubis") || family.includes("Shark"))) return true;
    if (techId === "T1636.004" && !family.includes("Benign")) return true;
    if (techId === "T1407" && family.includes("Shark")) return true;
    if (techId === "T1406" && family.includes("Shark")) return true;
    if (techId === "T1628" && !family.includes("Benign")) return true;
    
    return mappedIds.includes(techId);
  };

  return (
    <div className="flex-1 flex flex-col space-y-8 select-none p-4 md:p-6 max-w-7xl mx-auto w-full animate-fade-in">
      
      {/* Title Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-900 pb-5">
        <div>
          <h2 className="text-xl font-bold text-[#E8F5F2] font-sans flex items-center space-x-2.5">
            <Fingerprint className="w-5 h-5 text-[#007A8E]" />
            <span className="uppercase tracking-wide font-semibold">Threat Intelligence Correlation</span>
          </h2>
          <p className="text-xs text-slate-500 font-mono mt-1.5 leading-relaxed">
            Mappings to MITRE ATT&CK Mobile matrix TTPs and OWASP Mobile Top 10 security standards.
          </p>
        </div>
      </div>

      {/* MITRE Heatmap Matrix */}
      <div className="bracket-card p-6 bg-[#0d1217] space-y-5">
        <div className="flex items-center space-x-2 border-b border-slate-900 pb-3">
          <Map className="w-4 h-4 text-[#007A8E]" />
          <h3 className="text-sm font-semibold text-white font-sans">MITRE ATT&CK Mobile Matrix Heatmap</h3>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-5 gap-4 overflow-x-auto pb-2">
          {mitreBaseTactics.map((t) => (
            <div key={t.tactic} className="space-y-3 min-w-[150px] flex-1">
              <div className="text-[9px] text-slate-400 font-mono uppercase tracking-[0.15em] border-b border-slate-900 pb-2 flex items-center justify-between">
                <span>{t.tactic}</span>
                <span className="w-1 h-1 rounded-full bg-slate-700" />
              </div>
              <div className="space-y-2.5">
                {t.techniques.map((tech) => {
                  const flagged = isTechniqueFlagged(tech.id);
                  const isSelected = selectedMitre?.id === tech.id;
                  return (
                    <div
                      key={tech.id}
                      onClick={() => setSelectedMitre(tech)}
                      className={`p-3.5 rounded-xl border text-left cursor-pointer transition-all duration-350 relative overflow-hidden btn-premium-click flex flex-col justify-between ${
                        flagged 
                          ? "bg-[#007A8E]/[0.03] border-[#007A8E]/25 text-[#007A8E] shadow-[inset_0_1px_1px_0_rgba(0,122,142,0.03)] hover:bg-[#007A8E]/10" 
                          : "bg-slate-950/20 border-slate-900 text-slate-500 hover:border-slate-800 hover:text-slate-350 hover:bg-slate-900/10"
                      } ${isSelected ? "ring-1 ring-[#4B9CD3] border-transparent shadow-[0_4px_20px_rgba(75,156,211,0.08)]" : ""}`}
                    >
                      {flagged && (
                        <span className="absolute top-1.5 right-1.5 w-1 h-1 rounded-full bg-[#007A8E] animate-pulse" />
                      )}
                      <span className="text-[8px] font-mono text-slate-500 leading-none">{tech.id}</span>
                      <span className="text-[11px] font-semibold font-sans mt-2 leading-snug">{tech.name}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Split Details & OWASP Map */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Technique Specification Panel */}
        <div className="bracket-card p-6 bg-[#0d1217] flex flex-col justify-between min-h-[300px]">
          <div className="space-y-4 h-full flex flex-col">
            <div className="flex items-center space-x-2 border-b border-slate-900 pb-3">
              <HelpCircle className="w-4 h-4 text-[#007A8E]" />
              <h3 className="text-sm font-semibold text-white font-sans">Technique Specifications</h3>
            </div>

            {selectedMitre ? (
              <div className="space-y-4 font-mono text-xs flex-1 flex flex-col justify-between animate-fade-in">
                <div className="space-y-3">
                  <div className="flex justify-between border-b border-slate-900 pb-2">
                    <span className="text-slate-500">Technique Name:</span>
                    <span className="text-white font-semibold font-sans">{selectedMitre.name}</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-900 pb-2">
                    <span className="text-slate-500">ID Reference:</span>
                    <span className="text-[#007A8E] font-bold">{selectedMitre.id}</span>
                  </div>
                  <div className="flex flex-col space-y-1.5">
                    <span className="text-slate-500 font-mono text-[9px] uppercase tracking-wider">Description:</span>
                    <p className="text-slate-400 font-sans leading-relaxed text-[11px] bg-slate-950/40 border border-slate-900/60 rounded-xl p-3 select-text">
                      {selectedMitre.desc}
                    </p>
                  </div>
                  {selectedMitre.mitigation && (
                    <div className="flex flex-col space-y-1.5 pt-1">
                      <span className="text-slate-500 font-mono text-[9px] uppercase tracking-wider">Suggested Mitigation:</span>
                      <p className="text-slate-400 font-sans leading-relaxed text-[11px] bg-[#007A8E]/[0.02] border border-[#007A8E]/10 rounded-xl p-3 select-text">
                        {selectedMitre.mitigation}
                      </p>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="text-xs text-slate-500 italic py-16 text-center font-mono flex-1 flex flex-col items-center justify-center space-y-2">
                <Activity className="w-8 h-8 text-slate-750 animate-pulse" />
                <span>Select a technique cell in the matrix heatmap above to view specifications.</span>
              </div>
            )}
          </div>
        </div>

        {/* OWASP Mobile Top 10 Mapping */}
        <div className="bracket-card p-6 bg-[#0d1217] space-y-4 min-h-[300px] flex flex-col">
          <div className="flex items-center space-x-2 border-b border-slate-900 pb-3">
            <Shield className="w-4 h-4 text-[#007A8E]" />
            <h3 className="text-sm font-semibold text-white font-sans">OWASP Mobile Top 10 Map</h3>
          </div>

          <div className="space-y-3 overflow-y-auto pr-1 flex-1 max-h-[300px]">
            {!report || !report.owasp_mapping || report.owasp_mapping.length === 0 ? (
              <div className="text-xs text-slate-500 italic py-16 text-center font-mono flex flex-col items-center justify-center space-y-2">
                <Layers className="w-8 h-8 text-slate-750" />
                <span>No active OWASP vulnerability mappings generated.</span>
              </div>
            ) : (
              report.owasp_mapping.map((o, idx) => (
                <div key={idx} className="p-3.5 rounded-xl bg-slate-950/40 border border-slate-900/60 flex flex-col space-y-1.5 hover:border-slate-800 transition-colors">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-semibold text-[#007A8E] font-mono">{o.category}</span>
                    <span className="px-1.5 py-0.5 rounded text-[8px] font-mono bg-slate-900 border border-slate-850 text-slate-500 uppercase">RISK_MAP</span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed font-sans">{o.description}</p>
                </div>
              ))
            )}
          </div>
        </div>

      </div>

      {/* Navigation Footer */}
      <div className="flex justify-end pt-4 border-t border-slate-900">
        <button 
          onClick={() => setPage("report")}
          className="flex items-center space-x-1.5 px-4 py-2 bg-[#007A8E]/10 text-[#007A8E] hover:bg-[#007A8E] hover:text-white rounded-lg text-xs font-semibold font-mono transition-all border border-[#007A8E]/20 hover:border-transparent btn-premium-click cursor-pointer"
        >
          <span>Proceed to Forensic Analysis Report</span>
          <ChevronRight className="w-4 h-4" />
        </button>
      </div>

    </div>
  );
}
