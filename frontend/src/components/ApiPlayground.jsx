import React, { useState, useEffect } from "react";
import { 
  Terminal, 
  Key, 
  Plus, 
  Trash2, 
  Copy, 
  Check, 
  Code,
  ShieldCheck,
  AlertTriangle,
  FileCode,
  Info
} from "lucide-react";

export default function ApiPlayground() {
  const [keys, setKeys] = useState([]);
  const [keyName, setKeyName] = useState("");
  const [generatedKey, setGeneratedKey] = useState(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);
  const [docTab, setDocTab] = useState("curl");

  const fetchKeys = async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/api-keys");
      if (res.ok) {
        const data = await res.json();
        setKeys(data);
      }
    } catch (err) {
      console.error("Error fetching API keys:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchKeys();
  }, []);

  const handleGenerateKey = async (e) => {
    e.preventDefault();
    if (!keyName.trim()) return;
    
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/api-keys?name=${encodeURIComponent(keyName)}`, {
        method: "POST"
      });
      if (res.ok) {
        const data = await res.json();
        setGeneratedKey(data.full_key);
        setKeyName("");
        fetchKeys();
      } else {
        alert("Failed to generate API Key");
      }
    } catch (err) {
      console.error(err);
      alert("Error contacting API server");
    }
  };

  const handleRevokeKey = async (id) => {
    if (confirm("Revoke this API key? External systems using it will immediately fail.")) {
      try {
        const res = await fetch(`http://127.0.0.1:8000/api/api-keys/${id}`, {
          method: "DELETE"
        });
        if (res.ok) {
          fetchKeys();
        }
      } catch (err) {
        console.error(err);
      }
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const docSnippets = {
    curl: `# Step 1: Upload APK to scan
curl -X POST "http://127.0.0.1:8000/api/jobs/upload" \\
  -H "X-API-Key: sentinel_your_secret_key_here" \\
  -F "file=@/path/to/malicious_app.apk"

# Step 2: Poll analysis report results
curl -X GET "http://127.0.0.1:8000/api/jobs/your_job_uuid_here" \\
  -H "X-API-Key: sentinel_your_secret_key_here"`,

    python: `import requests
import time

API_KEY = "sentinel_your_secret_key_here"
BASE_URL = "http://127.0.0.1:8000/api"
headers = {"X-API-Key": API_KEY}

# 1. Post target APK to analysis queue
files = {"file": open("target_app.apk", "rb")}
res = requests.post(f"{BASE_URL}/jobs/upload", headers=headers, files=files)
job_id = res.json()["id"]
print(f"[*] Queued job ID: {job_id}")

# 2. Wait and poll status
while True:
    status_res = requests.get(f"{BASE_URL}/jobs/{job_id}", headers=headers).json()
    status = status_res["job"]["status"]
    print(f"[-] Current Status: {status}")
    if status in ["COMPLETED", "FAILED"]:
        break
    time.sleep(5)

print("[+] Investigation Report: ", status_res["report"]["executive_summary"])`,

    node: `const axios = require('axios');
const fs = require('fs');
const FormData = require('form-data');

const headers = { 'X-API-Key': 'sentinel_your_secret_key_here' };

async function runAudit() {
  const form = new FormData();
  form.append('file', fs.createReadStream('app.apk'));

  // Submit file
  const submitRes = await axios.post('http://127.0.0.1:8000/api/jobs/upload', form, {
    headers: { ...headers, ...form.getHeaders() }
  });
  
  const jobId = submitRes.data.id;
  console.log(\`Job successfully queued. ID: \${jobId}\`);
}`
  };

  const getDocFilename = () => {
    if (docTab === "curl") return "request_audit.sh";
    if (docTab === "python") return "sentinel_scan.py";
    return "sentinel_node.js";
  };

  return (
    <div className="flex-1 flex flex-col space-y-8 select-none p-4 md:p-6 max-w-7xl mx-auto w-full animate-fade-in">
      
      {/* Title Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-900 pb-5">
        <div>
          <h2 className="text-xl font-bold text-white font-sans flex items-center space-x-2.5">
            <Key className="w-5 h-5 text-[#007A8E]" />
            <span className="uppercase tracking-wide font-semibold text-white">API Management Playground</span>
          </h2>
          <p className="text-xs text-slate-500 font-mono mt-1.5">
            Generate and manage access credentials for automation scripts, CI/CD pipelines, and webhooks.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
        
        {/* Left Column: API Key Registry & Forms */}
        <div className="space-y-6">
          
          {/* Key Generation Form */}
          <div className="bracket-card p-6 bg-[#0d1217]">
            <h3 className="text-xs font-bold text-white font-mono uppercase tracking-[0.2em] mb-4 flex items-center space-x-2">
              <Plus className="w-4 h-4 text-[#4B9CD3]" />
              <span>Generate Authorized Key</span>
            </h3>

            <form onSubmit={handleGenerateKey} className="flex space-x-3">
              <input
                type="text"
                placeholder="Key Scope Name (e.g., Jenkins-Agent-01)"
                value={keyName}
                onChange={(e) => setKeyName(e.target.value)}
                className="flex-1 rounded-xl bg-slate-950/80 border border-slate-900 p-2.5 font-mono text-xs text-white placeholder-slate-600 focus:outline-none focus:border-[#007A8E] focus:ring-1 focus:ring-[#007A8E] transition-all custom-input"
                required
              />
              <button
                type="submit"
                className="px-4 py-2.5 bg-[#007A8E]/10 hover:bg-[#007A8E] text-[#007A8E] hover:text-white border border-[#007A8E]/20 hover:border-transparent rounded-xl text-xs font-mono font-semibold transition-all btn-premium-click cursor-pointer flex-shrink-0"
              >
                Generate
              </button>
            </form>

            {generatedKey && (
              <div className="mt-5 p-4 rounded-xl border border-amber-500/25 bg-amber-950/[0.08] relative space-y-2.5">
                <div className="text-[9px] text-amber-500 font-mono uppercase tracking-[0.2em] flex items-center space-x-1.5">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>Copy key now — it will not be displayed again</span>
                </div>
                <div className="flex items-center justify-between rounded-xl bg-slate-950 p-2.5 border border-slate-900 select-text">
                  <code className="text-xs text-white font-mono break-all">{generatedKey}</code>
                  <button 
                    onClick={() => copyToClipboard(generatedKey)}
                    className="p-1.5 text-slate-400 hover:text-white rounded ml-2 border border-transparent hover:border-slate-800 hover:bg-slate-900 transition-all"
                    title="Copy token key"
                  >
                    {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Key Registry Table */}
          <div className="bracket-card p-6 bg-[#0d1217] space-y-4">
            <div className="flex items-center justify-between border-b border-slate-900 pb-3">
              <h3 className="text-xs font-bold text-white font-mono uppercase tracking-[0.2em]">Active Credentials Registry</h3>
              <span className="text-[10px] text-slate-500 font-mono tracking-widest uppercase">{keys.length} active</span>
            </div>

            <div className="overflow-x-auto w-full max-h-[300px]">
              <table className="w-full text-left border-collapse text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-850 text-slate-500">
                    <th className="pb-3 font-semibold font-mono tracking-wider">Ident Label</th>
                    <th className="pb-3 font-semibold font-mono tracking-wider">Key Hash Prefix</th>
                    <th className="pb-3 font-semibold font-mono tracking-wider">Created Timestamp</th>
                    <th className="pb-3 font-semibold font-mono tracking-wider text-right">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {loading ? (
                    <tr>
                      <td colSpan="4" className="py-8 text-center text-slate-500 font-mono italic">
                        Retrieving credentials database...
                      </td>
                    </tr>
                  ) : keys.length === 0 ? (
                    <tr>
                      <td colSpan="4" className="py-8 text-center text-slate-500 font-mono italic">
                        No active API keys found. Generate a key to restrict backend access parameters.
                      </td>
                    </tr>
                  ) : (
                    keys.map((k) => (
                      <tr key={k.id} className="border-b border-slate-900 hover:bg-slate-900/10">
                        <td className="py-3 text-white font-semibold">{k.name}</td>
                        <td className="py-3 text-slate-450">{k.key_prefix}...</td>
                        <td className="py-3 text-slate-500">{new Date(k.created_at).toLocaleDateString()}</td>
                        <td className="py-3 text-right">
                          <button
                            onClick={() => handleRevokeKey(k.id)}
                            className="text-slate-550 hover:text-red-400 p-1.5 rounded-lg border border-transparent hover:border-slate-800 hover:bg-slate-950 transition-all btn-premium-click cursor-pointer"
                            title="Revoke access"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

        </div>

        {/* Right Column: Code Integration Docs */}
        <div className="bracket-card p-6 bg-[#0d1217] space-y-4">
          <div className="flex items-center space-x-2 border-b border-slate-900 pb-3">
            <Code className="w-4 h-4 text-[#007A8E]" />
            <h3 className="text-sm font-semibold text-white font-sans">SOC Integration Blueprint</h3>
          </div>

          {/* Capsule Pill Sub-tabs */}
          <div className="flex border border-white/[0.03] bg-slate-950/45 p-1 rounded-xl w-fit space-x-1">
            <button
              onClick={() => setDocTab("curl")}
              className={`px-3 py-1.5 text-[10px] font-semibold font-mono rounded-lg transition-all btn-premium-click ${
                docTab === "curl" ? "bg-[#131920] border border-white/[0.04] text-white" : "border border-transparent text-slate-500 hover:text-slate-350"
              }`}
            >
              cURL Request
            </button>
            <button
              onClick={() => setDocTab("python")}
              className={`px-3 py-1.5 text-[10px] font-semibold font-mono rounded-lg transition-all btn-premium-click ${
                docTab === "python" ? "bg-[#131920] border border-white/[0.04] text-white" : "border border-transparent text-slate-500 hover:text-slate-350"
              }`}
            >
              Python SDK
            </button>
            <button
              onClick={() => setDocTab("node")}
              className={`px-3 py-1.5 text-[10px] font-semibold font-mono rounded-lg transition-all btn-premium-click ${
                docTab === "node" ? "bg-[#131920] border border-white/[0.04] text-white" : "border border-transparent text-slate-500 hover:text-slate-350"
              }`}
            >
              Node.js SDK
            </button>
          </div>

          {/* Document Terminal Emulator */}
          <div className="rounded-xl border border-slate-900 bg-slate-950/95 overflow-hidden shadow-2xl relative group/code select-text">
            {/* Header */}
            <div className="flex items-center justify-between border-b border-slate-900/60 bg-slate-950/80 px-4 py-2">
              <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-1.5 flex-shrink-0">
                  <span className="w-2.5 h-2.5 rounded-full bg-slate-805" />
                  <span className="w-2.5 h-2.5 rounded-full bg-slate-805" />
                  <span className="w-2.5 h-2.5 rounded-full bg-slate-805" />
                </div>
                <span className="text-[9px] text-slate-600 font-mono tracking-wider">{getDocFilename()}</span>
              </div>
              <button
                onClick={() => copyToClipboard(docSnippets[docTab])}
                className="p-1.5 rounded border border-transparent hover:border-slate-800 hover:bg-slate-900 text-slate-500 hover:text-white transition-all cursor-pointer btn-premium-click"
                title="Copy snippet"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
            {/* Snippet text */}
            <div className="p-4 font-mono text-[10.5px] text-slate-350 overflow-x-auto leading-relaxed max-h-[300px]">
              <pre>
                <code>{docSnippets[docTab]}</code>
              </pre>
            </div>
          </div>

          {/* Alert Callout */}
          <div className="p-4 rounded-xl border border-slate-900 bg-slate-950/30 text-[11px] text-slate-500 leading-relaxed flex items-start space-x-3 font-mono">
            <Info className="w-4 h-4 text-[#007A8E] flex-shrink-0 mt-0.5" />
            <div>
              <span className="text-white font-semibold block mb-0.5 font-sans">Custom Security Headers</span>
              Provide keys inside request headers as payload mapping key `X-API-Key`. All API requests fail automatically with unauthorized status 401 if valid keys are absent from headers once keys are configured.
            </div>
          </div>
        </div>

      </div>

    </div>
  );
}
