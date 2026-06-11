import React, { useState, useEffect } from "react";
import { 
  TrendingUp, 
  Server, 
  ShieldAlert, 
  Layers, 
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Activity
} from "lucide-react";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell
} from "recharts";

export default function CampaignTriage({ onSelectJob, setPage }) {
  const [campaigns, setCampaigns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expandedCampaign, setExpandedCampaign] = useState(null);

  const fetchCampaigns = async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/campaigns");
      if (res.ok) {
        const data = await res.json();
        setCampaigns(data);
      }
    } catch (err) {
      console.error("Error fetching campaign triages:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCampaigns();
  }, []);

  const toggleExpand = (campaignId) => {
    if (expandedCampaign === campaignId) {
      setExpandedCampaign(null);
    } else {
      setExpandedCampaign(campaignId);
    }
  };

  if (loading) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center space-y-4 min-h-[50vh]">
        <div className="relative">
          <div className="w-10 h-10 border-4 border-white/[0.04] border-t-[#007A8E] rounded-full animate-spin" />
          <div className="absolute inset-0 bg-[#007A8E]/10 rounded-full blur-md" />
        </div>
        <span className="text-xs font-mono text-[#007A8E] tracking-wider uppercase animate-pulse">Correlating SOC Threat Campaigns...</span>
      </div>
    );
  }

  // Formatting campaigns data for horizontal chart comparison
  const chartData = campaigns.map(c => ({
    name: c.malware_family,
    affectedCount: c.affected_apps.length,
    threatLevel: c.threat_level
  }));

  // Curated color palette matching family severity
  const getBarColor = (threatLevel) => {
    if (threatLevel === "Critical") return "#007A8E";
    if (threatLevel === "High") return "#4B9CD3";
    return "#5B9C7D";
  };

  return (
    <div className="flex-1 flex flex-col space-y-8 select-none p-4 md:p-6 max-w-7xl mx-auto w-full animate-fade-in">
      
      {/* Title Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-900 pb-5">
        <div>
          <h2 className="text-xl font-bold text-white font-sans flex items-center space-x-2.5">
            <TrendingUp className="w-5 h-5 text-[#007A8E]" />
            <span className="uppercase tracking-wide font-semibold text-white">Campaign Triage & Correlation</span>
          </h2>
          <p className="text-xs text-slate-500 font-mono mt-1.5 leading-relaxed">
            Detecting automated distribution networks and shared C2 infrastructure across analyzed targets.
          </p>
        </div>
      </div>

      {/* Intro Stats & Recharts Chart Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Statistics Widgets */}
        <div className="space-y-4 lg:col-span-1">
          <div className="bracket-card p-5 bg-[#0d1217] flex items-center space-x-4">
            <div className="bg-[#007A8E]/5 p-3.5 rounded-xl border border-[#007A8E]/10 flex items-center justify-center">
              <Layers className="w-5 h-5 text-[#007A8E]" />
            </div>
            <div>
              <div className="text-xl font-bold font-mono text-white leading-none">{campaigns.length}</div>
              <div className="text-micro-label mt-1.5">Active Clusters</div>
            </div>
          </div>
          
          <div className="bracket-card p-5 bg-[#0d1217] flex items-center space-x-4">
            <div className="bg-[#2C5F2D]/5 p-3.5 rounded-xl border border-[#2C5F2D]/10 flex items-center justify-center">
              <Activity className="w-5 h-5 text-[#5B9C7D]" />
            </div>
            <div>
              <div className="text-xl font-bold font-mono text-white leading-none">
                {campaigns.reduce((acc, c) => acc + c.affected_apps.length, 0)}
              </div>
              <div className="text-micro-label mt-1.5">Correlated Targets</div>
            </div>
          </div>
        </div>

        {/* Recharts Campaign Threat Scale Comparison */}
        <div className="bracket-card p-5 bg-[#0d1217] lg:col-span-2 relative min-h-[160px] flex flex-col justify-between">
          <div className="absolute top-3 left-4 text-micro-label">Threat Scale Comparison</div>
          
          {campaigns.length === 0 ? (
            <div className="text-xs text-slate-500 italic py-10 text-center font-mono w-full">No active campaign distributions.</div>
          ) : (
            <div className="w-full h-28 mt-5">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart layout="vertical" data={chartData} margin={{ left: -10, right: 10, top: 0, bottom: 0 }}>
                  <XAxis type="number" stroke="rgba(255,255,255,0.01)" tick={{ fill: "rgba(148,163,184,0.4)", fontSize: 8 }} />
                  <YAxis type="category" dataKey="name" stroke="rgba(255,255,255,0.01)" tick={{ fill: "rgba(255,255,255,0.85)", fontSize: 8.5, fontFamily: "monospace" }} width={80} />
                  <Tooltip 
                    cursor={{ fill: 'rgba(255,255,255,0.01)' }}
                    contentStyle={{ background: '#070b0f', borderColor: 'rgba(75, 156, 211, 0.05)', fontSize: '10px', fontFamily: 'monospace', borderRadius: '4px' }}
                  />
                  <Bar dataKey="affectedCount" radius={[0, 4, 4, 0]} barSize={12}>
                    {chartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={getBarColor(entry.threatLevel)} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

      </div>

      {/* Campaigns Listing Card List */}
      <div className="space-y-4">
        {campaigns.length === 0 ? (
          <div className="bracket-card border border-slate-850 rounded-2xl p-12 text-center text-slate-500 text-xs italic font-mono bg-[#0d1217]">
            No active threat campaigns correlated yet. Analyze multiple samples linking the same C2 hosts to build dynamic campaigns.
          </div>
        ) : (
          campaigns.map((c) => {
            const isExpanded = expandedCampaign === c.campaign_id;
            return (
              <div 
                key={c.campaign_id} 
                className={`bracket-card transition-all duration-350 overflow-hidden bg-[#0d1217] ${
                  isExpanded ? "border-[#007A8E]/20 shadow-[0_4px_20px_rgba(0,122,142,0.05)]" : "border-slate-850"
                }`}
              >
                
                {/* Header Row */}
                <div 
                  onClick={() => toggleExpand(c.campaign_id)}
                  className="p-5 flex items-center justify-between cursor-pointer select-none"
                >
                  <div className="flex items-center space-x-4">
                    <div className={`p-2.5 rounded-xl border flex-shrink-0 ${
                      c.threat_level === "Critical" || c.threat_level === "High"
                        ? "bg-[#007A8E]/10 border-[#007A8E]/20 text-[#007A8E]"
                        : "bg-[#5B9C7D]/10 border-[#5B9C7D]/20 text-[#5B9C7D]"
                    }`}>
                      <Server className="w-5 h-5 animate-pulse" />
                    </div>
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="text-xs font-bold text-white font-mono">{c.malware_family} Cluster</span>
                        <span className={`px-2 py-0.5 rounded text-[8px] font-bold font-mono border ${
                          c.threat_level === "Critical" ? "bg-[#007A8E]/10 text-[#007A8E] border-[#007A8E]/20" :
                          c.threat_level === "High" ? "bg-[#4B9CD3]/10 text-[#4B9CD3] border-[#4B9CD3]/20" :
                          "bg-[#5B9C7D]/10 text-[#5B9C7D] border-[#5B9C7D]/20"
                        }`}>
                          {c.threat_level}
                        </span>
                      </div>
                      
                      <div className="text-[9px] text-slate-500 font-mono mt-1.5 flex items-center space-x-1.5">
                        <span className="text-[#007A8E] font-bold">{c.type}:</span>
                        <span className="truncate max-w-[200px] sm:max-w-md text-slate-400 select-text">{c.correlated_value}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center space-x-4 font-mono text-xs">
                    <div className="text-right hidden sm:block">
                      <span className="text-slate-500 block text-[8px] uppercase tracking-wider">Affected Targets</span>
                      <span className="text-white font-bold block mt-0.5">{c.affected_apps.length} APK nodes</span>
                    </div>
                    {isExpanded ? (
                      <ChevronUp className="w-4 h-4 text-slate-400" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-slate-400" />
                    )}
                  </div>
                </div>

                {/* Expanded details nodes grid */}
                {isExpanded && (
                  <div className="border-t border-slate-900 bg-slate-950/20 p-5 space-y-4 animate-fade-in">
                    <div className="text-[9px] text-slate-500 font-mono uppercase tracking-[0.2em]">Active Campaign Nodes</div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {c.affected_apps.map((app) => (
                        <div 
                          key={app.job_id}
                          onClick={() => {
                            onSelectJob(app.job_id);
                            setPage("dashboard");
                          }}
                          className="p-4 rounded-xl border border-slate-900 bg-[#0d1217]/50 hover:border-[#007A8E]/20 hover:bg-[#007A8E]/[0.01] transition-all duration-300 cursor-pointer flex justify-between items-center group btn-premium-click"
                        >
                          <div className="space-y-1 pr-4 min-w-0">
                            <div className="text-xs font-semibold text-white group-hover:text-[#007A8E] transition-colors truncate font-sans" title={app.filename}>
                              {app.filename}
                            </div>
                            <div className="text-[9px] text-slate-500 font-mono">
                              Job: {app.job_id.slice(0, 8)}...
                            </div>
                          </div>

                          <div className="flex items-center space-x-3 text-right flex-shrink-0">
                            <div>
                              <span className="text-[8px] font-mono text-slate-500 block uppercase">Risk</span>
                              <span className={`text-xs font-bold font-mono ${
                                app.risk_score > 75 ? "text-[#007A8E]" : "text-[#4B9CD3]"
                              }`}>
                                {app.risk_score}%
                              </span>
                            </div>
                            <ExternalLink className="w-3.5 h-3.5 text-slate-500 group-hover:text-[#007A8E] transition-colors" />
                          </div>
                        </div>
                      ))}
                    </div>

                    {/* Technical Command directive */}
                    <div className="p-4 rounded-xl border border-slate-900 bg-slate-950/60 text-[11px] text-slate-400 font-mono leading-relaxed flex items-start space-x-3 select-text">
                      <ShieldAlert className="w-4 h-4 text-[#007A8E] flex-shrink-0 mt-0.5" />
                      <div>
                        <span className="text-white font-semibold block mb-1">SOC Threat Action Directive</span>
                        Shared infrastructure endpoints confirm coordinated deployment campaigns. Block outbound C2 communication to `{c.correlated_value}` on network gateways and deploy signatures to firewalls.
                      </div>
                    </div>

                  </div>
                )}

              </div>
            );
          })
        )}
      </div>

    </div>
  );
}
