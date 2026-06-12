import React, { useState, useEffect } from "react";
import Sidebar from "./components/Sidebar";
import UploadPage from "./components/UploadPage";
import DashboardView from "./components/DashboardView";
import EvidenceExplorer from "./components/EvidenceExplorer";
import ThreatIntel from "./components/ThreatIntel";
import InvestigationReport from "./components/InvestigationReport";
import CampaignTriage from "./components/CampaignTriage";
import ApiPlayground from "./components/ApiPlayground";
import V2UploadPage from "./components/v2/V2UploadPage";
import V2ResultsPage from "./components/v2/V2ResultsPage";
import V2ReportView from "./components/v2/V2ReportView";
import { Menu, X } from "lucide-react";

function App() {
  const [jobId, setJobId] = useState(null);
  const [currentPage, setCurrentPage] = useState("upload");
  const [isV2, setIsV2] = useState(false);
  const [loading, setLoading] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  // Helper to format/update the hash URL
  const updateHash = (page, currentJobId) => {
    const query = currentJobId ? `?jobId=${currentJobId}` : "";
    const newHash = `#${page}${query}`;
    if (window.location.hash !== newHash) {
      window.location.hash = newHash;
    }
  };

  // Sync state with URL hash on mount and when hash changes
  useEffect(() => {
    const handleHashChange = () => {
      const rawHash = window.location.hash.replace("#", "");
      if (!rawHash) {
        // Default page route if hash is empty
        updateHash(currentPage, jobId);
        return;
      }

      const [page, queryString] = rawHash.split("?");
      let urlJobId = null;
      if (queryString) {
        const params = new URLSearchParams(queryString);
        urlJobId = params.get("jobId");
      }

      const validPages = [
        "upload", "dashboard", "evidence", "threat-intel", 
        "report", "campaigns", "api-keys", "v2-upload", 
        "v2-results", "v2-report"
      ];

      if (validPages.includes(page)) {
        if (urlJobId !== jobId) {
          setJobId(urlJobId);
        }
        if (urlJobId) {
          setIsV2(page.startsWith("v2-"));
        }
        if (page !== currentPage) {
          setCurrentPage(page);
        }
      } else {
        // Fallback for invalid hashes
        updateHash("upload", null);
      }
    };

    window.addEventListener("hashchange", handleHashChange);
    
    // Initial sync
    handleHashChange();

    return () => {
      window.removeEventListener("hashchange", handleHashChange);
    };
  }, [jobId, currentPage]);

  const resetUpload = () => {
    setJobId(null);
    const targetPage = currentPage && currentPage.startsWith("v2-") ? "v2-upload" : "upload";
    setCurrentPage(targetPage);
    updateHash(targetPage, null);
    setSidebarOpen(false);
  };

  const setPage = (page) => {
    setCurrentPage(page);
    if (["dashboard", "evidence", "threat-intel", "report"].includes(page)) {
      setIsV2(false);
    } else if (page.startsWith("v2-")) {
      setIsV2(true);
    }
    updateHash(page, jobId);
    setSidebarOpen(false);
  };

  const renderContent = () => {
    switch (currentPage) {
      case "upload":
        return (
          <UploadPage
            onSelectJob={(id) => {
              setJobId(id);
              setIsV2(false);
              setCurrentPage("dashboard");
              updateHash("dashboard", id);
            }}
            onStartLoading={() => setLoading(true)}
            onStopLoading={() => setLoading(false)}
            loading={loading}
          />
        );
      case "dashboard":
        return <DashboardView jobId={jobId} setPage={setPage} />;
      case "evidence":
        return <EvidenceExplorer jobId={jobId} setPage={setPage} />;
      case "threat-intel":
        return <ThreatIntel jobId={jobId} setPage={setPage} />;
      case "report":
        return <InvestigationReport jobId={jobId} setPage={setPage} />;
      case "campaigns":
        return (
          <CampaignTriage
            onSelectJob={(id) => {
              setJobId(id);
              setIsV2(false);
              setCurrentPage("dashboard");
              updateHash("dashboard", id);
            }}
            setPage={setPage}
          />
        );
      case "api-keys":
        return <ApiPlayground />;
      case "v2-upload":
        return (
          <V2UploadPage
            onSelectJob={(id) => {
              setJobId(id);
              setIsV2(true);
              setCurrentPage("v2-results");
              updateHash("v2-results", id);
            }}
            onStartLoading={() => setLoading(true)}
            onStopLoading={() => setLoading(false)}
          />
        );
      case "v2-results":
        return <V2ResultsPage jobId={jobId} setPage={setPage} />;
      case "v2-report":
        return <V2ReportView jobId={jobId} setPage={setPage} />;
      default:
        return (
          <div className="flex-1 flex items-center justify-center font-mono text-xs text-slate-500">
            Error: Page not found.
          </div>
        );
    }
  };

  return (
    <div className="min-h-screen bg-[#070b0f] text-slate-200 flex font-sans antialiased overflow-x-hidden relative">
      
      {/* Premium Dot-Matrix Background */}
      <div className="absolute inset-0 dot-matrix-bg [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_90%,transparent_100%)] pointer-events-none opacity-45" />

      {/* Global Ambient Glow Spotlights */}
      <div className="radial-spotlight-primary -top-60 left-1/4" />
      <div className="radial-spotlight-secondary top-1/2 right-1/4" />

      {/* Backdrop overlay for mobile drawer */}
      {sidebarOpen && (
        <div 
          onClick={() => setSidebarOpen(false)}
          className="fixed inset-0 bg-black/60 backdrop-blur-sm z-20 lg:hidden"
        />
      )}

      {/* Sidebar Navigation */}
      <Sidebar
        currentPage={currentPage}
        jobId={jobId}
        isV2={isV2}
        setPage={setPage}
        resetUpload={resetUpload}
        sidebarOpen={sidebarOpen}
        setSidebarOpen={setSidebarOpen}
      />

      {/* Main Contents Panel */}
      <main className="flex-1 lg:ml-64 min-h-screen flex flex-col justify-start relative z-0">
        
        {/* Mobile top bar */}
        <header className="lg:hidden h-14 border-b border-slate-900 bg-[#07090e]/85 backdrop-blur-md flex items-center justify-between px-4 sticky top-0 z-10">
          <div className="flex items-center space-x-3">
            <button
              onClick={() => setSidebarOpen(true)}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-900 transition-all cursor-pointer"
              aria-label="Open menu"
            >
              <Menu className="w-5 h-5" />
            </button>
            <span className="text-xs font-bold tracking-[0.2em] text-white font-mono">SENTINEL<span className="text-[#007A8E]">_AI</span></span>
          </div>
          {jobId && (
            <div className="text-[10px] text-slate-500 font-mono">
              Job: {jobId.slice(0, 8)}...
            </div>
          )}
        </header>

        <div className="flex-1 flex flex-col max-w-7xl w-full mx-auto p-4 md:p-6 lg:p-8 animate-fade-in" key={currentPage}>
          {renderContent()}
        </div>
      </main>

    </div>
  );
}

export default App;
