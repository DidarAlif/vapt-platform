"use client";

import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import Image from "next/image";

// Types
interface ScanResult {
  template_id: string;
  name: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  matched_at: string;
  description: string;
  category?: string;
}

interface SecurityHeader {
  name: string;
  present: boolean;
  value?: string;
  risk: "high" | "medium" | "low";
  recommendation: string;
}

interface TechStack {
  type: string;
  name: string;
  version?: string;
}

interface User {
  id: string;
  email: string;
  name: string;
  is_verified: boolean;
}

type ScanStatus = "idle" | "scanning" | "complete" | "error";
type ScanMode = "quick" | "full" | "network" | "custom";
type ResultTab = "overview" | "vulnerabilities" | "headers" | "tech";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

const SCAN_MODES = [
  { id: "quick" as ScanMode, name: "Quick Recon", desc: "Tech fingerprinting & detection", time: "~2 min" },
  { id: "full" as ScanMode, name: "Full Scan", desc: "CVEs, vulnerabilities, exposures", time: "~10 min" },
  { id: "network" as ScanMode, name: "Network Scan", desc: "SSL, DNS, cloud services", time: "~5 min" },
  { id: "custom" as ScanMode, name: "Custom", desc: "Select specific categories", time: "Variable" },
];

const CATEGORIES = [
  { id: "cves", label: "CVEs", desc: "Known vulnerabilities" },
  { id: "misconfig", label: "Misconfigurations", desc: "Security misconfigs" },
  { id: "exposures", label: "Exposures", desc: ".env, .git, backups" },
  { id: "takeovers", label: "Takeovers", desc: "Subdomain takeovers" },
  { id: "ssl", label: "SSL/TLS", desc: "Certificate issues" },
  { id: "xss", label: "XSS", desc: "Cross-site scripting" },
  { id: "sqli", label: "SQL Injection", desc: "Database attacks" },
  { id: "rce", label: "RCE", desc: "Remote code execution" },
];

// Minimal SVG Icons
const Icons = {
  scan: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
    </svg>
  ),
  shield: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
  ),
  server: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
    </svg>
  ),
  code: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
    </svg>
  ),
  chart: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
    </svg>
  ),
  lock: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
    </svg>
  ),
  logout: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
    </svg>
  ),
  zap: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
    </svg>
  ),
  globe: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
    </svg>
  ),
  settings: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
    </svg>
  ),
};

export default function ScanPage() {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  // Scan configuration
  const [target, setTarget] = useState("");
  const [scanMode, setScanMode] = useState<ScanMode>("quick");
  const [selectedCategories, setSelectedCategories] = useState<string[]>(["cves", "misconfig"]);

  // Scan status
  const [status, setStatus] = useState<ScanStatus>("idle");
  const [progress, setProgress] = useState(0);
  const [terminalLog, setTerminalLog] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  // Results
  const [results, setResults] = useState<ScanResult[]>([]);
  const [headers, setHeaders] = useState<SecurityHeader[]>([]);
  const [techStack, setTechStack] = useState<TechStack[]>([]);
  const [activeTab, setActiveTab] = useState<ResultTab>("overview");
  const [riskScore, setRiskScore] = useState(0);

  const eventSourceRef = useRef<EventSource | null>(null);

  // Check authentication on mount
  useEffect(() => {
    const token = localStorage.getItem("access_token");
    const userData = localStorage.getItem("user");

    if (!token || !userData) {
      router.push("/login");
      return;
    }

    try {
      const parsedUser = JSON.parse(userData);
      if (!parsedUser.is_verified) {
        router.push("/verify-email?pending=true");
        return;
      }
      setUser(parsedUser);
    } catch {
      router.push("/login");
      return;
    }

    setLoading(false);
  }, [router]);

  const handleLogout = () => {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    localStorage.removeItem("user");
    router.push("/login");
  };

  const handleCategoryToggle = (categoryId: string) => {
    setSelectedCategories(prev =>
      prev.includes(categoryId)
        ? prev.filter(c => c !== categoryId)
        : [...prev, categoryId]
    );
  };

  const handleScan = async () => {
    if (!target.trim()) return;

    setStatus("scanning");
    setError(null);
    setResults([]);
    setHeaders([]);
    setTechStack([]);
    setProgress(0);
    setTerminalLog([]);

    const token = localStorage.getItem("access_token");

    // Use SSE for real-time progress
    const categories = scanMode === "custom" ? selectedCategories.join(",") : "";
    const sseUrl = `${API_URL}/scan/stream?target=${encodeURIComponent(target)}&scan_mode=${scanMode}&categories=${categories}`;

    try {
      // For SSE, we need to make a fetch request with auth header
      const response = await fetch(sseUrl, {
        headers: {
          "Authorization": `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        if (response.status === 401) {
          router.push("/login");
          return;
        }
        if (response.status === 403) {
          router.push("/verify-email?pending=true");
          return;
        }
        throw new Error(`Scan failed: ${response.statusText}`);
      }

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      const collectedResults: ScanResult[] = [];
      let collectedHeaders: SecurityHeader[] = [];
      let collectedTech: TechStack[] = [];

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          const chunk = decoder.decode(value);
          const lines = chunk.split("\n");

          for (const line of lines) {
            if (line.startsWith("data: ")) {
              try {
                const data = JSON.parse(line.slice(6));

                if (data.type === "status") {
                  setTerminalLog(prev => [...prev.slice(-20), data.message]);
                  setProgress(data.progress || 0);
                } else if (data.type === "finding") {
                  collectedResults.push(data.data);
                  setResults([...collectedResults]);
                } else if (data.type === "headers") {
                  collectedHeaders = data.data;
                  setHeaders(data.data);
                } else if (data.type === "tech_stack") {
                  collectedTech = data.data;
                  setTechStack(data.data);
                } else if (data.type === "complete") {
                  setProgress(100);
                  setRiskScore(calculateRiskScore(collectedResults));
                  setStatus("complete");
                  setActiveTab("overview");
                } else if (data.type === "error") {
                  throw new Error(data.message);
                }
              } catch (e) {
                // Skip invalid JSON
              }
            }
          }
        }
      }

      // Fallback if SSE didn't complete properly
      if (status !== "complete") {
        setStatus("complete");
        setRiskScore(calculateRiskScore(collectedResults));
      }

    } catch (err) {
      console.error("Scan error:", err);
      setError(err instanceof Error ? err.message : "An unexpected error occurred");
      setStatus("error");
    }
  };

  const calculateRiskScore = (findings: ScanResult[]): number => {
    if (!findings.length) return 0;
    const weights = { critical: 40, high: 25, medium: 15, low: 5, info: 1 };
    const score = findings.reduce((acc, f) => acc + (weights[f.severity] || 0), 0);
    return Math.min(100, score);
  };

  const getSeverityStyles = (severity: string) => {
    const base = "px-2 py-0.5 rounded text-xs font-medium uppercase";
    const styles: Record<string, string> = {
      critical: `${base} bg-red-500/20 text-red-400 border border-red-500/40`,
      high: `${base} bg-orange-500/20 text-orange-400 border border-orange-500/40`,
      medium: `${base} bg-yellow-500/20 text-yellow-400 border border-yellow-500/40`,
      low: `${base} bg-emerald-500/20 text-emerald-400 border border-emerald-500/40`,
      info: `${base} bg-slate-500/20 text-slate-400 border border-slate-500/40`,
    };
    return styles[severity] || styles.info;
  };

  const getRiskColor = (score: number) => {
    if (score >= 70) return "text-red-400";
    if (score >= 40) return "text-orange-400";
    if (score >= 20) return "text-yellow-400";
    return "text-emerald-400";
  };

  const countBySeverity = (severity: string) => results.filter(r => r.severity === severity).length;

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0a0a0f] flex items-center justify-center">
        <div className="text-gray-400 font-mono text-sm">Loading...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-gray-100">
      <div className="max-w-7xl mx-auto px-6 py-6">
        {/* Header */}
        <header className="mb-8 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 relative">
              <Image src="/logo.png" alt="RS" fill className="object-contain" priority />
            </div>
            <div>
              <h1 className="text-xl font-bold text-[#00d4aa]">ReconScience</h1>
              <p className="text-gray-500 text-xs font-mono">Security Reconnaissance</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-xs text-gray-500 font-mono">{user?.email}</span>
            <a href="/history" className="text-gray-400 hover:text-gray-200 text-sm">History</a>
            <button onClick={handleLogout} className="flex items-center gap-1.5 text-gray-400 hover:text-gray-200 text-sm">
              {Icons.logout}
              <span>Logout</span>
            </button>
          </div>
        </header>

        {/* Main Content */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column - Configuration */}
          <div className="lg:col-span-1 space-y-4">
            {/* Scan Mode */}
            <div className="bg-[#12121a] border border-gray-800/50 rounded-lg p-4">
              <h3 className="text-xs font-medium text-gray-400 uppercase tracking-wide mb-3 flex items-center gap-2">
                {Icons.settings}
                Scan Mode
              </h3>
              <div className="space-y-2">
                {SCAN_MODES.map((mode) => (
                  <button
                    key={mode.id}
                    onClick={() => setScanMode(mode.id)}
                    disabled={status === "scanning"}
                    className={`w-full text-left p-3 rounded-lg border transition-all ${scanMode === mode.id
                      ? "bg-[#00d4aa]/10 border-[#00d4aa]/50 text-[#00d4aa]"
                      : "bg-[#0a0a0f] border-gray-800 text-gray-400 hover:border-gray-700"
                      } disabled:opacity-50`}
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="font-medium text-sm">{mode.name}</div>
                        <div className="text-xs opacity-70 mt-0.5">{mode.desc}</div>
                      </div>
                      <span className="text-xs text-gray-500">{mode.time}</span>
                    </div>
                  </button>
                ))}
              </div>

              {/* Custom Categories */}
              {scanMode === "custom" && (
                <div className="mt-4 pt-4 border-t border-gray-800">
                  <p className="text-xs text-gray-500 mb-3">Select categories:</p>
                  <div className="grid grid-cols-2 gap-2">
                    {CATEGORIES.map((cat) => (
                      <label key={cat.id} className="flex items-center gap-2 p-2 rounded hover:bg-gray-800/30 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={selectedCategories.includes(cat.id)}
                          onChange={() => handleCategoryToggle(cat.id)}
                          className="w-3.5 h-3.5 rounded border-gray-600 bg-gray-800 text-[#00d4aa] focus:ring-[#00d4aa]/20"
                        />
                        <span className="text-xs text-gray-300">{cat.label}</span>
                      </label>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Right Column - Target & Results */}
          <div className="lg:col-span-2 space-y-4">
            {/* Target Input */}
            <div className="bg-[#12121a] border border-gray-800/50 rounded-lg p-4">
              <label className="block text-xs font-medium text-gray-400 uppercase tracking-wide mb-2">Target URL</label>
              <div className="flex gap-3">
                <input
                  type="url"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="https://example.com"
                  disabled={status === "scanning"}
                  className="flex-1 bg-[#0a0a0f] border border-gray-800 rounded-lg px-4 py-2.5 text-sm font-mono placeholder-gray-600 focus:border-[#00d4aa]/50 focus:ring-1 focus:ring-[#00d4aa]/20 transition-all disabled:opacity-50"
                />
                <button
                  onClick={handleScan}
                  disabled={status === "scanning" || !target.trim()}
                  className="px-6 py-2.5 bg-[#00d4aa] hover:bg-[#00b894] text-[#0a0a0f] font-semibold rounded-lg transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2"
                >
                  {status === "scanning" ? (
                    <>
                      <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                      </svg>
                      <span>{progress}%</span>
                    </>
                  ) : (
                    <>
                      {Icons.scan}
                      <span>Scan</span>
                    </>
                  )}
                </button>
              </div>
              <p className="mt-2 text-xs text-gray-600 font-mono">Only scan targets you own or have permission to test.</p>
            </div>

            {/* Scanning Progress */}
            {status === "scanning" && (
              <div className="bg-[#12121a] border border-gray-800/50 rounded-lg p-4">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-sm text-[#00d4aa] flex items-center gap-2">
                    <div className="w-2 h-2 bg-[#00d4aa] rounded-full animate-pulse" />
                    Scanning...
                  </span>
                  <span className="text-xs text-gray-500 font-mono">{progress}%</span>
                </div>
                <div className="w-full bg-gray-800 rounded-full h-1 mb-4">
                  <div className="bg-[#00d4aa] h-1 rounded-full transition-all duration-300" style={{ width: `${progress}%` }} />
                </div>
                <div className="bg-[#0a0a0f] rounded-lg p-3 font-mono text-xs border border-gray-800 max-h-32 overflow-y-auto">
                  {terminalLog.map((log, i) => (
                    <div key={i} className="text-gray-400 py-0.5">
                      <span className="text-gray-600 mr-2">[{String(i + 1).padStart(2, "0")}]</span>
                      <span className="text-[#00d4aa]/70">{log}</span>
                    </div>
                  ))}
                  <span className="text-gray-600 animate-pulse">█</span>
                </div>
              </div>
            )}

            {/* Error State */}
            {status === "error" && error && (
              <div className="bg-red-950/20 border border-red-500/30 rounded-lg p-4">
                <div className="flex items-center gap-2 text-red-400 text-sm">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  {error}
                </div>
              </div>
            )}

            {/* Results */}
            {status === "complete" && (
              <div className="bg-[#12121a] border border-gray-800/50 rounded-lg overflow-hidden">
                {/* Tabs */}
                <div className="flex border-b border-gray-800 overflow-x-auto">
                  {[
                    { id: "overview" as ResultTab, label: "Overview", icon: Icons.chart },
                    { id: "vulnerabilities" as ResultTab, label: `Findings (${results.length})`, icon: Icons.shield },
                    { id: "headers" as ResultTab, label: "Headers", icon: Icons.lock },
                    { id: "tech" as ResultTab, label: "Tech Stack", icon: Icons.code },
                  ].map((tab) => (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id)}
                      className={`px-4 py-3 text-sm font-medium whitespace-nowrap transition-all flex items-center gap-2 ${activeTab === tab.id
                        ? "text-[#00d4aa] border-b-2 border-[#00d4aa] bg-[#00d4aa]/5"
                        : "text-gray-500 hover:text-gray-300"
                        }`}
                    >
                      {tab.icon}
                      {tab.label}
                    </button>
                  ))}
                </div>

                {/* Tab Content */}
                <div className="p-5">
                  {/* Overview */}
                  {activeTab === "overview" && (
                    <div className="space-y-4">
                      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                        <div className="bg-[#0a0a0f] rounded-lg p-3 text-center border border-gray-800">
                          <div className={`text-2xl font-bold ${getRiskColor(riskScore)}`}>{riskScore}</div>
                          <div className="text-xs text-gray-500 mt-1">Risk Score</div>
                        </div>
                        <div className="bg-[#0a0a0f] rounded-lg p-3 text-center border border-gray-800">
                          <div className="text-2xl font-bold text-red-400">{countBySeverity("critical")}</div>
                          <div className="text-xs text-gray-500 mt-1">Critical</div>
                        </div>
                        <div className="bg-[#0a0a0f] rounded-lg p-3 text-center border border-gray-800">
                          <div className="text-2xl font-bold text-orange-400">{countBySeverity("high")}</div>
                          <div className="text-xs text-gray-500 mt-1">High</div>
                        </div>
                        <div className="bg-[#0a0a0f] rounded-lg p-3 text-center border border-gray-800">
                          <div className="text-2xl font-bold text-yellow-400">{countBySeverity("medium")}</div>
                          <div className="text-xs text-gray-500 mt-1">Medium</div>
                        </div>
                        <div className="bg-[#0a0a0f] rounded-lg p-3 text-center border border-gray-800">
                          <div className="text-2xl font-bold text-emerald-400">{countBySeverity("low") + countBySeverity("info")}</div>
                          <div className="text-xs text-gray-500 mt-1">Low/Info</div>
                        </div>
                      </div>
                      <div className="bg-[#0a0a0f] rounded-lg p-4 border border-gray-800">
                        <h4 className="text-sm font-medium text-gray-300 mb-3">Scan Summary</h4>
                        <div className="grid grid-cols-2 gap-3 text-sm">
                          <div className="flex justify-between"><span className="text-gray-500">Target:</span><span className="text-[#00d4aa] font-mono text-xs truncate max-w-[200px]">{target}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Mode:</span><span className="text-gray-300">{SCAN_MODES.find(m => m.id === scanMode)?.name}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Findings:</span><span className="text-gray-300">{results.length}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Technologies:</span><span className="text-gray-300">{techStack.length}</span></div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Vulnerabilities */}
                  {activeTab === "vulnerabilities" && (
                    results.length === 0 ? (
                      <div className="text-center py-10">
                        <div className="text-gray-600 mb-2">{Icons.shield}</div>
                        <p className="text-[#00d4aa] font-mono text-sm">No vulnerabilities detected</p>
                        <p className="text-gray-500 text-xs mt-1">Scan completed with no findings.</p>
                      </div>
                    ) : (
                      <div className="overflow-x-auto">
                        <table className="w-full">
                          <thead>
                            <tr className="bg-[#0a0a0f]">
                              <th className="px-3 py-2 text-left text-xs text-gray-500 uppercase">Template</th>
                              <th className="px-3 py-2 text-left text-xs text-gray-500 uppercase">Finding</th>
                              <th className="px-3 py-2 text-left text-xs text-gray-500 uppercase">Severity</th>
                              <th className="px-3 py-2 text-left text-xs text-gray-500 uppercase">URL</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-gray-800">
                            {results.map((r, i) => (
                              <tr key={i} className="hover:bg-white/[0.02]">
                                <td className="px-3 py-2 font-mono text-xs text-[#00d4aa]/80">{r.template_id}</td>
                                <td className="px-3 py-2 text-sm text-gray-200">{r.name}</td>
                                <td className="px-3 py-2"><span className={getSeverityStyles(r.severity)}>{r.severity}</span></td>
                                <td className="px-3 py-2 font-mono text-xs text-gray-400 max-w-[200px] truncate">{r.matched_at}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )
                  )}

                  {/* Headers */}
                  {activeTab === "headers" && (
                    <div className="space-y-2">
                      {headers.map((h, i) => (
                        <div key={i} className={`p-3 rounded-lg border ${h.present ? "bg-emerald-500/5 border-emerald-500/20" : "bg-red-500/5 border-red-500/20"}`}>
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-mono text-sm text-gray-200">{h.name}</span>
                            <span className={`px-2 py-0.5 rounded text-xs ${h.present ? "bg-emerald-500/20 text-emerald-400" : "bg-red-500/20 text-red-400"}`}>
                              {h.present ? "Present" : "Missing"}
                            </span>
                          </div>
                          {h.value && <p className="text-xs text-gray-500 font-mono truncate">{h.value}</p>}
                          <p className="text-xs text-gray-600 mt-1">{h.recommendation}</p>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Tech Stack */}
                  {activeTab === "tech" && (
                    techStack.length === 0 ? (
                      <div className="text-center py-10">
                        <div className="text-gray-600 mb-2">{Icons.code}</div>
                        <p className="text-gray-400 text-sm">No technologies detected</p>
                      </div>
                    ) : (
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                        {techStack.map((t, i) => (
                          <div key={i} className="bg-[#0a0a0f] rounded-lg p-3 border border-gray-800">
                            <div className="text-xs text-gray-500 uppercase">{t.type}</div>
                            <div className="text-gray-200 font-medium text-sm mt-1">{t.name}</div>
                            {t.version && <div className="text-xs text-[#00d4aa] font-mono mt-1">v{t.version}</div>}
                          </div>
                        ))}
                      </div>
                    )
                  )}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <footer className="mt-10 text-center border-t border-gray-800/50 pt-6">
          <p className="font-mono text-xs text-gray-600">ReconScience • Security Reconnaissance Platform</p>
          <p className="font-mono text-xs text-gray-700 mt-1">© 2026 Alif. All rights reserved.</p>
        </footer>
      </div>
    </div>
  );
}
