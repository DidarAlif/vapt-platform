"use client";

import { useState } from "react";
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

type ScanStatus = "idle" | "scanning" | "complete" | "error";
type ScanMode = "quick" | "full" | "network" | "custom";
type ResultTab = "overview" | "vulnerabilities" | "headers" | "tech" | "network";

const SCAN_MODES = [
  { id: "quick" as ScanMode, name: "Quick Recon", desc: "Headers, tech stack, basic exposure", icon: "⚡" },
  { id: "full" as ScanMode, name: "Full Scan", desc: "All vulnerability templates", icon: "🔍" },
  { id: "network" as ScanMode, name: "Network Scan", desc: "Port & service detection", icon: "🌐" },
  { id: "custom" as ScanMode, name: "Custom", desc: "Select specific categories", icon: "⚙️" },
];

const CATEGORIES = [
  { id: "cves", label: "CVEs", desc: "Known vulnerabilities" },
  { id: "misconfig", label: "Misconfigurations", desc: "Security misconfigs" },
  { id: "exposures", label: "Exposures", desc: ".env, .git, backups" },
  { id: "takeovers", label: "Takeovers", desc: "Subdomain takeovers" },
  { id: "ssl", label: "SSL/TLS", desc: "Certificate issues" },
];

const terminalMessages: Record<ScanMode, string[]> = {
  quick: [
    "Initializing quick reconnaissance...",
    "Analyzing HTTP headers...",
    "Detecting technology stack...",
    "Checking for exposures...",
    "Finalizing quick scan...",
  ],
  full: [
    "Initializing full vulnerability scan...",
    "Loading 5000+ Nuclei templates...",
    "Scanning for CVEs...",
    "Checking misconfigurations...",
    "Analyzing exposures...",
    "Testing for takeovers...",
    "Finalizing comprehensive scan...",
  ],
  network: [
    "Initializing network reconnaissance...",
    "Scanning common ports (21,22,80,443,8080)...",
    "Detecting running services...",
    "Grabbing service banners...",
    "Analyzing network exposure...",
  ],
  custom: [
    "Initializing custom scan...",
    "Loading selected templates...",
    "Running targeted checks...",
    "Analyzing results...",
  ],
};

export default function ScanPage() {
  // Form state
  const [userName, setUserName] = useState("");
  const [userEmail, setUserEmail] = useState("");
  const [target, setTarget] = useState("");

  // Scan configuration
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

  const simulateTerminalLogs = (mode: ScanMode) => {
    setTerminalLog([]);
    setProgress(0);
    const messages = terminalMessages[mode];
    let index = 0;

    const interval = setInterval(() => {
      if (index < messages.length) {
        setTerminalLog((prev) => [...prev, messages[index]]);
        setProgress(Math.round(((index + 1) / messages.length) * 100));
        index++;
      } else {
        clearInterval(interval);
      }
    }, 1000);
    return interval;
  };

  const isFormValid = userName.trim() && userEmail.trim() && target.trim();

  const handleCategoryToggle = (categoryId: string) => {
    setSelectedCategories(prev =>
      prev.includes(categoryId)
        ? prev.filter(c => c !== categoryId)
        : [...prev, categoryId]
    );
  };

  const handleScan = async () => {
    if (!isFormValid) return;

    setStatus("scanning");
    setError(null);
    setResults([]);
    setHeaders([]);
    setTechStack([]);
    const logInterval = simulateTerminalLogs(scanMode);

    try {
      // Get auth token from localStorage
      const token = localStorage.getItem("access_token");
      const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };

      // Add auth header if token exists
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
      }

      const response = await fetch(`${API_URL}/scan`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          name: userName.trim(),
          email: userEmail.trim(),
          target: target.trim(),
          scan_mode: scanMode,
          categories: scanMode === "custom" ? selectedCategories : undefined,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `Scan failed with status ${response.status}`);
      }

      const data = await response.json();
      clearInterval(logInterval);
      setProgress(100);

      // Process results
      setResults(data.findings || data);
      setHeaders(data.headers || generateMockHeaders());
      setTechStack(data.tech_stack || []);
      setRiskScore(calculateRiskScore(data.findings || data));
      setStatus("complete");
      setActiveTab("overview");
    } catch (err) {
      clearInterval(logInterval);
      console.error("Scan error:", err);
      if (err instanceof TypeError && err.message === "Failed to fetch") {
        const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
        setError(`Cannot connect to server. API: ${API_URL}`);
      } else {
        setError(err instanceof Error ? err.message : "An unexpected error occurred");
      }
      setStatus("error");
    }
  };

  const calculateRiskScore = (findings: ScanResult[]): number => {
    if (!findings.length) return 0;
    const weights = { critical: 40, high: 25, medium: 15, low: 5, info: 1 };
    const score = findings.reduce((acc, f) => acc + (weights[f.severity] || 0), 0);
    return Math.min(100, score);
  };

  const generateMockHeaders = (): SecurityHeader[] => [
    { name: "Content-Security-Policy", present: false, risk: "high", recommendation: "Add CSP header to prevent XSS attacks" },
    { name: "Strict-Transport-Security", present: false, risk: "high", recommendation: "Enable HSTS to force HTTPS" },
    { name: "X-Frame-Options", present: true, value: "DENY", risk: "low", recommendation: "Header is properly configured" },
    { name: "X-Content-Type-Options", present: true, value: "nosniff", risk: "low", recommendation: "Header is properly configured" },
    { name: "Referrer-Policy", present: false, risk: "medium", recommendation: "Add Referrer-Policy to control referrer information" },
  ];

  const getSeverityStyles = (severity: string) => {
    const base = "px-2.5 py-1 rounded text-xs font-semibold uppercase tracking-wide";
    const styles: Record<string, string> = {
      critical: `${base} bg-red-500/20 text-red-400 border border-red-500/30`,
      high: `${base} bg-orange-500/20 text-orange-400 border border-orange-500/30`,
      medium: `${base} bg-yellow-500/20 text-yellow-400 border border-yellow-500/30`,
      low: `${base} bg-emerald-500/20 text-emerald-400 border border-emerald-500/30`,
      info: `${base} bg-slate-500/20 text-slate-400 border border-slate-500/30`,
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

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-gray-100 relative overflow-hidden">
      {/* Background Effects */}
      <div className="absolute inset-0 opacity-[0.03]" style={{
        backgroundImage: `linear-gradient(rgba(0,255,170,0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(0,255,170,0.1) 1px, transparent 1px)`,
        backgroundSize: "50px 50px",
      }} />
      <div className="absolute inset-0 bg-gradient-to-br from-cyan-950/20 via-transparent to-emerald-950/20 pointer-events-none" />

      <div className="relative z-10 max-w-7xl mx-auto px-6 py-8">
        {/* Header with Logo */}
        <header className="mb-10 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-14 h-14 relative">
              <Image src="/logo.png" alt="RS Security" fill className="object-contain" priority />
            </div>
            <div>
              <h1 className="text-3xl md:text-4xl font-bold bg-gradient-to-r from-cyan-400 via-emerald-300 to-purple-400 bg-clip-text text-transparent">
                ReconScience
              </h1>
              <p className="text-gray-500 text-sm font-mono">Advanced Security Reconnaissance Platform</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 mr-4">
              <div className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse" />
              <span className="font-mono text-xs text-emerald-400/80">Online</span>
            </div>
            <a href="/history" className="text-gray-400 hover:text-gray-200 text-sm">History</a>
            <a href="/login" className="text-gray-400 hover:text-gray-200 text-sm">Login</a>
            <a href="/register" className="px-4 py-2 bg-gradient-to-r from-emerald-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 text-white text-sm rounded-lg transition-all">
              Sign Up
            </a>
          </div>
        </header>

        {/* Main Content */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column - Scan Configuration */}
          <div className="lg:col-span-1 space-y-6">
            {/* User Info Card */}
            <div className="bg-[#12121a] border border-gray-800/50 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
                <span className="text-lg">👤</span> User Information
              </h3>
              <div className="space-y-4">
                <div>
                  <label className="block font-mono text-xs text-gray-500 uppercase mb-2">Name</label>
                  <input
                    type="text" value={userName} onChange={(e) => setUserName(e.target.value)}
                    placeholder="Your name" disabled={status === "scanning"}
                    className="w-full bg-[#0a0a0f] border border-gray-700/50 rounded-lg px-3 py-2.5 text-sm font-mono placeholder-gray-600 focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all disabled:opacity-50"
                  />
                </div>
                <div>
                  <label className="block font-mono text-xs text-gray-500 uppercase mb-2">Email</label>
                  <input
                    type="email" value={userEmail} onChange={(e) => setUserEmail(e.target.value)}
                    placeholder="your@email.com" disabled={status === "scanning"}
                    className="w-full bg-[#0a0a0f] border border-gray-700/50 rounded-lg px-3 py-2.5 text-sm font-mono placeholder-gray-600 focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all disabled:opacity-50"
                  />
                </div>
              </div>
            </div>

            {/* Scan Mode Selection */}
            <div className="bg-[#12121a] border border-gray-800/50 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
                <span className="text-lg">🎯</span> Scan Mode
              </h3>
              <div className="space-y-2">
                {SCAN_MODES.map((mode) => (
                  <button
                    key={mode.id}
                    onClick={() => setScanMode(mode.id)}
                    disabled={status === "scanning"}
                    className={`w-full text-left p-3 rounded-lg border transition-all ${scanMode === mode.id
                      ? "bg-cyan-500/10 border-cyan-500/50 text-cyan-300"
                      : "bg-[#0a0a0f] border-gray-700/50 text-gray-400 hover:border-gray-600"
                      } disabled:opacity-50`}
                  >
                    <div className="flex items-center gap-3">
                      <span className="text-xl">{mode.icon}</span>
                      <div>
                        <div className="font-semibold text-sm">{mode.name}</div>
                        <div className="text-xs opacity-70">{mode.desc}</div>
                      </div>
                    </div>
                  </button>
                ))}
              </div>

              {/* Custom Categories */}
              {scanMode === "custom" && (
                <div className="mt-4 pt-4 border-t border-gray-800/50">
                  <p className="text-xs text-gray-500 mb-3">Select categories:</p>
                  <div className="space-y-2">
                    {CATEGORIES.map((cat) => (
                      <label key={cat.id} className="flex items-center gap-3 p-2 rounded-lg hover:bg-gray-800/30 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={selectedCategories.includes(cat.id)}
                          onChange={() => handleCategoryToggle(cat.id)}
                          className="w-4 h-4 rounded border-gray-600 bg-gray-800 text-cyan-500 focus:ring-cyan-500/20"
                        />
                        <div>
                          <div className="text-sm text-gray-300">{cat.label}</div>
                          <div className="text-xs text-gray-500">{cat.desc}</div>
                        </div>
                      </label>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Right Column - Target & Results */}
          <div className="lg:col-span-2 space-y-6">
            {/* Target Input */}
            <div className="bg-[#12121a] border border-gray-800/50 rounded-xl p-5">
              <label className="block font-mono text-xs text-gray-500 uppercase mb-3">Target URL</label>
              <div className="flex gap-3">
                <input
                  type="url" value={target} onChange={(e) => setTarget(e.target.value)}
                  placeholder="https://target.example.com" disabled={status === "scanning"}
                  className="flex-1 bg-[#0a0a0f] border border-gray-700/50 rounded-lg px-4 py-3 font-mono placeholder-gray-600 focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/20 transition-all disabled:opacity-50"
                />
                <button
                  onClick={handleScan}
                  disabled={status === "scanning" || !isFormValid}
                  className="px-6 py-3 bg-gradient-to-r from-emerald-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 text-white font-semibold rounded-lg transition-all disabled:opacity-40 disabled:cursor-not-allowed shadow-lg shadow-emerald-900/30 hover:shadow-emerald-500/30 active:scale-[0.98] whitespace-nowrap"
                >
                  {status === "scanning" ? (
                    <span className="flex items-center gap-2">
                      <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                      </svg>
                      {progress}%
                    </span>
                  ) : "Start Scan"}
                </button>
              </div>
              <p className="mt-3 text-xs text-gray-500 font-mono">⚠ Only scan targets you own or have permission to test.</p>
            </div>

            {/* Scanning Progress */}
            {status === "scanning" && (
              <div className="bg-[#12121a] border border-gray-800/50 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <span className="font-mono text-sm text-cyan-400 flex items-center gap-2">
                    <div className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse" />
                    Scanning in progress...
                  </span>
                  <span className="text-sm text-gray-500">{progress}%</span>
                </div>
                <div className="w-full bg-gray-800 rounded-full h-1.5 mb-4">
                  <div className="bg-gradient-to-r from-cyan-500 to-emerald-500 h-1.5 rounded-full transition-all duration-500" style={{ width: `${progress}%` }} />
                </div>
                <div className="bg-[#0a0a0f] rounded-lg p-4 font-mono text-xs border border-gray-800/50 max-h-40 overflow-y-auto">
                  {terminalLog.map((log, i) => (
                    <div key={i} className="text-emerald-400/70 flex items-center gap-2">
                      <span className="text-gray-600">[{String(i + 1).padStart(2, "0")}]</span>
                      <span>{log}</span>
                    </div>
                  ))}
                  <div className="text-gray-500 animate-pulse mt-1">█</div>
                </div>
              </div>
            )}

            {/* Error State */}
            {status === "error" && error && (
              <div className="bg-red-950/30 border border-red-500/30 rounded-xl p-5">
                <div className="flex items-center gap-3">
                  <svg className="w-5 h-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <span className="font-mono text-sm text-red-400">{error}</span>
                </div>
              </div>
            )}

            {/* Results Section */}
            {status === "complete" && (
              <div className="bg-[#12121a] border border-gray-800/50 rounded-xl overflow-hidden">
                {/* Tabs */}
                <div className="flex border-b border-gray-800/50 overflow-x-auto">
                  {[
                    { id: "overview" as ResultTab, label: "Overview", icon: "📊" },
                    { id: "vulnerabilities" as ResultTab, label: `Vulnerabilities (${results.length})`, icon: "🔓" },
                    { id: "headers" as ResultTab, label: "Headers", icon: "🛡️" },
                    { id: "tech" as ResultTab, label: "Tech Stack", icon: "⚙️" },
                  ].map((tab) => (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id)}
                      className={`px-5 py-3 text-sm font-medium whitespace-nowrap transition-all ${activeTab === tab.id
                        ? "text-cyan-400 border-b-2 border-cyan-400 bg-cyan-500/5"
                        : "text-gray-500 hover:text-gray-300"
                        }`}
                    >
                      <span className="mr-2">{tab.icon}</span>{tab.label}
                    </button>
                  ))}
                </div>

                {/* Tab Content */}
                <div className="p-5">
                  {/* Overview Tab */}
                  {activeTab === "overview" && (
                    <div className="space-y-6">
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <div className="bg-[#0a0a0f] rounded-xl p-4 text-center">
                          <div className={`text-3xl font-bold ${getRiskColor(riskScore)}`}>{riskScore}</div>
                          <div className="text-xs text-gray-500 mt-1">Risk Score</div>
                        </div>
                        <div className="bg-[#0a0a0f] rounded-xl p-4 text-center">
                          <div className="text-3xl font-bold text-red-400">{countBySeverity("critical") + countBySeverity("high")}</div>
                          <div className="text-xs text-gray-500 mt-1">Critical/High</div>
                        </div>
                        <div className="bg-[#0a0a0f] rounded-xl p-4 text-center">
                          <div className="text-3xl font-bold text-yellow-400">{countBySeverity("medium")}</div>
                          <div className="text-xs text-gray-500 mt-1">Medium</div>
                        </div>
                        <div className="bg-[#0a0a0f] rounded-xl p-4 text-center">
                          <div className="text-3xl font-bold text-emerald-400">{countBySeverity("low") + countBySeverity("info")}</div>
                          <div className="text-xs text-gray-500 mt-1">Low/Info</div>
                        </div>
                      </div>

                      <div className="bg-[#0a0a0f] rounded-xl p-5">
                        <h4 className="text-sm font-semibold text-gray-300 mb-3">Scan Summary</h4>
                        <div className="grid grid-cols-2 gap-4 text-sm">
                          <div className="flex justify-between"><span className="text-gray-500">Target:</span><span className="text-cyan-400 font-mono">{target}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Mode:</span><span className="text-gray-300">{SCAN_MODES.find(m => m.id === scanMode)?.name}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Total Findings:</span><span className="text-gray-300">{results.length}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Headers Checked:</span><span className="text-gray-300">{headers.length}</span></div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Vulnerabilities Tab */}
                  {activeTab === "vulnerabilities" && (
                    results.length === 0 ? (
                      <div className="text-center py-10">
                        <div className="text-5xl mb-4">🛡️</div>
                        <p className="text-emerald-400 font-mono">No vulnerabilities detected!</p>
                        <p className="text-gray-500 text-sm mt-2">The scan completed with no findings.</p>
                      </div>
                    ) : (
                      <div className="overflow-x-auto">
                        <table className="w-full">
                          <thead>
                            <tr className="bg-[#0a0a0f]/50">
                              <th className="px-4 py-3 text-left font-mono text-xs text-gray-400 uppercase">Template</th>
                              <th className="px-4 py-3 text-left font-mono text-xs text-gray-400 uppercase">Finding</th>
                              <th className="px-4 py-3 text-left font-mono text-xs text-gray-400 uppercase">Severity</th>
                              <th className="px-4 py-3 text-left font-mono text-xs text-gray-400 uppercase">URL</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-gray-800/50">
                            {results.map((r, i) => (
                              <tr key={i} className="hover:bg-white/[0.02]">
                                <td className="px-4 py-3 font-mono text-xs text-cyan-400/80">{r.template_id}</td>
                                <td className="px-4 py-3 text-sm text-gray-200">{r.name}</td>
                                <td className="px-4 py-3"><span className={getSeverityStyles(r.severity)}>{r.severity}</span></td>
                                <td className="px-4 py-3 font-mono text-xs text-gray-400 max-w-xs truncate">{r.matched_at}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )
                  )}

                  {/* Headers Tab */}
                  {activeTab === "headers" && (
                    <div className="space-y-3">
                      {headers.map((h, i) => (
                        <div key={i} className={`p-4 rounded-lg border ${h.present ? "bg-emerald-500/5 border-emerald-500/20" : "bg-red-500/5 border-red-500/20"}`}>
                          <div className="flex items-center justify-between mb-2">
                            <span className="font-mono text-sm text-gray-200">{h.name}</span>
                            <span className={`px-2 py-0.5 rounded text-xs ${h.present ? "bg-emerald-500/20 text-emerald-400" : "bg-red-500/20 text-red-400"}`}>
                              {h.present ? "Present" : "Missing"}
                            </span>
                          </div>
                          {h.value && <p className="text-xs text-gray-400 font-mono mb-1">Value: {h.value}</p>}
                          <p className="text-xs text-gray-500">{h.recommendation}</p>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Tech Stack Tab */}
                  {activeTab === "tech" && (
                    techStack.length === 0 ? (
                      <div className="text-center py-10">
                        <div className="text-5xl mb-4">🔍</div>
                        <p className="text-gray-400">Technology detection coming soon</p>
                        <p className="text-gray-500 text-sm mt-2">Run a Full Scan to detect web technologies.</p>
                      </div>
                    ) : (
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                        {techStack.map((t, i) => (
                          <div key={i} className="bg-[#0a0a0f] rounded-lg p-4">
                            <div className="text-xs text-gray-500 uppercase mb-1">{t.type}</div>
                            <div className="text-gray-200 font-medium">{t.name}</div>
                            {t.version && <div className="text-xs text-cyan-400 font-mono mt-1">v{t.version}</div>}
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
        <footer className="mt-12 text-center border-t border-gray-800/50 pt-8">
          <p className="font-mono text-xs text-gray-600">ReconScience • Advanced Security Reconnaissance Platform</p>
          <p className="font-mono text-xs text-gray-500 mt-2">© 2026 Alif. All rights reserved.</p>
        </footer>
      </div>
    </div>
  );
}
