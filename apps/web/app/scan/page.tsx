"use client";

import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import AuthenticatedLayout from "../../components/AuthenticatedLayout";

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

const API_URL = (process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

const SCAN_MODES: { id: ScanMode; name: string; desc: string; time: string; icon: string }[] = [
  { id: "quick", name: "Quick", desc: "Surface-level reconnaissance. Focuses on top 100 ports and common CVEs.", time: "~ 5 mins", icon: "bolt" },
  { id: "full", name: "Full", desc: "Deep architectural audit. Full port sweep and directory fuzzing.", time: "~ 45 mins", icon: "vitals" },
  { id: "network", name: "Network", desc: "Internal topology mapping. Discovers lateral movement vectors.", time: "~ 20 mins", icon: "hub" },
  { id: "custom", name: "Custom", desc: "Define specific payloads, headers, and evasion techniques.", time: "Variable", icon: "tune" },
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
  const [scanId, setScanId] = useState<string | null>(null);

  const terminalEndRef = useRef<HTMLDivElement | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  // Auto-scroll terminal
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [terminalLog, progress]);

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
      setUser(parsedUser);
    } catch {
      router.push("/login");
      return;
    }

    setLoading(false);
  }, [router]);

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

    const categories = scanMode === "custom" ? selectedCategories.join(",") : "";
    const sseUrl = `${API_URL}/scan/stream?target=${encodeURIComponent(target)}&scan_mode=${scanMode}&categories=${categories}`;

    abortControllerRef.current = new AbortController();

    try {
      const response = await fetch(sseUrl, {
        headers: {
          "Authorization": `Bearer ${token}`,
        },
        signal: abortControllerRef.current.signal,
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
                  if (data.scan_id) setScanId(data.scan_id);
                  setStatus("complete");
                  setActiveTab("overview");
                } else if (data.type === "error") {
                  throw new Error(data.message);
                }
              } catch {
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

    } catch (err: unknown) {
      if (err instanceof Error && err.name === "AbortError") {
        console.log("Scan cancelled");
        return;
      }
      console.error("Scan error:", err);
      setError(err instanceof Error ? err.message : "An unexpected error occurred");
      setStatus("error");
    }
  };

  const handleCancel = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      setStatus("idle");
      setTerminalLog(prev => [...prev, "[!] User aborted the scanner process..."]);
      setError("Scan cancelled by user.");
    }
  };

  const calculateRiskScore = (findings: ScanResult[]): number => {
    if (!findings.length) return 0;
    const weights: Record<string, number> = { critical: 40, high: 25, medium: 15, low: 5, info: 1 };
    const score = findings.reduce((acc, f) => acc + (weights[f.severity] || 0), 0);
    return Math.min(100, score);
  };

  const getSeverityBadge = (severity: string) => {
    const styles: Record<string, string> = {
      critical: "bg-error text-error-container text-[9px] font-headline font-bold px-2 py-0.5 rounded",
      high: "bg-tertiary-container text-on-tertiary-container text-[9px] font-headline font-bold px-2 py-0.5 rounded",
      medium: "bg-[#ffcc00] text-surface text-[9px] font-headline font-bold px-2 py-0.5 rounded",
      low: "bg-emerald-500/20 text-emerald-400 text-[9px] font-headline font-bold px-2 py-0.5 rounded",
      info: "bg-surface-container-highest text-slate-400 text-[9px] font-headline font-bold px-2 py-0.5 rounded",
    };
    return styles[severity] || styles.info;
  };

  const getRiskColor = (score: number) => {
    if (score >= 70) return "text-error";
    if (score >= 40) return "text-tertiary";
    if (score >= 20) return "text-[#ffcc00]";
    return "text-emerald-400";
  };

  const countBySeverity = (severity: string) => results.filter(r => r.severity === severity).length;

  if (loading) {
    return (
      <div className="min-h-screen bg-surface flex items-center justify-center">
        <div className="text-on-surface-variant font-headline text-sm">Loading...</div>
      </div>
    );
  }

  return (
    <AuthenticatedLayout>
      <div className="max-w-6xl mx-auto px-10 py-12">
        {/* Header Section */}
        <div className="mb-12">
          <h1 className="text-4xl font-bold font-headline tracking-tight text-on-surface mb-2">
            New Scan Configuration
          </h1>
          <p className="text-on-surface-variant font-body max-w-2xl leading-relaxed">
            Initialize a high-fidelity diagnostic sweep across your infrastructure. Select a modality below to begin the ingestion process.
          </p>
        </div>

        {/* Stage 1: Target Input */}
        <section className="mb-10">
          <div className="flex items-center gap-3 mb-6">
            <span className="w-6 h-6 flex items-center justify-center rounded bg-primary-container text-[10px] font-bold text-on-primary-container">
              01
            </span>
            <h2 className="text-sm font-headline font-bold uppercase tracking-widest text-primary">
              Target Definition
            </h2>
          </div>
          <div className="relative group">
            <div className="absolute inset-y-0 left-0 pl-6 flex items-center pointer-events-none">
              <span className="material-symbols-outlined text-primary/50 group-focus-within:text-primary transition-colors">
                language
              </span>
            </div>
            <input
              type="url"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              disabled={status === "scanning"}
              className="w-full bg-surface-container-low border-b-2 border-outline-variant/20 focus:border-primary focus:ring-0 text-xl font-headline py-6 pl-16 pr-8 transition-all outline-none text-on-surface placeholder:text-slate-600 disabled:opacity-50"
              placeholder="https://target-infrastructure.io or 192.168.1.1"
            />
          </div>
          <p className="mt-2 text-[10px] text-slate-500 font-headline uppercase tracking-widest">
            Only engage authorized parameters. Unauthorized reconnaissance is prohibited.
          </p>
        </section>

        {/* Stage 2: Mode Selection */}
        <section className="mb-10">
          <div className="flex items-center gap-3 mb-6">
            <span className="w-6 h-6 flex items-center justify-center rounded bg-primary-container text-[10px] font-bold text-on-primary-container">
              02
            </span>
            <h2 className="text-sm font-headline font-bold uppercase tracking-widest text-primary">
              Scan Modality
            </h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {SCAN_MODES.map((mode) => (
              <button
                key={mode.id}
                onClick={() => setScanMode(mode.id)}
                disabled={status === "scanning"}
                className={`flex flex-col items-start p-6 transition-all text-left group disabled:opacity-50 ${
                  scanMode === mode.id
                    ? "bg-surface-container-high border-l-2 border-primary"
                    : "bg-surface-container-low border-l-2 border-transparent hover:border-primary/50 hover:bg-surface-container-high"
                }`}
              >
                <span
                  className={`material-symbols-outlined mb-4 text-3xl transition-colors ${
                    scanMode === mode.id ? "text-primary" : "text-slate-500 group-hover:text-primary"
                  }`}
                >
                  {mode.icon}
                </span>
                <h3 className="font-headline font-bold text-on-surface mb-1">{mode.name}</h3>
                <p className="text-xs text-on-surface-variant font-body leading-snug">{mode.desc}</p>
                <span className={`mt-4 text-[10px] font-bold tracking-widest uppercase ${
                  scanMode === mode.id ? "text-primary" : "text-slate-500"
                }`}>
                  {mode.time}
                </span>
              </button>
            ))}
          </div>

          {/* Custom Categories */}
          {scanMode === "custom" && (
            <div className="mt-6 bg-surface-container-low p-6 rounded-xl border border-outline-variant/10">
              <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-4 font-headline">
                Select scan categories
              </p>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {CATEGORIES.map((cat) => (
                  <label
                    key={cat.id}
                    className="flex items-center gap-2 p-3 rounded-lg hover:bg-surface-container cursor-pointer transition-colors"
                  >
                    <input
                      type="checkbox"
                      checked={selectedCategories.includes(cat.id)}
                      onChange={() => handleCategoryToggle(cat.id)}
                      className="rounded border-outline-variant bg-surface-container-highest text-primary focus:ring-primary/20"
                    />
                    <div>
                      <span className="text-xs text-on-surface font-headline font-medium">{cat.label}</span>
                      <p className="text-[10px] text-slate-500">{cat.desc}</p>
                    </div>
                  </label>
                ))}
              </div>
            </div>
          )}
        </section>

        {/* Bottom Action Area */}
        {status === "idle" && (
          <div className="flex items-center justify-between p-8 bg-surface-container-high rounded-2xl border border-primary/10 shadow-xl mb-10">
            <div className="flex items-center gap-6">
              <div className="flex flex-col">
                <span className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Estimated duration</span>
                <span className="text-lg font-headline font-bold text-on-surface">
                  {SCAN_MODES.find(m => m.id === scanMode)?.time || "Variable"}
                </span>
              </div>
              <div className="h-8 w-px bg-outline-variant/20"></div>
              <div className="flex flex-col">
                <span className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Scan mode</span>
                <span className="text-lg font-headline font-bold text-on-surface uppercase">
                  {SCAN_MODES.find(m => m.id === scanMode)?.name}
                </span>
              </div>
            </div>
            <button
              onClick={handleScan}
              disabled={!target.trim()}
              className="bg-primary-container hover:bg-[#8433c4] text-on-primary-container px-10 py-4 rounded-xl font-headline font-bold uppercase tracking-widest flex items-center gap-3 transition-all active:scale-95 shadow-[0_10px_30px_-10px_rgba(154,74,217,0.4)] disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <span className="material-symbols-outlined">rocket_launch</span>
              Start Scan
            </button>
          </div>
        )}

        {/* Scanning Progress */}
        {status === "scanning" && (
          <section className="mb-10">
            <div className="bg-surface-container-lowest rounded-xl border border-outline-variant/10 overflow-hidden">
              <div className="bg-surface-container-highest/50 px-6 py-3 flex items-center justify-between">
                <span className="text-[10px] font-headline font-bold text-primary flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-primary animate-pulse"></span>
                  REAL-TIME SCAN ANALYTICS
                </span>
                <div className="flex items-center gap-4">
                  <span className="text-[10px] font-headline text-on-surface-variant uppercase tracking-widest">
                    Progress: {progress}%
                  </span>
                  <button
                    onClick={handleCancel}
                    className="px-4 py-1.5 bg-error-container text-on-error-container text-[10px] font-headline font-bold rounded hover:bg-error transition-colors"
                  >
                    ABORT
                  </button>
                </div>
              </div>
              <div className="px-6 pt-4">
                <div className="h-1 w-full bg-surface-container-highest rounded-full overflow-hidden">
                  <div
                    className="h-full bg-primary transition-all duration-300 shadow-[0_0_8px_rgba(224,182,255,0.8)]"
                    style={{ width: `${progress}%` }}
                  />
                </div>
              </div>
              <div className="p-4 font-mono text-[10px] text-on-surface-variant/80 space-y-1 h-48 overflow-y-auto custom-scrollbar">
                {terminalLog.map((log, i) => (
                  <p key={i}>
                    <span className="text-outline">[{String(i + 1).padStart(2, "0")}]</span>{" "}
                    <span className="text-primary">{log}</span>
                  </p>
                ))}
                <div ref={terminalEndRef} className="h-1" />
                <p className="text-primary animate-pulse">_ BLINKING CURSOR</p>
              </div>
            </div>
          </section>
        )}

        {/* Error State */}
        {status === "error" && error && (
          <div className="mb-10 bg-error-container/20 border border-error/30 rounded-xl p-6 flex items-center gap-3">
            <span className="material-symbols-outlined text-error">error</span>
            <span className="text-error text-sm font-body">{error}</span>
          </div>
        )}

        {/* Results */}
        {status === "complete" && (
          <section className="space-y-8 mb-12">
            {/* Results Header */}
            <div className="grid grid-cols-12 gap-6">
              <div className="col-span-8 bg-surface-container-low p-8 rounded-xl">
                <div className="flex items-center gap-3 mb-2">
                  <span className="px-2 py-0.5 bg-secondary-container/30 text-secondary text-[10px] font-bold font-headline rounded border border-secondary/20">
                    SCAN COMPLETE
                  </span>
                </div>
                <h2 className="text-3xl font-headline font-bold text-on-surface tracking-tight mb-2">
                  {target}
                </h2>
                <div className="flex items-center gap-6 text-on-surface-variant font-body text-sm">
                  <div className="flex items-center gap-2">
                    <span className="material-symbols-outlined text-primary text-sm">security</span>
                    <span>Mode: <span className="text-on-surface font-medium uppercase">{SCAN_MODES.find(m => m.id === scanMode)?.name}</span></span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="material-symbols-outlined text-primary text-sm">bug_report</span>
                    <span>Findings: <span className="text-on-surface font-medium">{results.length}</span></span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="material-symbols-outlined text-primary text-sm">code</span>
                    <span>Tech Detected: <span className="text-on-surface font-medium">{techStack.length}</span></span>
                  </div>
                </div>
              </div>
              <div className={`col-span-4 bg-surface-container-high p-8 rounded-xl flex flex-col items-center justify-center border-l-4 ${riskScore >= 70 ? "border-error" : riskScore >= 40 ? "border-tertiary" : "border-emerald-500"}`}>
                <span className="text-on-surface-variant font-headline text-[10px] tracking-widest uppercase mb-1">
                  RISK SCORE
                </span>
                <div className={`text-7xl font-headline font-black ${getRiskColor(riskScore)}`}>
                  {riskScore}
                </div>
              </div>
            </div>

            {/* Tabs */}
            <div className="bg-surface-container-low rounded-xl overflow-hidden">
              <div className="flex border-b border-outline-variant/10 overflow-x-auto">
                {[
                  { id: "overview" as ResultTab, label: "Overview", icon: "analytics" },
                  { id: "vulnerabilities" as ResultTab, label: `Findings (${results.length})`, icon: "shield" },
                  { id: "headers" as ResultTab, label: "Headers", icon: "lock" },
                  { id: "tech" as ResultTab, label: "Tech Stack", icon: "code" },
                ].map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`px-6 py-4 text-sm font-headline font-medium whitespace-nowrap transition-all flex items-center gap-2 ${
                      activeTab === tab.id
                        ? "text-primary border-b-2 border-primary bg-primary/5"
                        : "text-slate-500 hover:text-on-surface"
                    }`}
                  >
                    <span className="material-symbols-outlined text-sm">{tab.icon}</span>
                    {tab.label}
                  </button>
                ))}

                {/* Export buttons */}
                {scanId && (
                  <div className="ml-auto flex items-center gap-2 px-4">
                    <a
                      href={`${API_URL}/scans/${scanId}/report/html`}
                      target="_blank"
                      className="px-3 py-1.5 bg-surface-container-highest text-on-surface-variant text-[10px] font-headline font-bold rounded border border-outline-variant/20 hover:border-primary hover:text-primary transition-all flex items-center gap-1"
                    >
                      <span className="material-symbols-outlined text-xs">code</span> HTML
                    </a>
                    <a
                      href={`${API_URL}/scans/${scanId}/report/json`}
                      target="_blank"
                      className="px-3 py-1.5 bg-surface-container-highest text-on-surface-variant text-[10px] font-headline font-bold rounded border border-outline-variant/20 hover:border-primary hover:text-primary transition-all flex items-center gap-1"
                    >
                      <span className="material-symbols-outlined text-xs">data_object</span> JSON
                    </a>
                  </div>
                )}
              </div>

              <div className="p-6">
                {/* Overview Tab */}
                {activeTab === "overview" && (
                  <div className="space-y-6">
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                      <div className="bg-surface-container-lowest p-4 rounded-xl text-center">
                        <div className={`text-3xl font-headline font-bold ${getRiskColor(riskScore)}`}>{riskScore}</div>
                        <div className="text-[10px] text-slate-500 mt-1 font-headline uppercase">Risk Score</div>
                      </div>
                      <div className="bg-surface-container-lowest p-4 rounded-xl text-center">
                        <div className="text-3xl font-headline font-bold text-error">{countBySeverity("critical")}</div>
                        <div className="text-[10px] text-slate-500 mt-1 font-headline uppercase">Critical</div>
                      </div>
                      <div className="bg-surface-container-lowest p-4 rounded-xl text-center">
                        <div className="text-3xl font-headline font-bold text-tertiary">{countBySeverity("high")}</div>
                        <div className="text-[10px] text-slate-500 mt-1 font-headline uppercase">High</div>
                      </div>
                      <div className="bg-surface-container-lowest p-4 rounded-xl text-center">
                        <div className="text-3xl font-headline font-bold text-[#ffcc00]">{countBySeverity("medium")}</div>
                        <div className="text-[10px] text-slate-500 mt-1 font-headline uppercase">Medium</div>
                      </div>
                      <div className="bg-surface-container-lowest p-4 rounded-xl text-center">
                        <div className="text-3xl font-headline font-bold text-emerald-400">{countBySeverity("low") + countBySeverity("info")}</div>
                        <div className="text-[10px] text-slate-500 mt-1 font-headline uppercase">Low/Info</div>
                      </div>
                    </div>
                    <div className="bg-surface-container p-6 rounded-xl border-l-2 border-primary/40">
                      <h4 className="text-sm font-headline font-bold text-primary uppercase tracking-wider mb-4">Mission Debrief</h4>
                      <div className="grid grid-cols-2 gap-4 text-sm font-body">
                        <div className="flex flex-col">
                          <span className="text-slate-500 text-xs mb-1">Target Host:</span>
                          <span className="text-primary truncate">{target}</span>
                        </div>
                        <div className="flex flex-col">
                          <span className="text-slate-500 text-xs mb-1">Protocol:</span>
                          <span className="text-on-surface uppercase">{SCAN_MODES.find(m => m.id === scanMode)?.name}</span>
                        </div>
                        <div className="flex flex-col">
                          <span className="text-slate-500 text-xs mb-1">Anomalies Detected:</span>
                          <span className="text-on-surface">{results.length}</span>
                        </div>
                        <div className="flex flex-col">
                          <span className="text-slate-500 text-xs mb-1">Tech Signatures:</span>
                          <span className="text-on-surface">{techStack.length}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Vulnerabilities Tab */}
                {activeTab === "vulnerabilities" && (
                  results.length === 0 ? (
                    <div className="text-center py-16">
                      <span className="material-symbols-outlined text-4xl text-slate-600 mb-3 block">verified_user</span>
                      <p className="text-primary font-headline text-sm">No vulnerabilities detected</p>
                      <p className="text-slate-500 text-xs mt-1">Scan completed with no findings.</p>
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left">
                        <thead className="bg-surface-container-lowest text-slate-500 uppercase font-headline font-bold text-[9px] tracking-[0.15em]">
                          <tr>
                            <th className="px-6 py-3">Template</th>
                            <th className="px-6 py-3">Finding</th>
                            <th className="px-6 py-3 text-center">Severity</th>
                            <th className="px-6 py-3">Matched URL</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-outline-variant/10 text-on-surface-variant text-xs">
                          {results.map((r, i) => (
                            <tr key={i} className="hover:bg-surface-container transition-colors">
                              <td className="px-6 py-3 font-mono text-primary/80">{r.template_id}</td>
                              <td className="px-6 py-3 text-on-surface font-medium">{r.name}</td>
                              <td className="px-6 py-3 text-center">
                                <span className={getSeverityBadge(r.severity)}>{r.severity.toUpperCase()}</span>
                              </td>
                              <td className="px-6 py-3 font-mono text-slate-500 max-w-[250px] truncate">{r.matched_at}</td>
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
                      <div
                        key={i}
                        className={`p-4 rounded-lg border-l-4 ${
                          h.present
                            ? "bg-emerald-500/5 border-emerald-500/50"
                            : "bg-error/5 border-error/50"
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-headline text-sm text-on-surface font-bold">{h.name}</span>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-headline font-bold ${
                              h.present ? "bg-emerald-500/20 text-emerald-400" : "bg-error/20 text-error"
                            }`}
                          >
                            {h.present ? "PRESENT" : "MISSING"}
                          </span>
                        </div>
                        {h.value && <p className="text-[10px] text-slate-500 font-mono truncate">{h.value}</p>}
                        <p className="text-xs text-on-surface-variant mt-1">{h.recommendation}</p>
                      </div>
                    ))}
                  </div>
                )}

                {/* Tech Stack Tab */}
                {activeTab === "tech" && (
                  techStack.length === 0 ? (
                    <div className="text-center py-16">
                      <span className="material-symbols-outlined text-4xl text-slate-600 mb-3 block">code</span>
                      <p className="text-on-surface-variant text-sm">No technologies detected</p>
                    </div>
                  ) : (
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                      {techStack.map((t, i) => (
                        <div key={i} className="bg-surface-container-lowest p-4 rounded-xl border border-outline-variant/10">
                          <div className="text-[10px] text-slate-500 uppercase font-headline">{t.type}</div>
                          <div className="text-on-surface font-headline font-bold text-sm mt-1">{t.name}</div>
                          {t.version && <div className="text-xs text-primary font-mono mt-1">v{t.version}</div>}
                        </div>
                      ))}
                    </div>
                  )
                )}
              </div>
            </div>
          </section>
        )}
      </div>
    </AuthenticatedLayout>
  );
}
