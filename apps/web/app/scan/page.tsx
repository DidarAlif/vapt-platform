"use client";

import { useState } from "react";

interface ScanResult {
  template_id: string;
  name: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  matched_at: string;
  description: string;
}

type ScanStatus = "idle" | "scanning" | "complete" | "error";

const terminalMessages = [
  "Initializing scan engine...",
  "Loading vulnerability templates...",
  "Dispatching reconnaissance probes...",
  "Analyzing response headers...",
  "Checking security configurations...",
];

export default function ScanPage() {
  const [userName, setUserName] = useState("");
  const [userEmail, setUserEmail] = useState("");
  const [target, setTarget] = useState("");
  const [status, setStatus] = useState<ScanStatus>("idle");
  const [results, setResults] = useState<ScanResult[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [terminalLog, setTerminalLog] = useState<string[]>([]);

  const simulateTerminalLogs = () => {
    setTerminalLog([]);
    let index = 0;
    const interval = setInterval(() => {
      if (index < terminalMessages.length) {
        setTerminalLog((prev) => [...prev, terminalMessages[index]]);
        index++;
      } else {
        clearInterval(interval);
      }
    }, 800);
    return interval;
  };

  const isFormValid = userName.trim() && userEmail.trim() && target.trim();

  const handleScan = async () => {
    if (!isFormValid) return;

    setStatus("scanning");
    setError(null);
    setResults([]);
    const logInterval = simulateTerminalLogs();

    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000"}/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          name: userName.trim(),
          email: userEmail.trim(),
          target: target.trim(),
        }),
      });

      if (!response.ok) {
        throw new Error(`Scan failed with status ${response.status}`);
      }

      const data: ScanResult[] = await response.json();
      clearInterval(logInterval);
      setResults(data);
      setStatus("complete");
    } catch (err) {
      clearInterval(logInterval);
      setError(err instanceof Error ? err.message : "An unexpected error occurred");
      setStatus("error");
    }
  };

  const getSeverityStyles = (severity: string) => {
    const baseStyles = "px-2.5 py-1 rounded text-xs font-semibold uppercase tracking-wide";
    switch (severity) {
      case "critical":
        return `${baseStyles} bg-red-500/20 text-red-400 border border-red-500/30`;
      case "high":
        return `${baseStyles} bg-orange-500/20 text-orange-400 border border-orange-500/30`;
      case "medium":
        return `${baseStyles} bg-yellow-500/20 text-yellow-400 border border-yellow-500/30`;
      case "low":
        return `${baseStyles} bg-emerald-500/20 text-emerald-400 border border-emerald-500/30`;
      case "info":
      default:
        return `${baseStyles} bg-slate-500/20 text-slate-400 border border-slate-500/30`;
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-gray-100 relative overflow-hidden">
      {/* Background Grid Effect */}
      <div
        className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage: `
            linear-gradient(rgba(0, 255, 170, 0.1) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 255, 170, 0.1) 1px, transparent 1px)
          `,
          backgroundSize: "50px 50px",
        }}
      />

      {/* Gradient Overlay */}
      <div className="absolute inset-0 bg-gradient-to-br from-cyan-950/20 via-transparent to-emerald-950/20 pointer-events-none" />

      <div className="relative z-10 max-w-6xl mx-auto px-6 py-12">
        {/* Header Section */}
        <header className="mb-12">
          <div className="flex items-center gap-3 mb-4">
            <div className="relative">
              <div className="w-3 h-3 bg-emerald-400 rounded-full animate-pulse" />
              <div className="w-3 h-3 bg-emerald-400 rounded-full absolute inset-0 animate-ping opacity-75" />
            </div>
            <span className="font-mono text-xs text-emerald-400/80 uppercase tracking-widest">
              System Online
            </span>
          </div>

          <h1 className="text-4xl md:text-5xl font-bold bg-gradient-to-r from-gray-100 via-emerald-200 to-cyan-200 bg-clip-text text-transparent mb-3">
            Vulnerability Scan Console
          </h1>
          <p className="text-gray-400 font-mono text-sm md:text-base">
            Automated reconnaissance powered by <span className="text-cyan-400">Nuclei</span>
          </p>
        </header>

        {/* Scan Input Card */}
        <div className="bg-[#12121a] border border-gray-800/50 rounded-xl p-6 md:p-8 mb-8 backdrop-blur-sm shadow-2xl shadow-black/50">
          {/* User Information Section */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <div>
              <label htmlFor="userName" className="block font-mono text-xs text-gray-400 uppercase tracking-wider mb-3">
                Your Name <span className="text-red-400">*</span>
              </label>
              <input
                id="userName"
                type="text"
                value={userName}
                onChange={(e) => setUserName(e.target.value)}
                placeholder="John Doe"
                disabled={status === "scanning"}
                className="w-full bg-[#0a0a0f] border border-gray-700/50 rounded-lg px-4 py-3.5 font-mono text-gray-100 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/20 focus:shadow-[0_0_20px_rgba(0,255,170,0.1)] transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
              />
            </div>
            <div>
              <label htmlFor="userEmail" className="block font-mono text-xs text-gray-400 uppercase tracking-wider mb-3">
                Email Address <span className="text-red-400">*</span>
              </label>
              <input
                id="userEmail"
                type="email"
                value={userEmail}
                onChange={(e) => setUserEmail(e.target.value)}
                placeholder="john@example.com"
                disabled={status === "scanning"}
                className="w-full bg-[#0a0a0f] border border-gray-700/50 rounded-lg px-4 py-3.5 font-mono text-gray-100 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/20 focus:shadow-[0_0_20px_rgba(0,255,170,0.1)] transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
              />
            </div>
          </div>

          <div className="mb-6">
            <label htmlFor="target" className="block font-mono text-xs text-gray-400 uppercase tracking-wider mb-3">
              Target URL <span className="text-red-400">*</span>
            </label>
            <input
              id="target"
              type="url"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://target.example"
              disabled={status === "scanning"}
              className="w-full bg-[#0a0a0f] border border-gray-700/50 rounded-lg px-4 py-3.5 font-mono text-gray-100 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/20 focus:shadow-[0_0_20px_rgba(0,255,170,0.1)] transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
            />
          </div>

          <button
            onClick={handleScan}
            disabled={status === "scanning" || !isFormValid}
            className="w-full md:w-auto px-8 py-3.5 bg-gradient-to-r from-emerald-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 text-white font-semibold rounded-lg transition-all duration-300 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:from-emerald-600 disabled:hover:to-cyan-600 shadow-lg shadow-emerald-900/30 hover:shadow-emerald-500/30 active:scale-[0.98]"
          >
            {status === "scanning" ? (
              <span className="flex items-center justify-center gap-2">
                <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
                Scanning...
              </span>
            ) : (
              "Start Scan"
            )}
          </button>

          <p className="mt-4 text-xs text-gray-500 font-mono">
            ⚠ Only scan targets you own or have permission to test.
          </p>
        </div>

        {/* Scan Status Area */}
        {status === "scanning" && (
          <div className="bg-[#12121a] border border-gray-800/50 rounded-xl p-6 mb-8 backdrop-blur-sm">
            <div className="flex items-center gap-3 mb-4">
              <div className="relative">
                <div className="w-2.5 h-2.5 bg-cyan-400 rounded-full animate-pulse" />
              </div>
              <span className="font-mono text-sm text-cyan-400">Scanning target...</span>
            </div>

            <div className="bg-[#0a0a0f] rounded-lg p-4 font-mono text-xs border border-gray-800/50">
              <div className="text-gray-500 mb-2">$ nuclei -u {target}</div>
              {terminalLog.map((log, index) => (
                <div key={index} className="text-emerald-400/70 flex items-center gap-2">
                  <span className="text-gray-600">[{String(index + 1).padStart(2, "0")}]</span>
                  <span>{log}</span>
                </div>
              ))}
              <div className="flex items-center gap-1 text-gray-500 mt-1">
                <span className="animate-pulse">█</span>
              </div>
            </div>
          </div>
        )}

        {/* Error State */}
        {status === "error" && error && (
          <div className="bg-red-950/30 border border-red-500/30 rounded-xl p-6 mb-8">
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
          <div className="bg-[#12121a] border border-gray-800/50 rounded-xl overflow-hidden backdrop-blur-sm">
            <div className="px-6 py-4 border-b border-gray-800/50 flex items-center justify-between">
              <h2 className="font-mono text-lg text-gray-100 flex items-center gap-3">
                <svg className="w-5 h-5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                </svg>
                Scan Results
              </h2>
              <span className="font-mono text-xs text-gray-500">
                {results.length} finding{results.length !== 1 ? "s" : ""}
              </span>
            </div>

            {results.length === 0 ? (
              <div className="px-6 py-12 text-center">
                <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-emerald-500/10 mb-4">
                  <svg className="w-8 h-8 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <p className="font-mono text-emerald-400 text-sm">No vulnerabilities detected for this target.</p>
                <p className="font-mono text-gray-500 text-xs mt-2">The scan completed successfully with no findings.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="bg-[#0a0a0f]/50">
                      <th className="px-6 py-3 text-left font-mono text-xs text-gray-400 uppercase tracking-wider">Template ID</th>
                      <th className="px-6 py-3 text-left font-mono text-xs text-gray-400 uppercase tracking-wider">Finding Name</th>
                      <th className="px-6 py-3 text-left font-mono text-xs text-gray-400 uppercase tracking-wider">Severity</th>
                      <th className="px-6 py-3 text-left font-mono text-xs text-gray-400 uppercase tracking-wider">Affected URL</th>
                      <th className="px-6 py-3 text-left font-mono text-xs text-gray-400 uppercase tracking-wider">Description</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800/50">
                    {results.map((result, index) => (
                      <tr
                        key={index}
                        className="hover:bg-white/[0.02] transition-colors duration-150"
                      >
                        <td className="px-6 py-4 font-mono text-xs text-cyan-400/80 whitespace-nowrap">
                          {result.template_id}
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-200 max-w-xs">
                          {result.name}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={getSeverityStyles(result.severity)}>
                            {result.severity}
                          </span>
                        </td>
                        <td className="px-6 py-4 font-mono text-xs text-gray-400 max-w-xs truncate">
                          {result.matched_at}
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-400 max-w-md">
                          {result.description}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Footer */}
        <footer className="mt-12 text-center">
          <p className="font-mono text-xs text-gray-600">
            VAPT Platform • Vulnerability Assessment &amp; Penetration Testing
          </p>
          <p className="font-mono text-xs text-gray-500 mt-2">
            © 2026 Alif. All rights reserved.
          </p>
        </footer>
      </div>
    </div>
  );
}
