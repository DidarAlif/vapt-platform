import React from "react";

export default function AboutPage() {
  return (
    <div className="min-h-screen bg-[#050505] text-[#e5e5e5] cyber-grid py-12 px-6">
      <div className="max-w-4xl mx-auto space-y-12">
        
        {/* Header Section */}
        <section className="border border-[#00d4aa]/30 bg-[#050505]/80 backdrop-blur p-8 shadow-[0_0_15px_rgba(0,212,170,0.1)] relative overflow-hidden">
          <div className="absolute top-0 left-0 w-2 h-full bg-[#00d4aa]"></div>
          <h1 className="text-3xl font-mono text-[#00d4aa] uppercase tracking-widest mb-4">About ReconScience</h1>
          <p className="text-sm font-mono text-gray-400 leading-relaxed max-w-2xl">
            ReconScience is an advanced, automated Vulnerability Assessment and Penetration Testing (VAPT) platform. It provides a hacker-centric perspective on your infrastructure, helping security teams and developers discover misconfigurations and CVEs before malicious actors do.
          </p>
        </section>

        {/* What does the app do */}
        <section className="grid md:grid-cols-2 gap-8">
          <div className="border border-gray-800 p-6 bg-[#0a0a0f] hover:border-[#00d4aa]/50 transition-all group">
            <h2 className="text-xl font-mono text-white tracking-wider mb-3 flex items-center gap-2">
              <span className="text-[#00d4aa]">{">"}</span> Automated Scanning
            </h2>
            <p className="text-sm text-gray-400 font-mono">
              Leveraging the power of Project Discovery's Nuclei, ReconScience runs thousands of security templates against your target. It fingerprints technologies, detects CVEs, and finds exposed panels automatically.
            </p>
          </div>
          <div className="border border-gray-800 p-6 bg-[#0a0a0f] hover:border-[#00ff41]/50 transition-all group">
            <h2 className="text-xl font-mono text-white tracking-wider mb-3 flex items-center gap-2">
              <span className="text-[#00ff41]">{">"}</span> Real-time Streaming
            </h2>
            <p className="text-sm text-gray-400 font-mono">
              Gone are the days of waiting for a progress bar. ReconScience streams a live terminal feed of the backend scanner directly to your browser using Server-Sent Events (SSE).
            </p>
          </div>
        </section>

        {/* Tech Stack */}
        <section className="border border-gray-800 p-8 bg-[#0a0a0f]">
          <h2 className="text-2xl font-mono text-[#00d4aa] tracking-widest uppercase mb-6 border-b border-gray-800 pb-4">Technology Stack</h2>
          
          <div className="grid md:grid-cols-3 gap-6">
            <div className="space-y-2">
              <h3 className="text-lg font-mono text-white">Frontend</h3>
              <ul className="text-sm font-mono text-gray-500 space-y-1 list-disc list-inside">
                <li>Next.js 15 (App Router)</li>
                <li>React 19</li>
                <li>Tailwind CSS WebGL</li>
                <li>TypeScript</li>
              </ul>
            </div>
            
            <div className="space-y-2">
              <h3 className="text-lg font-mono text-white">Backend Server</h3>
              <ul className="text-sm font-mono text-gray-500 space-y-1 list-disc list-inside">
                <li>Python 3.11</li>
                <li>FastAPI</li>
                <li>SQLAlchemy (ORM)</li>
                <li>JWT Authentication</li>
                <li>Server-Sent Events</li>
              </ul>
            </div>

            <div className="space-y-2">
              <h3 className="text-lg font-mono text-white">Security Engine</h3>
              <ul className="text-sm font-mono text-gray-500 space-y-1 list-disc list-inside">
                <li>Nuclei (Go implementation)</li>
                <li>Subfinder</li>
                <li>Custom YAML templates</li>
              </ul>
            </div>
          </div>
        </section>

      </div>
    </div>
  );
}
