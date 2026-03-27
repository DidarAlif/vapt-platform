import React from "react";
import Link from "next/link";

export default function AboutPage() {
  return (
    <div className="min-h-screen bg-[#12131c] text-on-surface py-16 px-6">
      <div className="max-w-4xl mx-auto space-y-12">

        {/* Header */}
        <section className="bg-surface-container-low border border-outline-variant/10 p-8 rounded-2xl relative overflow-hidden">
          <div className="absolute top-0 left-0 w-1.5 h-full bg-primary rounded-r-full"></div>
          <h1 className="text-3xl font-headline font-bold text-on-surface tracking-tight mb-4 pl-4">
            About <span className="text-primary">RECONSCIENCE</span>
          </h1>
          <p className="text-sm text-on-surface-variant font-body leading-relaxed max-w-2xl pl-4">
            ReconScience is an advanced, automated Vulnerability Assessment and Penetration Testing (VAPT) platform. It provides a hacker-centric perspective on your infrastructure, helping security teams and developers discover misconfigurations and CVEs before malicious actors do.
          </p>
        </section>

        {/* Features Grid */}
        <section className="grid md:grid-cols-2 gap-6">
          <div className="bg-surface-container-low border border-outline-variant/10 p-6 rounded-xl hover:border-primary/30 transition-all group">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                <span className="material-symbols-outlined text-primary">radar</span>
              </div>
              <h2 className="text-lg font-headline font-bold text-on-surface">Automated Scanning</h2>
            </div>
            <p className="text-sm text-on-surface-variant font-body leading-relaxed">
              Leveraging the power of Project Discovery&apos;s Nuclei, ReconScience runs thousands of security templates against your target. It fingerprints technologies, detects CVEs, and finds exposed panels automatically.
            </p>
          </div>
          <div className="bg-surface-container-low border border-outline-variant/10 p-6 rounded-xl hover:border-primary/30 transition-all group">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                <span className="material-symbols-outlined text-primary">stream</span>
              </div>
              <h2 className="text-lg font-headline font-bold text-on-surface">Real-time Streaming</h2>
            </div>
            <p className="text-sm text-on-surface-variant font-body leading-relaxed">
              Gone are the days of waiting for a progress bar. ReconScience streams a live terminal feed of the backend scanner directly to your browser using Server-Sent Events (SSE).
            </p>
          </div>
        </section>

        {/* Tech Stack */}
        <section className="bg-surface-container-low border border-outline-variant/10 p-8 rounded-xl">
          <h2 className="text-xl font-headline font-bold text-primary tracking-widest uppercase mb-8 flex items-center gap-3">
            <span className="w-1.5 h-6 bg-primary rounded-full"></span>
            Technology Stack
          </h2>

          <div className="grid md:grid-cols-3 gap-8">
            <div className="space-y-3">
              <h3 className="text-sm font-headline font-bold text-on-surface uppercase tracking-wider">Frontend</h3>
              <ul className="text-sm text-on-surface-variant font-body space-y-2">
                <li className="flex items-center gap-2"><span className="w-1 h-1 rounded-full bg-primary"></span>Next.js 16 (App Router)</li>
                <li className="flex items-center gap-2"><span className="w-1 h-1 rounded-full bg-primary"></span>React 19</li>
                <li className="flex items-center gap-2"><span className="w-1 h-1 rounded-full bg-primary"></span>Tailwind CSS v4</li>
                <li className="flex items-center gap-2"><span className="w-1 h-1 rounded-full bg-primary"></span>TypeScript</li>
              </ul>
            </div>
            <div className="space-y-3">
              <h3 className="text-sm font-headline font-bold text-on-surface uppercase tracking-wider">Backend</h3>
              <ul className="text-sm text-on-surface-variant font-body space-y-2">
                <li className="flex items-center gap-2"><span className="w-1 h-1 rounded-full bg-secondary"></span>Python 3.11</li>
                <li className="flex items-center gap-2"><span className="w-1 h-1 rounded-full bg-secondary"></span>FastAPI</li>
                <li className="flex items-center gap-2"><span className="w-1 h-1 rounded-full bg-secondary"></span>SQLAlchemy (ORM)</li>
                <li className="flex items-center gap-2"><span className="w-1 h-1 rounded-full bg-secondary"></span>JWT Authentication</li>
                <li className="flex items-center gap-2"><span className="w-1 h-1 rounded-full bg-secondary"></span>Server-Sent Events</li>
              </ul>
            </div>
            <div className="space-y-3">
              <h3 className="text-sm font-headline font-bold text-on-surface uppercase tracking-wider">Security Engine</h3>
              <ul className="text-sm text-on-surface-variant font-body space-y-2">
                <li className="flex items-center gap-2"><span className="w-1 h-1 rounded-full bg-tertiary"></span>Nuclei (Go)</li>
                <li className="flex items-center gap-2"><span className="w-1 h-1 rounded-full bg-tertiary"></span>Subfinder</li>
                <li className="flex items-center gap-2"><span className="w-1 h-1 rounded-full bg-tertiary"></span>Custom YAML templates</li>
              </ul>
            </div>
          </div>
        </section>

        {/* Footer Link */}
        <div className="text-center">
          <Link
            href="/scan"
            className="inline-flex items-center gap-2 bg-primary-container text-on-primary-container px-8 py-3 rounded-xl font-headline font-bold active:scale-95 transition-transform"
          >
            <span className="material-symbols-outlined">rocket_launch</span>
            Start Scanning
          </Link>
        </div>
      </div>
    </div>
  );
}
