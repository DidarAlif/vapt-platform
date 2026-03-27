"use client";

import React from "react";
import Link from "next/link";
import AuthenticatedLayout from "../../components/AuthenticatedLayout";

export default function DeveloperPage() {
  return (
    <AuthenticatedLayout>
      <div className="max-w-5xl mx-auto px-10 py-12">

        {/* Page Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-headline font-bold text-on-surface tracking-tight">Developer Profile</h1>
          <p className="text-on-surface-variant font-body mt-1">The architect behind ReconScience.</p>
        </div>

        {/* Terminal Window */}
        <div className="bg-surface-container-lowest border border-outline-variant/10 rounded-2xl overflow-hidden shadow-2xl">

          {/* Terminal Header */}
          <div className="bg-surface-container-high border-b border-outline-variant/10 px-6 py-3 flex items-center justify-between">
            <div className="flex space-x-2">
              <div className="w-3 h-3 rounded-full bg-error/60"></div>
              <div className="w-3 h-3 rounded-full bg-tertiary/60"></div>
              <div className="w-3 h-3 rounded-full bg-emerald-500/60"></div>
            </div>
            <div className="text-[10px] font-headline text-on-surface-variant uppercase tracking-widest">
              root@reconscience:~
            </div>
            <div className="w-4 h-4"></div>
          </div>

          {/* Terminal Body */}
          <div className="p-8 font-body">
            <div className="flex flex-col md:flex-row gap-8 items-start">

              {/* Avatar */}
              <div className="w-32 h-32 border-2 border-primary/30 rounded-xl p-1 flex-shrink-0 relative group cursor-pointer transition-all hover:border-primary/60 hover:shadow-[0_0_20px_rgba(224,182,255,0.15)] overflow-hidden">
                <div className="w-full h-full bg-primary-container rounded-lg flex items-center justify-center">
                  <span
                    className="material-symbols-outlined text-on-primary-container text-4xl"
                    style={{ fontVariationSettings: "'FILL' 1" }}
                  >
                    person
                  </span>
                </div>
              </div>

              <div className="space-y-6 flex-1">
                <div>
                  <h1 className="text-2xl font-headline font-bold text-primary">Md Didarul Alam Alif</h1>
                  <h2 className="text-on-surface-variant text-sm font-body mt-1">
                    Creator & Lead Architect, ReconScience
                  </h2>
                  <div className="flex items-center gap-3 mt-3">
                    <a
                      href="https://didarulalamalif.great-site.net"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 px-3 py-1 bg-primary/10 border border-primary/20 rounded-lg text-primary text-xs font-headline font-medium hover:bg-primary/20 transition-all"
                    >
                      <span className="material-symbols-outlined text-xs">language</span>
                      Portfolio
                    </a>
                    <a
                      href="https://github.com/DidarAlif"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 px-3 py-1 bg-surface-container-high border border-outline-variant/20 rounded-lg text-on-surface-variant text-xs font-headline font-medium hover:border-primary/40 hover:text-primary transition-all"
                    >
                      <span className="material-symbols-outlined text-xs">code</span>
                      GitHub
                    </a>
                  </div>
                </div>

                {/* whoami */}
                <div className="space-y-5 text-sm text-on-surface-variant font-body">
                  <div>
                    <p className="text-primary font-mono text-xs mb-1">
                      <span className="text-primary/60">$</span> whoami
                    </p>
                    <p className="leading-relaxed">
                      Security engineer and full-stack developer with strong communication skills developed through international corporate exposure. Passionate about building tools that automate offensive security workflows and bridge the gap between complex CLI tooling and modern web interfaces.
                    </p>
                  </div>

                  {/* Vision */}
                  <div>
                    <p className="text-primary font-mono text-xs mb-1">
                      <span className="text-primary/60">$</span> cat /vision.txt
                    </p>
                    <p className="leading-relaxed">
                      ReconScience was built to democratize vulnerability assessment. By combining FastAPI, React/Next.js, and the Nuclei scanning engine, it makes enterprise-grade reconnaissance as simple as entering a URL — while preserving the raw, detailed output that security professionals demand.
                    </p>
                  </div>

                  {/* Education */}
                  <div>
                    <p className="text-primary font-mono text-xs mb-2">
                      <span className="text-primary/60">$</span> cat /etc/education.conf
                    </p>
                    <div className="bg-surface-container rounded-lg p-4 font-mono text-xs text-on-surface-variant space-y-2">
                      <p className="flex items-start gap-3">
                        <span className="text-primary mt-0.5">📎</span>
                        <span>
                          <span className="text-on-surface font-medium">Computer Science & Engineering</span><br />
                          <span className="text-slate-500">Focused on cybersecurity, networking, and full-stack web development</span>
                        </span>
                      </p>
                    </div>
                  </div>

                  {/* Skills */}
                  <div>
                    <p className="text-primary font-mono text-xs mb-2">
                      <span className="text-primary/60">$</span> ls -la skills/
                    </p>
                    <div className="bg-surface-container rounded-lg p-4 font-mono text-xs text-on-surface-variant space-y-1">
                      <p className="flex items-center gap-3">
                        <span className="text-primary">drwxr-xr-x</span>
                        <span>Web Application Security & Pentesting</span>
                      </p>
                      <p className="flex items-center gap-3">
                        <span className="text-primary">drwxr-xr-x</span>
                        <span>Network Security & Infrastructure Hardening</span>
                      </p>
                      <p className="flex items-center gap-3">
                        <span className="text-primary">drwxr-xr-x</span>
                        <span>Full-Stack Development (Next.js, React, FastAPI, Node.js)</span>
                      </p>
                      <p className="flex items-center gap-3">
                        <span className="text-primary">drwxr-xr-x</span>
                        <span>Cloud Architecture & DevOps (Docker, CI/CD, Linux)</span>
                      </p>
                      <p className="flex items-center gap-3">
                        <span className="text-primary">drwxr-xr-x</span>
                        <span>Backend API Design & Database Management</span>
                      </p>
                      <p className="flex items-center gap-3">
                        <span className="text-primary">drwxr-xr-x</span>
                        <span>Python, TypeScript, Go, SQL</span>
                      </p>
                    </div>
                  </div>

                  {/* Tech Stack used in ReconScience */}
                  <div>
                    <p className="text-primary font-mono text-xs mb-2">
                      <span className="text-primary/60">$</span> cat reconscience/stack.yml
                    </p>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="bg-surface-container rounded-lg p-3 border border-outline-variant/10 hover:border-primary/30 transition-all">
                        <div className="text-[9px] text-slate-500 uppercase font-headline tracking-wider mb-1">Frontend</div>
                        <div className="text-xs text-on-surface font-medium space-y-0.5">
                          <p>Next.js 16 / React 19</p>
                          <p>Tailwind CSS v4</p>
                          <p>TypeScript</p>
                        </div>
                      </div>
                      <div className="bg-surface-container rounded-lg p-3 border border-outline-variant/10 hover:border-primary/30 transition-all">
                        <div className="text-[9px] text-slate-500 uppercase font-headline tracking-wider mb-1">Backend</div>
                        <div className="text-xs text-on-surface font-medium space-y-0.5">
                          <p>Python 3.11 / FastAPI</p>
                          <p>SQLAlchemy ORM</p>
                          <p>JWT + SSE Streaming</p>
                        </div>
                      </div>
                      <div className="bg-surface-container rounded-lg p-3 border border-outline-variant/10 hover:border-primary/30 transition-all">
                        <div className="text-[9px] text-slate-500 uppercase font-headline tracking-wider mb-1">Security Engine</div>
                        <div className="text-xs text-on-surface font-medium space-y-0.5">
                          <p>Nuclei Scanner (Go)</p>
                          <p>Subfinder</p>
                          <p>Custom YAML Templates</p>
                        </div>
                      </div>
                      <div className="bg-surface-container rounded-lg p-3 border border-outline-variant/10 hover:border-primary/30 transition-all">
                        <div className="text-[9px] text-slate-500 uppercase font-headline tracking-wider mb-1">Infrastructure</div>
                        <div className="text-xs text-on-surface font-medium space-y-0.5">
                          <p>Docker / Render / Vercel</p>
                          <p>Railway Deployment</p>
                          <p>GitHub CI/CD</p>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Contact / Links  */}
                  <div>
                    <p className="text-primary font-mono text-xs mb-2">
                      <span className="text-primary/60">$</span> cat /contact.md
                    </p>
                    <div className="bg-surface-container rounded-lg p-4 font-mono text-xs text-on-surface-variant space-y-2">
                      <p className="flex items-center gap-3">
                        <span className="material-symbols-outlined text-primary text-xs">language</span>
                        <a href="https://didarulalamalif.great-site.net" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
                          didarulalamalif.great-site.net
                        </a>
                      </p>
                      <p className="flex items-center gap-3">
                        <span className="material-symbols-outlined text-primary text-xs">code</span>
                        <a href="https://github.com/DidarAlif" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
                          github.com/DidarAlif
                        </a>
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-outline-variant/10">
              <p className="text-primary font-mono text-xs animate-pulse">_ BLINKING CURSOR</p>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="mt-8 text-center">
          <p className="text-slate-600 text-xs font-headline tracking-widest uppercase">
            Built with 💜 by Alif — © 2026
          </p>
        </div>
      </div>
    </AuthenticatedLayout>
  );
}
