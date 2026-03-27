import React from "react";

export default function DeveloperPage() {
  return (
    <div className="min-h-screen bg-[#12131c] text-on-surface py-16 px-6">
      <div className="max-w-4xl mx-auto">

        {/* Terminal Window */}
        <div className="bg-surface-container-lowest border border-outline-variant/10 rounded-2xl overflow-hidden shadow-2xl mt-10">

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
                  <h1 className="text-2xl font-headline font-bold text-primary">Alif</h1>
                  <h2 className="text-on-surface-variant text-sm font-body mt-1">
                    Creator & Lead Architect, ReconScience
                  </h2>
                </div>

                <div className="space-y-5 text-sm text-on-surface-variant font-body">
                  <div>
                    <p className="text-primary font-mono text-xs mb-1">
                      <span className="text-primary/60">$</span> whoami
                    </p>
                    <p className="leading-relaxed">
                      I am a security engineer and full-stack developer passionate about building tools that automate the tedious parts of offensive security.
                    </p>
                  </div>

                  <div>
                    <p className="text-primary font-mono text-xs mb-1">
                      <span className="text-primary/60">$</span> cat /vision.txt
                    </p>
                    <p className="leading-relaxed">
                      The vision for ReconScience was to bridge the gap between complex command-line hacking tools and modern, accessible web interfaces. By combining FastAPI, React, and Nuclei, the goal was to make vulnerability sweeping as easy as clicking a button without sacrificing the raw output developers need.
                    </p>
                  </div>

                  <div>
                    <p className="text-primary font-mono text-xs mb-2">
                      <span className="text-primary/60">$</span> ls -la skills/
                    </p>
                    <div className="bg-surface-container rounded-lg p-4 font-mono text-xs text-on-surface-variant space-y-1">
                      <p className="flex items-center gap-3">
                        <span className="text-primary">drwxr-xr-x</span>
                        <span>Web Application Security</span>
                      </p>
                      <p className="flex items-center gap-3">
                        <span className="text-primary">drwxr-xr-x</span>
                        <span>Network Penetration Testing</span>
                      </p>
                      <p className="flex items-center gap-3">
                        <span className="text-primary">drwxr-xr-x</span>
                        <span>Full-Stack Cloud Architecture</span>
                      </p>
                      <p className="flex items-center gap-3">
                        <span className="text-primary">drwxr-xr-x</span>
                        <span>Backend API Design</span>
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
      </div>
    </div>
  );
}
