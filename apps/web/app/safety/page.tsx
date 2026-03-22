import React from "react";

export default function SafetyPage() {
  return (
    <div className="min-h-screen bg-[#050505] text-[#e5e5e5] cyber-grid py-12 px-6">
      <div className="max-w-4xl mx-auto">
        
        <div className="text-center mb-16">
          <div className="inline-flex items-center justify-center p-4 bg-red-500/10 rounded-full mb-4 border border-red-500/30">
            <svg className="w-12 h-12 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <h1 className="text-4xl font-mono text-white tracking-widest uppercase">Safety & Ethics</h1>
          <p className="text-gray-500 font-mono mt-3 max-w-2xl mx-auto text-sm">
            Rules of Engagement for using the ReconScience platform.
          </p>
        </div>

        <div className="space-y-8">
          
          <div className="bg-[#0a0a0f] border-l-4 border-red-500 p-6 relative overflow-hidden group hover:bg-[#0a0a0f]/80 transition-all">
            <div className="absolute right-0 top-0 text-9xl text-red-500/[0.03] font-bold select-none group-hover:text-red-500/[0.05] transition-all">01</div>
            <h2 className="text-xl font-mono text-red-400 uppercase tracking-wider mb-2 relative z-10">Explicit Authorization Required</h2>
            <p className="text-sm font-mono text-gray-400 leading-relaxed relative z-10">
              You may ONLY run scans against domains, IP addresses, or infrastructure that you explicitly own, operate, or have written authorization to test. Attempting to scan third-party networks without permission is illegal and a violation of our Terms of Service.
            </p>
          </div>

          <div className="bg-[#0a0a0f] border-l-4 border-yellow-500 p-6 relative overflow-hidden group hover:bg-[#0a0a0f]/80 transition-all">
             <div className="absolute right-0 top-0 text-9xl text-yellow-500/[0.03] font-bold select-none group-hover:text-yellow-500/[0.05] transition-all">02</div>
            <h2 className="text-xl font-mono text-yellow-400 uppercase tracking-wider mb-2 relative z-10">Do No Harm</h2>
            <p className="text-sm font-mono text-gray-400 leading-relaxed relative z-10">
              While our scanners are designed to be non-destructive, active reconnaissance can occasionally trigger Intrusion Detection Systems (IDS), Web Application Firewalls (WAF), or cause unintended load on fragile systems. You are responsible for any downtime or damage caused to the target environment.
            </p>
          </div>

          <div className="bg-[#0a0a0f] border-l-4 border-[#00d4aa] p-6 relative overflow-hidden group hover:bg-[#0a0a0f]/80 transition-all">
             <div className="absolute right-0 top-0 text-9xl text-[#00d4aa]/[0.03] font-bold select-none group-hover:text-[#00d4aa]/[0.05] transition-all">03</div>
            <h2 className="text-xl font-mono text-[#00d4aa] uppercase tracking-wider mb-2 relative z-10">Ethical Disclosure</h2>
            <p className="text-sm font-mono text-gray-400 leading-relaxed relative z-10">
              If you discover a vulnerability in a system you were authorized to test, it must be reported responsibly to the system owners. Do not exploit vulnerabilities further than necessary to prove their existence, and never exfiltrate sensitive data.
            </p>
          </div>

        </div>

      </div>
    </div>
  );
}
