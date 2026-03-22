import React from "react";
import Link from "next/link";

export default function LearnPage() {
  return (
    <div className="min-h-screen bg-[#050505] text-[#e5e5e5] cyber-grid py-12 px-6">
      <div className="max-w-4xl mx-auto space-y-10">
        
        <div className="border-l-4 border-[#00d4aa] pl-6 py-2">
          <h1 className="text-4xl font-mono font-bold tracking-tight uppercase text-white">Introduction to <span className="text-[#00d4aa]">Reconnaissance</span></h1>
          <p className="text-gray-500 font-mono mt-2 flex items-center gap-2">
            <span className="inline-block w-2 h-2 bg-yellow-500 rounded-full animate-pulse"></span>
            Intelligence Gathering Phase // Step 1 of the Cyber Kill Chain
          </p>
        </div>

        <section className="bg-[#0a0a0f] border border-gray-800 p-6 shadow-lg">
          <h2 className="text-xl font-mono text-[#00ff41] mb-4 uppercase">What is Reconnaissance?</h2>
          <p className="text-sm font-mono text-gray-400 leading-relaxed mb-4">
            In cybersecurity, reconnaissance (or "recon") is the first phase of an attack or a penetration test. It involves gathering as much information as possible about a target system before actually interacting with it maliciously. This can include finding subdomains, open ports, exposed APIs, employee emails, leaked credentials, and fingerprinting the exact technology stack the server is running.
          </p>
          <div className="grid md:grid-cols-2 gap-4 mt-6">
            <div className="border border-gray-700/50 p-4">
              <h3 className="text-[#00d4aa] font-mono text-sm mb-2">Passive Recon</h3>
              <p className="text-xs text-gray-500 font-mono">Gathering data without directly interacting with the target's servers. Examples: WHOIS lookups, searching public GitHub repos, using Shodan, or reading the target's public documentation.</p>
            </div>
            <div className="border border-gray-700/50 p-4">
              <h3 className="text-red-400 font-mono text-sm mb-2">Active Recon</h3>
              <p className="text-xs text-gray-500 font-mono">Directly probing the target systems. Examples: Port scanning with Nmap, directory fuzzing, or running ReconScience vulnerability scanners against the domain.</p>
            </div>
          </div>
        </section>

        <section className="space-y-4">
          <h2 className="text-2xl font-mono text-white tracking-widest uppercase border-b border-gray-800 pb-2">Why is it important?</h2>
          <div className="bg-[#12121a] border-l-2 border-[#00d4aa] p-4">
            <p className="text-sm font-mono text-gray-400 leading-relaxed">
              <strong className="text-white">Attackers spend 80% of their time on recon.</strong> A poorly configured `.git` folder left on a production server or an unpatched WordPress plugin on a forgotten subdomain is all a hacker needs to compromise an entire corporate network. If you as a defender do not do reconnaissance on your own assets, the attackers will do it for you, and use your unknown weaknesses against you.
            </p>
          </div>
        </section>

        <section className="bg-[#0a0a0f] border border-gray-800 p-6 relative overflow-hidden">
          <div className="absolute top-0 right-0 w-32 h-32 bg-[#00d4aa]/5 rounded-bl-[100px] pointer-events-none"></div>
          <h2 className="text-xl font-mono text-[#00d4aa] mb-4 uppercase">How to use ReconScience for Recon</h2>
          <ul className="text-sm font-mono text-gray-400 space-y-3 list-none">
            <li className="flex gap-3">
              <span className="text-[#00d4aa]">{">"}</span>
              <span><strong>Map the Attack Surface:</strong> Enter your domain in the unified scanner. It maps technologies and exposed endpoints.</span>
            </li>
            <li className="flex gap-3">
              <span className="text-[#00d4aa]">{">"}</span>
              <span><strong>Identify Weaknesses:</strong> The scanner cross-references the tech stack against thousands of known CVEs.</span>
            </li>
            <li className="flex gap-3">
              <span className="text-[#00d4aa]">{">"}</span>
              <span><strong>Review & Remediate:</strong> Analyze the generated report. Fix critical and high severities immediately by patching software or updating server configurations.</span>
            </li>
          </ul>
          <div className="mt-8">
            <Link href="/scan" className="inline-block px-6 py-2 border border-[#00d4aa] text-[#00d4aa] font-mono text-sm hover:bg-[#00d4aa]/10 transition-colors uppercase tracking-wider">
              Start Scanning
            </Link>
          </div>
        </section>

      </div>
    </div>
  );
}
