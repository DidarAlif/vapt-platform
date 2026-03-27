import React from "react";
import Link from "next/link";

export default function LearnPage() {
  return (
    <div className="min-h-screen bg-[#12131c] text-on-surface py-16 px-6">
      <div className="max-w-4xl mx-auto space-y-10">

        {/* Header */}
        <div className="relative">
          <div className="absolute left-0 top-0 w-1.5 h-full bg-primary rounded-r-full"></div>
          <div className="pl-6">
            <h1 className="text-3xl font-headline font-bold tracking-tight text-on-surface">
              Introduction to <span className="text-primary">Reconnaissance</span>
            </h1>
            <p className="text-on-surface-variant font-body mt-2 flex items-center gap-2 text-sm">
              <span className="inline-block w-2 h-2 bg-tertiary rounded-full animate-pulse"></span>
              Intelligence Gathering Phase — Step 1 of the Cyber Kill Chain
            </p>
          </div>
        </div>

        {/* What is Recon */}
        <section className="bg-surface-container-low border border-outline-variant/10 p-8 rounded-xl">
          <h2 className="text-lg font-headline font-bold text-primary uppercase tracking-widest mb-4 flex items-center gap-2">
            <span className="w-1.5 h-5 bg-primary rounded-full"></span>
            What is Reconnaissance?
          </h2>
          <p className="text-sm text-on-surface-variant font-body leading-relaxed mb-6">
            In cybersecurity, reconnaissance (or &quot;recon&quot;) is the first phase of an attack or a penetration test. It involves gathering as much information as possible about a target system before actually interacting with it maliciously. This can include finding subdomains, open ports, exposed APIs, employee emails, leaked credentials, and fingerprinting the exact technology stack the server is running.
          </p>
          <div className="grid md:grid-cols-2 gap-4">
            <div className="bg-surface-container border border-outline-variant/10 p-5 rounded-lg">
              <div className="flex items-center gap-2 mb-3">
                <span className="material-symbols-outlined text-primary text-sm">visibility</span>
                <h3 className="text-sm font-headline font-bold text-primary">Passive Recon</h3>
              </div>
              <p className="text-xs text-on-surface-variant font-body leading-relaxed">
                Gathering data without directly interacting with the target&apos;s servers. Examples: WHOIS lookups, searching public GitHub repos, using Shodan, or reading the target&apos;s public documentation.
              </p>
            </div>
            <div className="bg-surface-container border border-outline-variant/10 p-5 rounded-lg">
              <div className="flex items-center gap-2 mb-3">
                <span className="material-symbols-outlined text-error text-sm">gps_fixed</span>
                <h3 className="text-sm font-headline font-bold text-error">Active Recon</h3>
              </div>
              <p className="text-xs text-on-surface-variant font-body leading-relaxed">
                Directly probing the target systems. Examples: Port scanning with Nmap, directory fuzzing, or running ReconScience vulnerability scanners against the domain.
              </p>
            </div>
          </div>
        </section>

        {/* Why Important */}
        <section className="space-y-4">
          <h2 className="text-xl font-headline font-bold text-on-surface tracking-tight uppercase border-b border-outline-variant/10 pb-3">
            Why is it important?
          </h2>
          <div className="bg-surface-container border-l-4 border-primary/40 p-6 rounded-r-xl">
            <p className="text-sm text-on-surface-variant font-body leading-relaxed">
              <strong className="text-on-surface">Attackers spend 80% of their time on recon.</strong> A poorly configured <code className="text-primary bg-primary/10 px-1.5 py-0.5 rounded text-xs">.git</code> folder left on a production server or an unpatched WordPress plugin on a forgotten subdomain is all a hacker needs to compromise an entire corporate network. If you as a defender do not do reconnaissance on your own assets, the attackers will do it for you, and use your unknown weaknesses against you.
            </p>
          </div>
        </section>

        {/* How to Use */}
        <section className="bg-surface-container-low border border-outline-variant/10 p-8 rounded-xl relative overflow-hidden">
          <div className="absolute top-0 right-0 w-32 h-32 bg-primary/5 rounded-bl-[100px] pointer-events-none"></div>
          <h2 className="text-lg font-headline font-bold text-primary uppercase tracking-widest mb-6 flex items-center gap-2">
            <span className="w-1.5 h-5 bg-primary rounded-full"></span>
            How to use ReconScience
          </h2>
          <div className="space-y-4">
            <div className="flex gap-4 items-start">
              <span className="w-6 h-6 flex-shrink-0 flex items-center justify-center rounded bg-primary-container text-[10px] font-bold text-on-primary-container mt-0.5">01</span>
              <div>
                <h3 className="text-sm font-headline font-bold text-on-surface mb-1">Map the Attack Surface</h3>
                <p className="text-xs text-on-surface-variant font-body">Enter your domain in the unified scanner. It maps technologies and exposed endpoints.</p>
              </div>
            </div>
            <div className="flex gap-4 items-start">
              <span className="w-6 h-6 flex-shrink-0 flex items-center justify-center rounded bg-primary-container text-[10px] font-bold text-on-primary-container mt-0.5">02</span>
              <div>
                <h3 className="text-sm font-headline font-bold text-on-surface mb-1">Identify Weaknesses</h3>
                <p className="text-xs text-on-surface-variant font-body">The scanner cross-references the tech stack against thousands of known CVEs.</p>
              </div>
            </div>
            <div className="flex gap-4 items-start">
              <span className="w-6 h-6 flex-shrink-0 flex items-center justify-center rounded bg-primary-container text-[10px] font-bold text-on-primary-container mt-0.5">03</span>
              <div>
                <h3 className="text-sm font-headline font-bold text-on-surface mb-1">Review & Remediate</h3>
                <p className="text-xs text-on-surface-variant font-body">Analyze the generated report. Fix critical and high severities immediately by patching software or updating server configurations.</p>
              </div>
            </div>
          </div>
          <div className="mt-8">
            <Link
              href="/scan"
              className="inline-flex items-center gap-2 bg-primary-container text-on-primary-container px-6 py-3 rounded-xl font-headline font-bold active:scale-95 transition-transform"
            >
              <span className="material-symbols-outlined">rocket_launch</span>
              Start Scanning
            </Link>
          </div>
        </section>
      </div>
    </div>
  );
}
