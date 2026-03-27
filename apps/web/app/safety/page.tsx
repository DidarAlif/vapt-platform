"use client";

import React from "react";
import AuthenticatedLayout from "../../components/AuthenticatedLayout";

export default function SafetyPage() {
  return (
    <AuthenticatedLayout>
      <div className="max-w-5xl mx-auto px-10 py-12">

        {/* Header */}
        <div className="text-center mb-16">
          <div className="inline-flex items-center justify-center p-4 bg-error/10 rounded-2xl mb-4 border border-error/20">
            <span className="material-symbols-outlined text-error text-4xl">warning</span>
          </div>
          <h1 className="text-3xl font-headline font-bold text-on-surface tracking-tight uppercase">
            Safety & Ethics
          </h1>
          <p className="text-on-surface-variant font-body mt-3 max-w-2xl mx-auto text-sm">
            Rules of Engagement for using the ReconScience platform.
          </p>
        </div>

        <div className="space-y-6">

          {/* Rule 1 */}
          <div className="bg-surface-container-low border border-outline-variant/10 border-l-4 border-l-error p-6 rounded-r-xl relative overflow-hidden group hover:bg-surface-container transition-all">
            <div className="absolute right-4 top-2 text-8xl text-error/[0.04] font-headline font-black select-none group-hover:text-error/[0.07] transition-all">
              01
            </div>
            <div className="relative z-10">
              <div className="flex items-center gap-3 mb-3">
                <span className="material-symbols-outlined text-error">gavel</span>
                <h2 className="text-lg font-headline font-bold text-error uppercase tracking-wider">
                  Explicit Authorization Required
                </h2>
              </div>
              <p className="text-sm text-on-surface-variant font-body leading-relaxed">
                You may ONLY run scans against domains, IP addresses, or infrastructure that you explicitly own, operate, or have written authorization to test. Attempting to scan third-party networks without permission is illegal and a violation of our Terms of Service.
              </p>
            </div>
          </div>

          {/* Rule 2 */}
          <div className="bg-surface-container-low border border-outline-variant/10 border-l-4 border-l-tertiary p-6 rounded-r-xl relative overflow-hidden group hover:bg-surface-container transition-all">
            <div className="absolute right-4 top-2 text-8xl text-tertiary/[0.04] font-headline font-black select-none group-hover:text-tertiary/[0.07] transition-all">
              02
            </div>
            <div className="relative z-10">
              <div className="flex items-center gap-3 mb-3">
                <span className="material-symbols-outlined text-tertiary">healing</span>
                <h2 className="text-lg font-headline font-bold text-tertiary uppercase tracking-wider">
                  Do No Harm
                </h2>
              </div>
              <p className="text-sm text-on-surface-variant font-body leading-relaxed">
                While our scanners are designed to be non-destructive, active reconnaissance can occasionally trigger Intrusion Detection Systems (IDS), Web Application Firewalls (WAF), or cause unintended load on fragile systems. You are responsible for any downtime or damage caused to the target environment.
              </p>
            </div>
          </div>

          {/* Rule 3 */}
          <div className="bg-surface-container-low border border-outline-variant/10 border-l-4 border-l-primary p-6 rounded-r-xl relative overflow-hidden group hover:bg-surface-container transition-all">
            <div className="absolute right-4 top-2 text-8xl text-primary/[0.04] font-headline font-black select-none group-hover:text-primary/[0.07] transition-all">
              03
            </div>
            <div className="relative z-10">
              <div className="flex items-center gap-3 mb-3">
                <span className="material-symbols-outlined text-primary">handshake</span>
                <h2 className="text-lg font-headline font-bold text-primary uppercase tracking-wider">
                  Ethical Disclosure
                </h2>
              </div>
              <p className="text-sm text-on-surface-variant font-body leading-relaxed">
                If you discover a vulnerability in a system you were authorized to test, it must be reported responsibly to the system owners. Do not exploit vulnerabilities further than necessary to prove their existence, and never exfiltrate sensitive data.
              </p>
            </div>
          </div>

        </div>
      </div>
    </AuthenticatedLayout>
  );
}
