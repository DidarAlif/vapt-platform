import React from "react";
import Image from "next/image";

export default function DeveloperPage() {
  return (
    <div className="min-h-screen bg-[#050505] text-[#e5e5e5] cyber-grid py-12 px-6">
      <div className="max-w-4xl mx-auto">
        
        {/* Terminal Window Frame */}
        <div className="border border-gray-700 bg-[#0a0a0f] shadow-[0_0_20px_rgba(0,0,0,0.8)] mt-10">
          
          {/* Terminal Header */}
          <div className="bg-gray-900 border-b border-gray-700 px-4 py-2 flex items-center justify-between">
            <div className="flex space-x-2">
              <div className="w-3 h-3 rounded-full bg-red-500"></div>
              <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
              <div className="w-3 h-3 rounded-full bg-green-500"></div>
            </div>
            <div className="text-xs font-mono text-gray-400">root@reconscience:~</div>
            <div className="w-4 h-4"></div> {/* spacer */}
          </div>

          {/* Terminal Body */}
          <div className="p-8 font-mono">
            <div className="flex flex-col md:flex-row gap-8 items-start">
              
              {/* Avatar placeholder or logo */}
              <div className="w-32 h-32 border-2 border-[#00d4aa] p-1 flex-shrink-0 relative group cursor-pointer transition-all hover:shadow-[0_0_15px_rgba(0,212,170,0.5)]">
                <Image src="/logo.png" alt="Developer" fill className="object-cover" />
                <div className="absolute inset-0 bg-[#00d4aa]/10 group-hover:bg-transparent transition-all"></div>
              </div>

              <div className="space-y-6">
                <div>
                  <h1 className="text-2xl text-[#00ff41] font-bold">Alif</h1>
                  <h2 className="text-gray-400 text-sm mt-1">Creator & Lead Architect, ReconScience</h2>
                </div>

                <div className="space-y-4 text-sm text-gray-300">
                  <p>
                    <span className="text-[#00d4aa]">{">"} whoami</span><br />
                    I am a security engineer and full-stack developer passionate about building tools that automate the tedious parts of offensive security.
                  </p>
                  
                  <p>
                    <span className="text-[#00d4aa]">{">"} cat /vision.txt</span><br />
                    The vision for ReconScience was to bridge the gap between complex command-line hacking tools and modern, accessible web interfaces. By combining FastAPI, React, and Nuclei, the goal was to make vulnerability sweeping as easy as clicking a button without sacrificing the raw output developers need.
                  </p>
                  
                  <p>
                    <span className="text-[#00d4aa]">{">"} ls -la skills/</span><br />
                    <span className="text-gray-500">
                    drwxr-xr-x  Web Application Security<br/>
                    drwxr-xr-x  Network Penetration Testing<br/>
                    drwxr-xr-x  Full-Stack Cloud Architecture<br/>
                    drwxr-xr-x  Backend API Design
                    </span>
                  </p>
                </div>
              </div>
            </div>
          </div>

        </div>

      </div>
    </div>
  );
}
