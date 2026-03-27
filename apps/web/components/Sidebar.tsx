"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const navLinks = [
  { name: "Dashboard", href: "/scan", icon: "dashboard" },
  { name: "New Scan", href: "/scan", icon: "radar" },
  { name: "Scan History", href: "/history", icon: "history" },
  { name: "Reports", href: "/history", icon: "assessment" },
];

const systemLinks = [
  { name: "About", href: "/about", icon: "info" },
  { name: "Learn", href: "/learn", icon: "school" },
  { name: "Safety", href: "/safety", icon: "shield" },
  { name: "Developer", href: "/developer", icon: "code" },
];

export default function Sidebar() {
  const pathname = usePathname();

  const isActive = (href: string, name: string) => {
    if (name === "Dashboard" && pathname === "/scan") return true;
    if (name === "Scan History" && pathname === "/history") return true;
    if (name === "Reports" && pathname === "/history") return false; // avoid double highlight
    if (name === "New Scan") return false; // Dashboard takes priority
    return pathname === href;
  };

  return (
    <aside className="fixed left-0 top-0 h-full flex flex-col z-40 w-64 bg-[#1a1b24]">
      <div className="p-6 flex items-center gap-3">
        <div className="w-8 h-8 bg-primary-container rounded flex items-center justify-center">
          <span
            className="material-symbols-outlined text-on-primary-container"
            style={{ fontVariationSettings: "'FILL' 1" }}
          >
            radar
          </span>
        </div>
        <div>
          <div className="text-xl font-bold tracking-widest text-[#e0b6ff] uppercase font-headline">
            RECONSCIENCE
          </div>
          <div className="text-[10px] text-slate-500 font-medium font-headline tracking-tight">
            Digital Curator v1.0
          </div>
        </div>
      </div>

      <nav className="flex-1 mt-4">
        {navLinks.map((link) => {
          const active = isActive(link.href, link.name);
          return (
            <Link
              key={link.name}
              href={link.href}
              className={`flex items-center gap-3 px-6 py-3 text-sm font-headline tracking-tight transition-colors duration-200 ${
                active
                  ? "text-[#e0b6ff] font-bold border-l-2 border-[#e0b6ff] bg-[#282933]"
                  : "text-slate-400 font-medium opacity-70 hover:bg-[#282933] hover:text-[#fff6ff]"
              }`}
            >
              <span
                className="material-symbols-outlined text-lg"
                style={active ? { fontVariationSettings: "'FILL' 1" } : undefined}
              >
                {link.icon}
              </span>
              <span>{link.name}</span>
            </Link>
          );
        })}

        <div className="mt-8 px-6 text-[10px] font-bold text-slate-600 uppercase tracking-[0.2em] font-headline">
          Resources
        </div>
        {systemLinks.map((link) => {
          const active = pathname === link.href;
          return (
            <Link
              key={link.name}
              href={link.href}
              className={`flex items-center gap-3 px-6 py-3 text-sm font-headline tracking-tight transition-colors duration-200 mt-0.5 ${
                active
                  ? "text-[#e0b6ff] font-bold border-l-2 border-[#e0b6ff] bg-[#282933]"
                  : "text-slate-400 font-medium opacity-70 hover:bg-[#282933] hover:text-[#fff6ff]"
              }`}
            >
              <span className="material-symbols-outlined text-lg">{link.icon}</span>
              <span>{link.name}</span>
            </Link>
          );
        })}
      </nav>

      <div className="p-6">
        <Link
          href="/scan"
          className="w-full bg-primary-container text-on-primary-container font-headline font-bold py-3 rounded-lg flex items-center justify-center gap-2 active:scale-95 transition-transform"
        >
          <span className="material-symbols-outlined">add_circle</span>
          Start New Scan
        </Link>
      </div>
    </aside>
  );
}
