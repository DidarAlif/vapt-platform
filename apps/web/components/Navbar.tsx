"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import Image from "next/image";
import { useState, useEffect } from "react";

export default function Navbar() {
  const pathname = usePathname();
  const router = useRouter();
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    // Check auth status on mount
    const token = localStorage.getItem("access_token");
    setIsAuthenticated(!!token);

    // Simple storage event listener in case other tabs login/logout
    window.addEventListener("storage", () => {
      setIsAuthenticated(!!localStorage.getItem("access_token"));
    });
  }, [pathname]);

  const handleLogout = () => {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    localStorage.removeItem("user");
    setIsAuthenticated(false);
    router.push("/login");
  };

  const navLinks = [
    { name: "Scan", href: "/scan", requiresAuth: true },
    { name: "History", href: "/history", requiresAuth: true },
    { name: "About", href: "/about", requiresAuth: false },
    { name: "Developer", href: "/developer", requiresAuth: false },
    { name: "Learn", href: "/learn", requiresAuth: false },
    { name: "Safety", href: "/safety", requiresAuth: false },
  ];

  // Don't show navbar on login/register/verify pages to keep them focused
  if (pathname === "/login" || pathname === "/register" || pathname === "/verify-email") {
    return null;
  }

  return (
    <nav className="border-b border-[#00d4aa]/30 bg-[#050505]/90 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-6">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center gap-3">
            <Link href="/" className="flex items-center gap-3">
              <div className="w-8 h-8 relative">
                <Image src="/logo.png" alt="RS" fill className="object-contain" priority />
              </div>
              <div>
                <h1 className="text-lg font-bold text-[#00d4aa] tracking-wider uppercase">ReconScience</h1>
              </div>
            </Link>
          </div>

          <div className="hidden md:flex flex-1 justify-center items-center gap-8">
            {navLinks.map((link) => {
              if (link.requiresAuth && !isAuthenticated) return null;
              
              const isActive = pathname === link.href;
              return (
                <Link
                  key={link.name}
                  href={link.href}
                  className={`text-sm font-mono uppercase tracking-widest transition-all ${
                    isActive
                      ? "text-[#00d4aa] drop-shadow-[0_0_8px_rgba(0,212,170,0.8)]"
                      : "text-gray-500 hover:text-[#00ff41] hover:drop-shadow-[0_0_5px_rgba(0,255,65,0.5)]"
                  }`}
                >
                  {link.name}
                </Link>
              );
            })}
          </div>

          <div className="flex items-center gap-4">
            {isAuthenticated ? (
              <button
                onClick={handleLogout}
                className="text-xs font-mono uppercase text-red-500 hover:text-red-400 hover:drop-shadow-[0_0_5px_rgba(239,68,68,0.5)] transition-all"
              >
                Logout
              </button>
            ) : (
              <Link
                href="/login"
                className="px-4 py-1.5 border border-[#00d4aa]/50 text-[#00d4aa] text-xs font-mono uppercase tracking-wider hover:bg-[#00d4aa]/10 hover:shadow-[0_0_15px_rgba(0,212,170,0.3)] transition-all"
              >
                Sign In
              </Link>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
}
