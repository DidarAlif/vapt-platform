"use client";

import { useRouter } from "next/navigation";
import { useState, useEffect } from "react";

export default function TopBar() {
  const router = useRouter();
  const [userName, setUserName] = useState("User");

  useEffect(() => {
    const userData = localStorage.getItem("user");
    if (userData) {
      try {
        const user = JSON.parse(userData);
        setUserName(user.name || user.email || "User");
      } catch {}
    }
  }, []);

  const handleLogout = () => {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    localStorage.removeItem("user");
    router.push("/login");
  };

  return (
    <header className="fixed top-0 right-0 left-0 flex justify-between items-center px-8 h-16 z-50 ml-64 bg-[#12131c]/80 backdrop-blur-xl border-b border-[#494455]/20 font-headline uppercase tracking-widest text-xs">
      <div className="flex items-center gap-4 flex-1">
        <div className="relative w-full max-w-md">
          <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 text-sm">
            search
          </span>
          <input
            className="bg-surface-container-low border-none rounded-lg pl-10 pr-4 py-2 w-full text-[10px] focus:ring-1 focus:ring-primary/40 placeholder:text-slate-600 text-on-surface outline-none"
            placeholder="Global system search..."
            type="text"
          />
        </div>
      </div>
      <div className="flex items-center gap-6">
        <div className="flex items-center gap-4">
          <span className="material-symbols-outlined text-slate-400 hover:text-[#fff6ff] cursor-pointer transition-colors">
            notifications
          </span>
          <span className="material-symbols-outlined text-slate-400 hover:text-[#fff6ff] cursor-pointer transition-colors">
            grid_view
          </span>
        </div>
        <div className="h-8 w-[1px] bg-outline-variant/20 mx-2"></div>
        <div className="flex items-center gap-3">
          <div className="text-right">
            <p className="text-[10px] font-bold text-on-surface">{userName}</p>
            <p className="text-[8px] text-slate-500">Tier 3 Access</p>
          </div>
          <button
            onClick={handleLogout}
            className="flex items-center gap-1.5 text-slate-400 hover:text-error transition-colors normal-case tracking-normal text-xs"
            title="Logout"
          >
            <span className="material-symbols-outlined text-lg">logout</span>
          </button>
        </div>
      </div>
    </header>
  );
}
