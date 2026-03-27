"use client";

import Sidebar from "./Sidebar";
import TopBar from "./TopBar";

export default function AuthenticatedLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen bg-surface overflow-x-hidden">
      <Sidebar />
      <TopBar />
      <main className="ml-64 pt-16 min-h-screen">
        {children}
      </main>
    </div>
  );
}
