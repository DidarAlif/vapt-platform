import type { Metadata } from "next";
import "./globals.css";
import Navbar from "../components/Navbar";

export const metadata: Metadata = {
  title: "ReconScience - Security Reconnaissance Platform",
  description: "Advanced vulnerability assessment and penetration testing platform powered by Nuclei",
  icons: {
    icon: "/logo.png",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased bg-[#050505] text-[#e5e5e5] cyber-grid selection:bg-[#00d4aa] selection:text-black">
        <Navbar />
        {children}
      </body>
    </html>
  );
}
