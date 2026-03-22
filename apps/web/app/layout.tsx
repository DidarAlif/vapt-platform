import type { Metadata } from "next";
import "./globals.css";

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
      <body className="antialiased bg-[#0a0a0f]">
        {children}
      </body>
    </html>
  );
}
