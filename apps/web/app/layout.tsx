import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "RECONSCIENCE — Digital Curator Dashboard",
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
    <html lang="en" className="dark">
      <head>
        <link
          href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=Manrope:wght@300;400;500;600;700&display=swap"
          rel="stylesheet"
        />
        <link
          href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="antialiased bg-[#12131c] text-[#e3e1ef]">
        {children}
      </body>
    </html>
  );
}
