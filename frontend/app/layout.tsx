import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });

export const metadata: Metadata = {
  title: "CodeSentinel ML — AI Security Intelligence Platform",
  description: "ML-assisted secure code intelligence platform detecting insecure vibe coding practices using static analysis, attack surface analysis, and machine learning.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet" />
      </head>
      <body className={`${inter.variable} antialiased bg-[#020308] text-slate-100 overflow-x-hidden`}>
        {children}
      </body>
    </html>
  );
}
