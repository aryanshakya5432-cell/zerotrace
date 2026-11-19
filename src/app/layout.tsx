import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "ZeroTrace — Unified URL & Malware Threat Scanner",
  description:
    "One omni-scanner for URLs and files. Browser-side hashing, live DNS/TLS probes and a 0–100 risk verdict in a bento SOC console.",
  applicationName: "ZeroTrace",
  keywords: [
    "cybersecurity",
    "malware scanner",
    "URL scanner",
    "threat intelligence",
    "SOC",
  ],
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full bg-slate-950 text-slate-200">
        <div className="zt-backdrop" aria-hidden />
        <div className="zt-noise" aria-hidden />
        {children}
      </body>
    </html>
  );
}
