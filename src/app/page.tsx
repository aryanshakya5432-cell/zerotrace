"use client";

import {
  Activity,
  CircleSlash,
  Code2,
  FileSearch,
  Gauge,
  Globe2,
  HardDrive,
  Radar,
  ShieldCheck,
  Terminal,
  Timer,
  Zap,
} from "lucide-react";
import { useCallback, useRef, useState } from "react";

import { OmniScanner } from "@/components/omni-scanner";
import { PipelineSection } from "@/components/pipeline-section";
import {
  ErrorBento,
  ResultsBento,
  ScanningBento,
} from "@/components/results-bento";
import { buildFileSlice } from "@/lib/file-slice";
import type { FileSlicePayload, ScanResult } from "@/lib/types";

const DEMO_PAYLOAD: FileSlicePayload = {
  name: "SBI_Account_Statement_2026.pdf.exe",
  size: 53583,
  mimeType: "application/x-msdownload",
  sha256:
    "B770F89F0919DDC0A535BB6A3C1BDF5003ECE95F54A5CC593AA9D54DF5619193",
  headerHex: "4D5A0D0A54686973",
  strings:
    "MZ This program cannot be run in DOS mode. SBI Account Statement 2026 - secure viewer bootstrap VirtualAlloc WriteProcessMemory CreateRemoteThread powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA NtUnmapViewOfSection QueueUserAPC LoadLibraryA GetProcAddress This sample is synthetic and harmless. ZeroTrace demo only.",
  entropy: 7.68,
  sampledBytes: 53583,
  truncated: false,
};

const MIN_SCAN_MS = 750;

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export default function Home() {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTarget, setActiveTarget] = useState("");
  const resultsRef = useRef<HTMLDivElement>(null);

  const revealResults = useCallback(() => {
    requestAnimationFrame(() => {
      resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }, []);

  const postScan = useCallback(
    async (endpoint: "/api/scan-url" | "/api/scan-file", body: unknown) => {
      const started = Date.now();
      setLoading(true);
      setError(null);
      setResult(null);

      try {
        const response = await fetch(endpoint, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        });

        const payload = (await response.json()) as ScanResult | { error?: string };

        if (!response.ok) {
          throw new Error(
            "error" in payload && payload.error
              ? payload.error
              : `The scanner returned HTTP ${response.status}.`,
          );
        }

        const elapsed = Date.now() - started;
        if (elapsed < MIN_SCAN_MS) await wait(MIN_SCAN_MS - elapsed);

        setResult(payload as ScanResult);
        revealResults();
      } catch (caught) {
        setError(
          caught instanceof Error
            ? caught.message
            : "Unexpected error while contacting the scan engine.",
        );
      } finally {
        setLoading(false);
      }
    },
    [revealResults],
  );

  const scanUrl = useCallback(
    (url: string) => {
      setActiveTarget(url);
      void postScan("/api/scan-url", { url });
    },
    [postScan],
  );

  const scanFile = useCallback(
    async (file: File) => {
      setActiveTarget(file.name);
      setLoading(true);
      setError(null);
      setResult(null);

      try {
        const slice = await buildFileSlice(file);
        await postScan("/api/scan-file", slice);
      } catch (caught) {
        setLoading(false);
        setError(
          caught instanceof Error
            ? `Could not read that file: ${caught.message}`
            : "Could not read that file in the browser.",
        );
      }
    },
    [postScan],
  );

  const scanDemoPayload = useCallback(() => {
    setActiveTarget(DEMO_PAYLOAD.name);
    void postScan("/api/scan-file", DEMO_PAYLOAD);
  }, [postScan]);

  return (
    <div className="flex min-h-screen flex-col">
      <SiteHeader />

      <main className="mx-auto w-full max-w-6xl flex-1 px-4 pb-20 sm:px-6">
        {/* Hero */}
        <section className="pt-10 sm:pt-14">
          <div className="flex flex-wrap items-center gap-2">
            <span className="zt-mono inline-flex items-center gap-2 rounded-full border border-emerald-400/25 bg-emerald-400/[0.07] px-3 py-1 text-[10px] tracking-[0.18em] text-emerald-300">
              <span className="zt-live-dot h-1.5 w-1.5 rounded-full bg-emerald-400" />
              SOC CONSOLE · ONLINE
            </span>
            <span className="zt-mono rounded-full border border-slate-700/70 bg-slate-900/60 px-3 py-1 text-[10px] tracking-[0.18em] text-slate-400">
              V2.0 · UNIFIED ENGINE
            </span>
          </div>

          <h1 className="mt-5 max-w-3xl text-4xl leading-[1.05] font-semibold tracking-tight text-slate-50 sm:text-5xl">
            Scan anything.{" "}
            <span className="bg-gradient-to-r from-emerald-300 via-cyan-300 to-rose-300 bg-clip-text text-transparent">
              Trust nothing.
            </span>
          </h1>
          <p className="mt-3 max-w-2xl text-[13.5px] leading-relaxed text-slate-400 sm:text-sm">
            One omni-scanner for suspicious links and hostile files. URLs get
            nine live checks plus TLS validation and two cloud threat feeds;
            payloads are hashed in your browser and triaged against magic
            bytes, entropy, injection APIs and signature databases.
          </p>

          <div className="mt-6 grid grid-cols-2 gap-2 sm:grid-cols-4">
            <HeroStat icon={Globe2} value="9" label="URL checks" />
            <HeroStat icon={FileSearch} value="9" label="File checks" />
            <HeroStat icon={Timer} value="3s" label="Socket ceiling" />
            <HeroStat icon={HardDrive} value="0 B" label="Raw file uploaded" />
          </div>
        </section>

        {/* Scanner */}
        <div className="mt-6">
          <OmniScanner
            loading={loading}
            onScanUrl={scanUrl}
            onScanFile={(file) => void scanFile(file)}
            onDemoPayload={scanDemoPayload}
          />
        </div>

        {/* Results */}
        <div ref={resultsRef} className="mt-4 scroll-mt-24">
          {loading ? (
            <ScanningBento target={activeTarget} />
          ) : error ? (
            <ErrorBento message={error} />
          ) : result ? (
            <ResultsBento result={result} />
          ) : (
            <IdlePanel />
          )}
        </div>

        <PipelineSection />
      </main>

      <SiteFooter />
    </div>
  );
}

function SiteHeader() {
  return (
    <header className="sticky top-0 z-40 border-b border-slate-800/70 bg-slate-950/80 backdrop-blur-xl">
      <div className="mx-auto flex w-full max-w-6xl items-center gap-3 px-4 py-3 sm:px-6">
        <a href="#top" className="flex items-center gap-2.5">
          <span className="relative flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-emerald-400 to-cyan-500 shadow-[0_0_24px_-6px_rgb(16_185_129_/_0.8)]">
            <ShieldCheck className="h-5 w-5 text-slate-950" strokeWidth={2.5} />
          </span>
          <span className="leading-none">
            <span className="flex items-baseline gap-1.5">
              <span className="text-[15px] font-semibold tracking-tight text-slate-50">
                ZeroTrace
              </span>
              <span className="zt-mono rounded border border-slate-700/70 bg-slate-900/70 px-1 py-0.5 text-[8.5px] tracking-[0.16em] text-slate-400">
                SOC
              </span>
            </span>
            <span className="zt-mono mt-1 block text-[9px] tracking-[0.22em] text-slate-500">
              THREAT SCANNER
            </span>
          </span>
        </a>

        <nav className="zt-mono ml-6 hidden items-center gap-5 text-[10.5px] tracking-[0.16em] text-slate-400 md:flex">
          <a href="#scanner" className="transition hover:text-emerald-300">
            SCANNER
          </a>
          <a href="#pipeline" className="transition hover:text-emerald-300">
            PIPELINE
          </a>
          <span className="inline-flex items-center gap-1 text-slate-600">
            <Terminal className="h-3 w-3" /> API /SCAN-URL · /SCAN-FILE
          </span>
        </nav>

        <div className="ml-auto flex items-center gap-2">
          <span className="zt-mono hidden items-center gap-1.5 rounded-full border border-emerald-400/20 bg-emerald-400/[0.06] px-2.5 py-1 text-[9.5px] tracking-[0.16em] text-emerald-300 sm:inline-flex">
            <span className="zt-live-dot h-1.5 w-1.5 rounded-full bg-emerald-400" />
            ENGINE ONLINE
          </span>
          <a
            href="https://github.com"
            target="_blank"
            rel="noreferrer"
            aria-label="ZeroTrace repository"
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-slate-800 bg-slate-900/60 text-slate-400 transition hover:border-emerald-400/40 hover:text-emerald-300"
          >
            <Code2 className="h-4 w-4" />
          </a>
        </div>
      </div>
    </header>
  );
}

function HeroStat({
  icon: Icon,
  value,
  label,
}: {
  icon: typeof Globe2;
  value: string;
  label: string;
}) {
  return (
    <div className="flex items-center gap-2.5 rounded-xl border border-slate-800/70 bg-slate-900/40 px-3 py-2.5">
      <Icon className="h-4 w-4 shrink-0 text-emerald-400/80" />
      <div className="min-w-0">
        <p className="zt-mono text-[13px] leading-none font-semibold text-slate-100">
          {value}
        </p>
        <p className="zt-mono mt-1 truncate text-[9px] tracking-[0.14em] text-slate-500 uppercase">
          {label}
        </p>
      </div>
    </div>
  );
}

function IdlePanel() {
  const notes = [
    {
      icon: Radar,
      title: "Awaiting target",
      body: "Drop a payload or paste a link above — or fire one of the three demo targets.",
    },
    {
      icon: Zap,
      title: "Instant verdict",
      body: "Weighted 0–100 risk score, threat classification and a full audited rule trail.",
    },
    {
      icon: CircleSlash,
      title: "Nothing uploaded",
      body: "Only a compact feature slice leaves the browser, so Vercel's 4.5 MB limit never applies.",
    },
  ];

  return (
    <div className="zt-panel grid gap-px overflow-hidden rounded-2xl sm:grid-cols-3">
      {notes.map((note) => (
        <div key={note.title} className="flex items-start gap-2.5 px-4 py-4">
          <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-slate-700/70 bg-slate-950/70">
            <note.icon className="h-3.5 w-3.5 text-slate-400" />
          </span>
          <div>
            <p className="text-[12px] font-medium text-slate-300">{note.title}</p>
            <p className="mt-0.5 text-[11px] leading-relaxed text-slate-500">
              {note.body}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}

function SiteFooter() {
  return (
    <footer className="border-t border-slate-800/70 bg-slate-950/70">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-3 px-4 py-8 sm:flex-row sm:items-center sm:justify-between sm:px-6">
        <div className="flex items-center gap-2.5">
          <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-gradient-to-br from-emerald-400 to-cyan-500">
            <ShieldCheck className="h-4 w-4 text-slate-950" strokeWidth={2.5} />
          </span>
          <div>
            <p className="text-[12px] font-medium text-slate-300">
              ZeroTrace — Unified URL &amp; Malware Threat Scanner
            </p>
            <p className="zt-mono mt-0.5 text-[9.5px] tracking-[0.14em] text-slate-600">
              HEURISTIC DEMO ENGINE · NOT A SANDBOX REPLACEMENT
            </p>
          </div>
        </div>

        <div className="zt-mono flex flex-wrap items-center gap-x-4 gap-y-1 text-[9.5px] tracking-[0.14em] text-slate-600">
          <span className="inline-flex items-center gap-1.5">
            <Activity className="h-3 w-3" /> NODE RUNTIME · MAX 10S
          </span>
          <span className="inline-flex items-center gap-1.5">
            <Gauge className="h-3 w-3" /> SHA-256 IN-BROWSER
          </span>
          <span className="inline-flex items-center gap-1.5">
            <ShieldCheck className="h-3 w-3" /> NO FILE STORAGE
          </span>
        </div>
      </div>
    </footer>
  );
}
