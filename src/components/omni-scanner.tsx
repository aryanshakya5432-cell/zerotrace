"use client";

import {
  AtSign,
  Bug,
  FileArchive,
  FileCheck2,
  Globe2,
  Loader2,
  Lock,
  ScanLine,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  UploadCloud,
  X,
} from "lucide-react";
import { useId, useRef, useState, type ReactNode } from "react";

import { formatBytes } from "@/lib/file-slice";

export const SAFE_URL = "https://github.com";
export const PHISHING_URL =
  "http://192.168.1.5/sbi-kyc-verify@secure-login.xyz";

const ACCEPTED =
  ".exe,.dll,.scr,.apk,.pdf,.zip,.rar,.txt,.bin,.doc,.docx,.xls,.js,.msi,.elf,.so";

interface OmniScannerProps {
  loading: boolean;
  onScanUrl: (url: string) => void;
  onScanFile: (file: File) => void;
  onDemoPayload: () => void;
}

export function OmniScanner({
  loading,
  onScanUrl,
  onScanFile,
  onDemoPayload,
}: OmniScannerProps) {
  const [url, setUrl] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const inputId = useId();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const canScan = url.trim().length > 0 || file !== null;

  const stageFile = (next: File | null) => {
    setFile(next);
    if (next) setUrl("");
  };

  const submit = () => {
    if (loading) return;
    if (file) {
      onScanFile(file);
      return;
    }
    if (url.trim()) onScanUrl(url.trim());
  };

  return (
    <section
      id="scanner"
      className={`zt-panel zt-panel-glow relative overflow-hidden rounded-3xl p-5 transition-colors sm:p-7 ${
        dragging ? "border-emerald-400/60" : ""
      }`}
      onDragOver={(event) => {
        event.preventDefault();
        setDragging(true);
      }}
      onDragLeave={(event) => {
        if (event.currentTarget.contains(event.relatedTarget as Node)) return;
        setDragging(false);
      }}
      onDrop={(event) => {
        event.preventDefault();
        setDragging(false);
        const dropped = event.dataTransfer.files?.[0];
        if (dropped) stageFile(dropped);
      }}
    >
      <div
        className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-emerald-400/60 to-transparent"
        aria-hidden
      />

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-emerald-400/25 bg-emerald-400/10">
            <ScanLine className="h-4 w-4 text-emerald-300" />
          </span>
          <div>
            <h2 className="text-sm font-semibold tracking-tight text-slate-100">
              Omni-Scanner
            </h2>
            <p className="zt-mono text-[10px] tracking-[0.2em] text-slate-500">
              SINGLE UNIFIED INPUT
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="zt-mono rounded-md border border-slate-700/60 bg-slate-900/70 px-2 py-1 text-[10px] tracking-[0.14em] text-slate-400">
            URL
          </span>
          <span className="text-slate-600">·</span>
          <span className="zt-mono rounded-md border border-slate-700/60 bg-slate-900/70 px-2 py-1 text-[10px] tracking-[0.14em] text-slate-400">
            FILE
          </span>
          <span className="text-slate-600">·</span>
          <span className="zt-mono rounded-md border border-slate-700/60 bg-slate-900/70 px-2 py-1 text-[10px] tracking-[0.14em] text-slate-400">
            HASH
          </span>
        </div>
      </div>

      <form
        className="mt-5"
        onSubmit={(event) => {
          event.preventDefault();
          submit();
        }}
      >
        <div className="flex flex-col gap-2.5 sm:flex-row">
          <label htmlFor={inputId} className="sr-only">
            Target URL
          </label>
          <div className="relative flex-1">
            <Globe2 className="pointer-events-none absolute top-1/2 left-4 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              id={inputId}
              value={url}
              onChange={(event) => {
                setUrl(event.target.value);
                if (file) setFile(null);
              }}
              disabled={loading}
              spellCheck={false}
              autoComplete="off"
              placeholder="Paste a URL — https://example.com/login"
              className="zt-mono h-14 w-full rounded-xl border border-slate-700/60 bg-slate-950/70 pr-4 pl-11 text-[13px] text-slate-100 placeholder:text-slate-600 focus:border-emerald-400/60 focus:ring-2 focus:ring-emerald-400/20 focus:outline-none disabled:opacity-60"
            />
            {url && !loading ? (
              <button
                type="button"
                aria-label="Clear URL"
                onClick={() => setUrl("")}
                className="absolute top-1/2 right-3 -translate-y-1/2 rounded-md p-1 text-slate-500 hover:bg-slate-800 hover:text-slate-300"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            ) : null}
          </div>

          <button
            type="submit"
            disabled={!canScan || loading}
            className="group relative inline-flex h-14 items-center justify-center gap-2 overflow-hidden rounded-xl bg-gradient-to-r from-emerald-400 to-cyan-400 px-6 text-sm font-semibold text-slate-950 shadow-[0_10px_40px_-18px_rgb(16_185_129_/_0.9)] transition hover:from-emerald-300 hover:to-cyan-300 disabled:cursor-not-allowed disabled:from-slate-700 disabled:to-slate-700 disabled:text-slate-400 disabled:shadow-none"
          >
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : file ? (
              <ShieldAlert className="h-4 w-4" />
            ) : (
              <ScanSearch className="h-4 w-4" />
            )}
            {loading ? "Scanning…" : file ? "Analyze Payload" : "Scan Target"}
          </button>
        </div>
      </form>

      <div className="my-5 flex items-center gap-3" aria-hidden>
        <span className="h-px flex-1 bg-gradient-to-r from-transparent to-slate-700/70" />
        <span className="zt-mono text-[10px] tracking-[0.28em] text-slate-600">
          OR DROP A FILE
        </span>
        <span className="h-px flex-1 bg-gradient-to-l from-transparent to-slate-700/70" />
      </div>

      <input
        ref={fileInputRef}
        type="file"
        accept={ACCEPTED}
        className="hidden"
        onChange={(event) => {
          const picked = event.target.files?.[0] ?? null;
          stageFile(picked);
          event.target.value = "";
        }}
      />

      <div
        role="button"
        tabIndex={0}
        aria-label="Browse for a file to scan"
        aria-disabled={loading}
        onClick={() => {
          if (!loading) fileInputRef.current?.click();
        }}
        onKeyDown={(event) => {
          if ((event.key === "Enter" || event.key === " ") && !loading) {
            event.preventDefault();
            fileInputRef.current?.click();
          }
        }}
        className={`relative flex min-h-[132px] cursor-pointer flex-col items-center justify-center gap-2 overflow-hidden rounded-2xl border border-dashed px-4 py-6 text-center transition ${
          dragging
            ? "border-emerald-400/80 bg-emerald-400/10"
            : file
              ? "border-cyan-400/40 bg-cyan-400/[0.04]"
              : "border-slate-700/70 bg-slate-950/40 hover:border-emerald-400/40 hover:bg-slate-900/50"
        }`}
      >
        {file ? (
          <>
            <div className="flex max-w-full items-center gap-3 rounded-xl border border-slate-700/70 bg-slate-900/80 px-3 py-2">
              <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-cyan-400/10 text-cyan-300">
                <FileArchive className="h-4 w-4" />
              </span>
              <span className="min-w-0 text-left">
                <span className="zt-mono block truncate text-[12px] text-slate-100">
                  {file.name}
                </span>
                <span className="zt-mono block text-[10px] tracking-wider text-slate-500">
                  {formatBytes(file.size)} · STAGED FOR ANALYSIS
                </span>
              </span>
              <button
                type="button"
                aria-label="Remove staged file"
                onClick={(event) => {
                  event.stopPropagation();
                  setFile(null);
                }}
                className="ml-2 rounded-md p-1 text-slate-500 hover:bg-slate-800 hover:text-rose-300"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <p className="zt-mono text-[10px] tracking-[0.12em] text-cyan-300/70">
              PRESS “ANALYZE PAYLOAD” TO RUN THE STATIC ENGINE
            </p>
          </>
        ) : (
          <>
            <span className="flex h-11 w-11 items-center justify-center rounded-xl border border-slate-700/70 bg-slate-900/80 text-emerald-300">
              <UploadCloud className="h-5 w-5" />
            </span>
            <p className="text-sm font-medium text-slate-200">
              Drag &amp; drop your payload here
            </p>
            <p className="zt-mono text-[11px] tracking-wide text-slate-500">
              or <span className="text-emerald-300 underline decoration-dotted">browse</span>{" "}
              — .exe .apk .pdf .zip .txt .bin
            </p>
            <p className="zt-mono inline-flex items-center gap-1.5 text-[10px] tracking-[0.1em] text-slate-600">
              <Lock className="h-3 w-3" />
              HASHED IN-BROWSER · ONLY A ≤24 KB SLICE IS UPLOADED
            </p>
          </>
        )}

        {dragging ? (
          <span className="pointer-events-none absolute inset-x-0 top-0 h-24 bg-gradient-to-b from-emerald-400/20 to-transparent" />
        ) : null}
      </div>

      <div className="mt-5">
        <div className="flex items-center justify-between">
          <p className="zt-mono text-[10px] tracking-[0.24em] text-slate-500">
            ONE-CLICK DEMO TARGETS
          </p>
          <span className="zt-mono hidden text-[10px] tracking-[0.14em] text-slate-600 sm:block">
            PRESENTATION MODE
          </span>
        </div>

        <div className="mt-2.5 grid gap-2 sm:grid-cols-3">
          <DemoButton
            onClick={() => {
              setFile(null);
              setUrl(SAFE_URL);
              onScanUrl(SAFE_URL);
            }}
            disabled={loading}
            icon={<ShieldCheck className="h-4 w-4 text-emerald-300" />}
            title="Safe URL"
            subtitle="github.com"
            tone="emerald"
          />
          <DemoButton
            onClick={() => {
              setFile(null);
              setUrl(PHISHING_URL);
              onScanUrl(PHISHING_URL);
            }}
            disabled={loading}
            icon={<AtSign className="h-4 w-4 text-rose-300" />}
            title="Phishing Link Trap"
            subtitle="sbi-kyc-verify@secure-login.xyz"
            tone="rose"
          />
          <DemoButton
            onClick={() => {
              setFile(null);
              setUrl("");
              onDemoPayload();
            }}
            disabled={loading}
            icon={<Bug className="h-4 w-4 text-amber-300" />}
            title="Trojan / Payload"
            subtitle="SBI_Statement_2026.pdf.exe"
            tone="amber"
          />
        </div>
      </div>

      {/* Static hint row keeps the card balanced and explains the privacy model. */}
      <div className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-slate-800/70 pt-3">
        <span className="zt-mono inline-flex items-center gap-1.5 text-[10px] tracking-[0.1em] text-slate-500">
          <FileCheck2 className="h-3 w-3 text-emerald-400/80" /> SHA-256 · 8-BYTE MAGIC ·
          64 KB STRINGS
        </span>
        <span className="zt-mono ml-auto text-[10px] tracking-[0.1em] text-slate-600">
          0 BYTES OF RAW FILE UPLOADED
        </span>
      </div>
    </section>
  );
}

function DemoButton({
  onClick,
  disabled,
  icon,
  title,
  subtitle,
  tone,
}: {
  onClick: () => void;
  disabled: boolean;
  icon: ReactNode;
  title: string;
  subtitle: string;
  tone: "emerald" | "rose" | "amber";
}) {
  const hover = {
    emerald: "hover:border-emerald-400/50 hover:bg-emerald-400/[0.06]",
    rose: "hover:border-rose-400/50 hover:bg-rose-400/[0.06]",
    amber: "hover:border-amber-400/50 hover:bg-amber-400/[0.06]",
  }[tone];

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`group flex items-center gap-2.5 rounded-xl border border-slate-800/80 bg-slate-900/50 px-3 py-2.5 text-left transition disabled:cursor-not-allowed disabled:opacity-50 ${hover}`}
    >
      <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-slate-700/60 bg-slate-950/70">
        {icon}
      </span>
      <span className="min-w-0">
        <span className="block text-[12px] font-medium text-slate-200">{title}</span>
        <span className="zt-mono block truncate text-[10px] text-slate-500">
          {subtitle}
        </span>
      </span>
    </button>
  );
}
