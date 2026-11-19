"use client";

import {
  AlertTriangle,
  CheckCircle2,
  ClipboardCheck,
  Copy,
  Cpu,
  FileWarning,
  Fingerprint,
  Gauge,
  Globe2,
  Loader2,
  Radar,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Timer,
} from "lucide-react";
import { useEffect, useState } from "react";

import { ScoreRing, VerdictBadge, verdictTheme } from "@/components/score-ring";
import type { ScanResult } from "@/lib/types";

/* ------------------------------------------------------------------ states */

export function ScanningBento({ target }: { target: string }) {
  const stages = [
    { icon: Fingerprint, label: "Extracting client-side features" },
    { icon: Globe2, label: "Probing live DNS & TLS sockets" },
    { icon: Cpu, label: "Matching signature database" },
    { icon: Gauge, label: "Scoring risk classification" },
  ];

  return (
    <div className="zt-panel relative overflow-hidden rounded-2xl p-6 sm:p-10">
      <div
        className="zt-sweep pointer-events-none absolute inset-x-0 top-0 h-24 bg-gradient-to-b from-emerald-400/10 via-emerald-400/[0.03] to-transparent"
        aria-hidden
      />
      <div className="relative flex flex-col items-center text-center">
        <span className="flex h-14 w-14 items-center justify-center rounded-2xl border border-emerald-400/30 bg-emerald-400/10">
          <Radar className="h-6 w-6 animate-pulse text-emerald-300" />
        </span>
        <h2 className="mt-4 text-base font-semibold text-slate-100">
          Scanning target…
        </h2>
        <p className="zt-mono mt-1 max-w-lg truncate text-[11px] tracking-wide text-slate-500">
          {target}
        </p>

        <div className="mt-6 h-1 w-full max-w-xl overflow-hidden rounded-full bg-slate-800">
          <div className="zt-shimmer h-full w-full rounded-full" />
        </div>

        <div className="mt-6 grid w-full max-w-2xl gap-2 sm:grid-cols-2">
          {stages.map((stage, index) => (
            <div
              key={stage.label}
              className="flex items-center gap-2.5 rounded-lg border border-slate-800/70 bg-slate-950/50 px-3 py-2 text-left"
              style={{ animationDelay: `${index * 120}ms` }}
            >
              <stage.icon className="h-3.5 w-3.5 shrink-0 text-emerald-400/80" />
              <span className="zt-mono flex-1 text-[10.5px] tracking-wide text-slate-400">
                {stage.label}
              </span>
              <Loader2 className="h-3 w-3 animate-spin text-emerald-400/70" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export function ErrorBento({ message }: { message: string }) {
  return (
    <div className="zt-panel flex flex-col items-center gap-3 rounded-2xl border-rose-500/30 p-10 text-center">
      <span className="flex h-12 w-12 items-center justify-center rounded-xl border border-rose-500/30 bg-rose-500/10">
        <AlertTriangle className="h-5 w-5 text-rose-300" />
      </span>
      <h2 className="text-sm font-semibold text-rose-200">Scan failed</h2>
      <p className="max-w-md text-[12.5px] text-slate-400">{message}</p>
    </div>
  );
}

/* ----------------------------------------------------------------- results */

export function ResultsBento({ result }: { result: ScanResult }) {
  const flagged = result.checks.filter((check) => check.status === "FLAGGED");
  const passed = result.checks.length - flagged.length;
  const theme = verdictTheme(result.verdict);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(false), 1800);
    return () => clearTimeout(timer);
  }, [copied]);

  const copyReport = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(result, null, 2));
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="zt-rise grid grid-cols-1 gap-3 lg:grid-cols-12">
      {/* Card 1 — verdict */}
      <article className="zt-panel relative flex flex-col overflow-hidden rounded-2xl p-5 lg:col-span-4">
        <div
          className="pointer-events-none absolute -top-20 -right-16 h-48 w-48 rounded-full blur-3xl"
          style={{ backgroundColor: theme.glow, opacity: 0.18 }}
          aria-hidden
        />
        <header className="flex items-center justify-between">
          <h3 className="zt-mono text-[10px] font-medium tracking-[0.24em] text-slate-500">
            THREAT ASSESSMENT
          </h3>
          <span className="zt-mono inline-flex items-center gap-1.5 rounded-md border border-slate-700/70 bg-slate-900/70 px-2 py-0.5 text-[9.5px] tracking-[0.14em] text-slate-400">
            {result.targetType === "file" ? (
              <FileWarning className="h-3 w-3" />
            ) : (
              <Globe2 className="h-3 w-3" />
            )}
            {result.targetType.toUpperCase()}
          </span>
        </header>

        <div className="mt-4 flex flex-col items-center">
          <ScoreRing score={result.score} verdict={result.verdict} />
          <div className="mt-1">
            <VerdictBadge verdict={result.verdict} />
          </div>
        </div>

        <div className="mt-5 rounded-xl border border-slate-800/80 bg-slate-950/50 p-3">
          <p className="zt-mono text-[9.5px] tracking-[0.22em] text-slate-500">
            CLASSIFICATION
          </p>
          <p
            className={`mt-1 flex items-center gap-2 text-[15px] font-semibold ${theme.text}`}
          >
            {result.verdict === "SAFE" ? (
              <ShieldCheck className="h-4 w-4 shrink-0" />
            ) : (
              <ShieldAlert className="h-4 w-4 shrink-0" />
            )}
            {result.threatType}
          </p>
        </div>

        <div className="mt-3 space-y-2">
          <div className="flex items-start gap-2">
            <ScanSearch className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-500" />
            <p className="zt-mono line-clamp-2 text-[11px] break-all text-slate-300">
              {result.target}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Timer className="h-3.5 w-3.5 shrink-0 text-slate-500" />
            <p className="zt-mono text-[10.5px] text-slate-500">
              {new Date(result.scannedAt).toLocaleTimeString()} ·{" "}
              {flagged.length} flagged / {passed} passed
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={copyReport}
          className="mt-4 inline-flex items-center justify-center gap-2 rounded-lg border border-slate-700/70 bg-slate-900/60 px-3 py-2 text-[11.5px] font-medium text-slate-300 transition hover:border-emerald-400/40 hover:text-emerald-200"
        >
          {copied ? (
            <>
              <ClipboardCheck className="h-3.5 w-3.5 text-emerald-300" /> Report copied
            </>
          ) : (
            <>
              <Copy className="h-3.5 w-3.5" /> Copy JSON report
            </>
          )}
        </button>
      </article>

      {/* Card 2 — intelligence */}
      <article className="zt-panel flex flex-col rounded-2xl p-5 lg:col-span-8">
        <header className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="zt-mono text-[10px] font-medium tracking-[0.24em] text-slate-500">
            TARGET INTELLIGENCE
          </h3>
          <span className="zt-mono inline-flex items-center gap-1.5 rounded-md border border-emerald-400/20 bg-emerald-400/[0.07] px-2 py-0.5 text-[9.5px] tracking-[0.1em] text-emerald-300/90">
            <span className="h-1 w-1 rounded-full bg-emerald-400" />
            {result.engine}
          </span>
        </header>

        <div className="mt-4 grid flex-1 grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3">
          {Object.entries(result.metadata).map(([key, value]) => {
            const wide = key === "SHA-256" || key === "Sampled";
            return (
              <div
                key={key}
                className={`rounded-xl border border-slate-800/80 bg-slate-950/50 px-3 py-2.5 ${
                  wide ? "sm:col-span-2 xl:col-span-3" : ""
                }`}
              >
                <p className="zt-mono text-[9px] tracking-[0.2em] text-slate-500 uppercase">
                  {key}
                </p>
                <p
                  className={`zt-mono mt-1 text-[12px] leading-snug break-all ${toneFor(
                    key,
                    value,
                  )}`}
                >
                  {value}
                </p>
              </div>
            );
          })}
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1.5 border-t border-slate-800/70 pt-3">
          <span className="zt-mono text-[10px] tracking-[0.1em] text-slate-600">
            ANALYSIS MODE · {result.targetType === "file" ? "STATIC + HASH" : "HEURISTIC + LIVE PROBES"}
          </span>
          <span className="zt-mono ml-auto text-[10px] tracking-[0.1em] text-slate-600">
            {result.checks.length} CHECKS EXECUTED
          </span>
        </div>
      </article>

      {/* Card 3 — audit */}
      <article className="zt-panel rounded-2xl p-5 lg:col-span-12">
        <header className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="zt-mono text-[10px] font-medium tracking-[0.24em] text-slate-500">
              HEURISTIC &amp; SIGNATURE AUDIT
            </h3>
            <p className="mt-1 text-[12px] text-slate-400">
              Every engine rule that contributed to this verdict.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="zt-mono inline-flex items-center gap-1.5 rounded-md border border-rose-500/25 bg-rose-500/10 px-2 py-1 text-[10px] tracking-[0.1em] text-rose-300">
              <AlertTriangle className="h-3 w-3" /> {flagged.length} FLAGGED
            </span>
            <span className="zt-mono inline-flex items-center gap-1.5 rounded-md border border-emerald-500/25 bg-emerald-500/10 px-2 py-1 text-[10px] tracking-[0.1em] text-emerald-300">
              <CheckCircle2 className="h-3 w-3" /> {passed} PASSED
            </span>
          </div>
        </header>

        <div className="mt-4 grid gap-2 md:grid-cols-2">
          {result.checks.map((check) => {
            const isFlag = check.status === "FLAGGED";
            return (
              <div
                key={check.id}
                className={`rounded-xl border px-3.5 py-3 transition ${
                  isFlag
                    ? "border-rose-500/25 bg-rose-500/[0.045]"
                    : "border-slate-800/80 bg-slate-950/45"
                }`}
              >
                <div className="flex items-start gap-2.5">
                  <span
                    className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-md ${
                      isFlag
                        ? "bg-rose-500/15 text-rose-300"
                        : "bg-emerald-500/15 text-emerald-300"
                    }`}
                  >
                    {isFlag ? (
                      <AlertTriangle className="h-3 w-3" />
                    ) : (
                      <CheckCircle2 className="h-3 w-3" />
                    )}
                  </span>

                  <div className="min-w-0 flex-1">
                    <div className="flex items-start justify-between gap-2">
                      <p className="text-[12.5px] leading-tight font-medium text-slate-200">
                        {check.label}
                      </p>
                      <span
                        className={`zt-mono shrink-0 rounded px-1.5 py-0.5 text-[9px] font-semibold tracking-[0.12em] ${
                          isFlag
                            ? "bg-rose-500/15 text-rose-300 ring-1 ring-rose-500/25 ring-inset"
                            : "bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/25 ring-inset"
                        }`}
                      >
                        {check.status}
                        {isFlag && check.weight > 0 ? ` +${check.weight}` : ""}
                      </span>
                    </div>
                    <p className="mt-1 text-[11.5px] leading-relaxed text-slate-400">
                      {check.detail}
                    </p>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </article>
    </div>
  );
}

function toneFor(key: string, value: string): string {
  if (key === "SSL Status") {
    return value === "VALID"
      ? "text-emerald-300"
      : value === "—"
        ? "text-slate-500"
        : "text-rose-300";
  }
  if (key === "Resolved IP") {
    return value === "—" ? "text-rose-300" : "text-slate-200";
  }
  if (key === "Shannon Entropy") {
    const numeric = Number.parseFloat(value);
    return numeric > 7.2 ? "text-rose-300" : "text-slate-200";
  }
  if (key === "Declared Extension") {
    return /\b(exe|scr|js|vbs|bat|cmd|msi)\b/i.test(value)
      ? "text-amber-300"
      : "text-slate-200";
  }
  return "text-slate-200";
}
