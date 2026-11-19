import {
  Binary,
  ChevronRight,
  Gauge,
  Layers,
  Radar,
  ShieldCheck,
} from "lucide-react";

const STEPS = [
  {
    step: "01",
    title: "Unified Input",
    description:
      "One omni-box takes a pasted URL or a dropped payload. No tabs, no mode switch — the engine detects what you gave it.",
    icon: Layers,
    accent: "text-emerald-300",
    ring: "border-emerald-400/25 bg-emerald-400/10",
    chip: "URL · FILE",
  },
  {
    step: "02",
    title: "Feature Extraction",
    description:
      "SHA-256, 8-byte magic header, 64 KB of printable strings and Shannon entropy are computed in the browser before any request.",
    icon: Binary,
    accent: "text-cyan-300",
    ring: "border-cyan-400/25 bg-cyan-400/10",
    chip: "IN-BROWSER",
  },
  {
    step: "03",
    title: "Rule & API Engine",
    description:
      "Nine URL checks with live DNS + TLS probes and two cloud threat feeds, plus nine static file checks with an optional VirusTotal v3 lookup.",
    icon: Radar,
    accent: "text-sky-300",
    ring: "border-sky-400/25 bg-sky-400/10",
    chip: "3000ms CEILING",
  },
  {
    step: "04",
    title: "Risk Classification",
    description:
      "Weighted signals roll into a 0–100 score and map to SAFE, SUSPICIOUS or MALICIOUS with a named threat family.",
    icon: ShieldCheck,
    accent: "text-rose-300",
    ring: "border-rose-400/25 bg-rose-400/10",
    chip: "0–100 SCORE",
  },
];

export function PipelineSection() {
  return (
    <section id="pipeline" className="mt-16 scroll-mt-24">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="zt-mono text-[10px] tracking-[0.3em] text-emerald-400/80">
            DETECTION PIPELINE
          </p>
          <h2 className="mt-2 text-xl font-semibold tracking-tight text-slate-100 sm:text-2xl">
            ZeroTrace Detection Pipeline
          </h2>
          <p className="mt-1.5 max-w-2xl text-[12.5px] leading-relaxed text-slate-400">
            Four deterministic stages turn a raw link or a binary payload into a
            defensible risk verdict — without ever shipping the file.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="zt-mono rounded-md border border-slate-700/70 bg-slate-900/70 px-2.5 py-1 text-[10px] tracking-[0.14em] text-slate-400">
            VERCEL-SAFE
          </span>
          <span className="zt-mono rounded-md border border-slate-700/70 bg-slate-900/70 px-2.5 py-1 text-[10px] tracking-[0.14em] text-slate-400">
            NODE RUNTIME
          </span>
        </div>
      </div>

      <div className="relative mt-5">
        <div
          className="pointer-events-none absolute top-[74px] right-6 left-6 hidden h-px bg-[repeating-linear-gradient(90deg,rgb(148_163_184/0.35)_0_6px,transparent_6px_14px)] lg:block"
          aria-hidden
        />
        <ol className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {STEPS.map((step, index) => (
            <li key={step.step} className="relative">
              <div className="zt-panel zt-card-hover group flex h-full flex-col rounded-2xl p-5">
                <div className="flex items-center justify-between">
                  <span
                    className={`flex h-10 w-10 items-center justify-center rounded-xl border ${step.ring}`}
                  >
                    <step.icon className={`h-[18px] w-[18px] ${step.accent}`} />
                  </span>
                  <span className="zt-mono text-[10px] tracking-[0.2em] text-slate-600">
                    {step.step}
                  </span>
                </div>

                <h3 className="mt-4 text-[13.5px] font-semibold text-slate-100">
                  {step.title}
                </h3>
                <p className="mt-1.5 flex-1 text-[11.5px] leading-relaxed text-slate-400">
                  {step.description}
                </p>

                <span className="zt-mono mt-4 inline-flex w-fit items-center gap-1 rounded border border-slate-700/60 bg-slate-950/60 px-1.5 py-0.5 text-[9px] tracking-[0.14em] text-slate-500">
                  {step.chip}
                </span>
              </div>

              {index < STEPS.length - 1 ? (
                <ChevronRight className="absolute top-1/2 -right-[13px] hidden h-4 w-4 -translate-y-1/2 text-slate-600 lg:block" />
              ) : null}
            </li>
          ))}
        </ol>
      </div>

      <div className="zt-panel mt-3 grid gap-px overflow-hidden rounded-2xl sm:grid-cols-3">
        <div className="flex items-center gap-2.5 px-4 py-3">
          <Gauge className="h-4 w-4 text-emerald-300" />
          <div>
            <p className="zt-mono text-[9px] tracking-[0.18em] text-slate-500">
              SCORE MODEL
            </p>
            <p className="text-[11.5px] text-slate-300">
              SAFE &lt; 20 · SUSPICIOUS 20–49 · MALICIOUS ≥ 50
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2.5 border-t border-slate-800/70 px-4 py-3 sm:border-t-0 sm:border-l">
          <Binary className="h-4 w-4 text-cyan-300" />
          <div>
            <p className="zt-mono text-[9px] tracking-[0.18em] text-slate-500">
              UPLOAD BUDGET
            </p>
            <p className="text-[11.5px] text-slate-300">
              ≤ 24 KB JSON · raw file never leaves the browser
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2.5 border-t border-slate-800/70 px-4 py-3 sm:border-t-0 sm:border-l">
          <Radar className="h-4 w-4 text-rose-300" />
          <div>
            <p className="zt-mono text-[9px] tracking-[0.18em] text-slate-500">
              NETWORK POLICY
            </p>
            <p className="text-[11.5px] text-slate-300">
              3000ms hard timeout on every DNS / TLS / API socket
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
