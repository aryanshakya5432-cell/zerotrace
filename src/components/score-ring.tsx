import type { Verdict } from "@/lib/types";

const THEME: Record<
  Verdict,
  { stroke: string; glow: string; text: string; soft: string }
> = {
  SAFE: {
    stroke: "#34d399",
    glow: "rgb(52 211 153 / 0.45)",
    text: "text-emerald-300",
    soft: "bg-emerald-400/10 text-emerald-300 ring-emerald-400/30",
  },
  SUSPICIOUS: {
    stroke: "#fbbf24",
    glow: "rgb(251 191 36 / 0.45)",
    text: "text-amber-300",
    soft: "bg-amber-400/10 text-amber-300 ring-amber-400/30",
  },
  MALICIOUS: {
    stroke: "#fb7185",
    glow: "rgb(251 113 133 / 0.45)",
    text: "text-rose-300",
    soft: "bg-rose-500/10 text-rose-300 ring-rose-400/30",
  },
};

const RADIUS = 78;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

export function ScoreRing({
  score,
  verdict,
}: {
  score: number;
  verdict: Verdict;
}) {
  const theme = THEME[verdict];
  const clamped = Math.max(0, Math.min(100, score));
  const offset = CIRCUMFERENCE * (1 - clamped / 100);

  return (
    <div className="relative flex h-[208px] w-[208px] items-center justify-center">
      <svg
        viewBox="0 0 200 200"
        className="h-full w-full -rotate-90"
        role="img"
        aria-label={`Risk score ${clamped} out of 100 — ${verdict}`}
      >
        <defs>
          <linearGradient id={`ring-${verdict}`} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor={theme.stroke} stopOpacity="0.55" />
            <stop offset="100%" stopColor={theme.stroke} />
          </linearGradient>
          <filter id="ring-glow" x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="4" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {Array.from({ length: 60 }).map((_, index) => {
          const active = index / 60 <= clamped / 100;
          const angle = (index / 60) * Math.PI * 2;
          const inner = 92;
          const outer = index % 5 === 0 ? 99 : 96;
          return (
            <line
              key={index}
              x1={100 + Math.cos(angle) * inner}
              y1={100 + Math.sin(angle) * inner}
              x2={100 + Math.cos(angle) * outer}
              y2={100 + Math.sin(angle) * outer}
              stroke={active ? theme.stroke : "#1e293b"}
              strokeWidth={index % 5 === 0 ? 2 : 1}
              strokeLinecap="round"
              opacity={active ? 0.75 : 0.6}
            />
          );
        })}

        <circle
          cx="100"
          cy="100"
          r={RADIUS}
          fill="none"
          stroke="#1e293b"
          strokeWidth="12"
        />
        <circle
          cx="100"
          cy="100"
          r={RADIUS}
          fill="none"
          stroke={`url(#ring-${verdict})`}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={CIRCUMFERENCE}
          strokeDashoffset={offset}
          filter="url(#ring-glow)"
          style={{ transition: "stroke-dashoffset 900ms cubic-bezier(0.22,1,0.36,1)" }}
        />
      </svg>

      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="zt-mono text-[10px] font-medium tracking-[0.32em] text-slate-500">
          RISK
        </span>
        <span
          className={`zt-mono text-6xl leading-none font-semibold tabular-nums ${theme.text}`}
        >
          {clamped}
        </span>
        <span className="zt-mono mt-1 text-[10px] tracking-[0.22em] text-slate-500">
          / 100
        </span>
      </div>
    </div>
  );
}

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const theme = THEME[verdict];
  return (
    <span
      className={`zt-mono inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-[10px] font-semibold tracking-[0.18em] ring-1 ring-inset ${theme.soft}`}
    >
      <span
        className="h-1.5 w-1.5 rounded-full"
        style={{ backgroundColor: theme.stroke }}
      />
      {verdict}
    </span>
  );
}

export function verdictTheme(verdict: Verdict) {
  return THEME[verdict];
}
