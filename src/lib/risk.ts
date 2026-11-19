import type { Verdict } from "./types";

export const MALICIOUS_THRESHOLD = 50;
export const SUSPICIOUS_THRESHOLD = 20;

export function verdictFromScore(score: number): Verdict {
  if (score >= MALICIOUS_THRESHOLD) return "MALICIOUS";
  if (score >= SUSPICIOUS_THRESHOLD) return "SUSPICIOUS";
  return "SAFE";
}

export function clampScore(score: number): number {
  return Math.max(0, Math.min(100, Math.round(score)));
}
