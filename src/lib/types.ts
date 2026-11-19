export type Verdict = "SAFE" | "SUSPICIOUS" | "MALICIOUS";

export type CheckStatus = "PASS" | "FLAGGED";

export type TargetType = "url" | "file";

export interface ScanCheck {
  id: string;
  label: string;
  status: CheckStatus;
  detail: string;
  weight: number;
}

export interface ScanResult {
  targetType: TargetType;
  target: string;
  score: number;
  verdict: Verdict;
  threatType: string;
  metadata: Record<string, string>;
  checks: ScanCheck[];
  scannedAt: string;
  engine: string;
}

export interface ScanError {
  error: string;
}

export interface FileSlicePayload {
  name: string;
  size: number;
  mimeType: string;
  sha256: string;
  headerHex: string;
  strings: string;
  entropy: number;
  sampledBytes: number;
  truncated: boolean;
}
