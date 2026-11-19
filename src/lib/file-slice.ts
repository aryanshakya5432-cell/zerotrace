import type { FileSlicePayload } from "./types";

/** Max bytes read into the browser for hashing / entropy sampling. */
export const MAX_SAMPLE_BYTES = 64 * 1024 * 1024; // 64 MB
/** Max bytes scanned for ASCII strings. */
const STRING_WINDOW = 64 * 1024;
/** Max bytes scanned for Shannon entropy. */
const ENTROPY_WINDOW = 1024 * 1024;
/** Cap on the strings payload shipped to the server. */
const MAX_STRINGS_EXPORT = 24_000;

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

/** Shannon entropy in bits per byte, normalised to the 0–8 range. */
export function shannonEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i += 1) counts[bytes[i]] += 1;

  let entropy = 0;
  for (let i = 0; i < 256; i += 1) {
    if (counts[i] === 0) continue;
    const p = counts[i] / bytes.length;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

/** Extracts printable ASCII runs (min length 4) and joins them with spaces. */
export function extractStrings(bytes: Uint8Array, minLength = 4): string {
  const decoder = new TextDecoder("latin1");
  const text = decoder.decode(bytes);
  const matches = text.match(new RegExp(`[\\x20-\\x7E]{${minLength},}`, "g"));
  if (!matches) return "";
  const joined = matches.join(" ");
  return joined.length > MAX_STRINGS_EXPORT
    ? joined.slice(0, MAX_STRINGS_EXPORT)
    : joined;
}

async function sha256Hex(buffer: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return toHex(new Uint8Array(digest));
}

/**
 * Reads the file in the browser and produces the lightweight JSON slice that
 * `/api/scan-file` consumes. The raw file never leaves the client, which keeps
 * every deployment under Vercel's 4.5 MB serverless request-body limit.
 */
export async function buildFileSlice(file: File): Promise<FileSlicePayload> {
  const truncated = file.size > MAX_SAMPLE_BYTES;
  const sample = file.slice(0, Math.min(file.size, MAX_SAMPLE_BYTES));
  const buffer = await sample.arrayBuffer();
  const bytes = new Uint8Array(buffer);

  const [sha256] = await Promise.all([sha256Hex(buffer)]);

  return {
    name: file.name,
    size: file.size,
    mimeType: file.type || "application/octet-stream",
    sha256,
    headerHex: toHex(bytes.slice(0, 8)),
    strings: extractStrings(bytes.slice(0, STRING_WINDOW)),
    entropy: shannonEntropy(bytes.slice(0, ENTROPY_WINDOW)),
    sampledBytes: bytes.length,
    truncated,
  };
}

export function formatBytes(size: number): string {
  if (!Number.isFinite(size) || size < 0) return "—";
  if (size < 1024) return `${size} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = size / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[unit]}`;
}
