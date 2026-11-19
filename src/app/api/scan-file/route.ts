import { formatBytes } from "@/lib/file-slice";
import { clampScore, verdictFromScore } from "@/lib/risk";
import type { ScanCheck, ScanResult } from "@/lib/types";

export const runtime = "nodejs";
export const maxDuration = 10;

/** Hard ceiling for the optional VirusTotal lookup (Vercel-safe). */
const NETWORK_TIMEOUT_MS = 3000;

/** Hashes of the harmless demo samples shipped in /test-samples. */
const KNOWN_SHA256: Record<string, string> = {
  B770F89F0919DDC0A535BB6A3C1BDF5003ECE95F54A5CC593AA9D54DF5619193:
    "Demo Trojan (finance lure + process injector)",
};

/** Filename signatures that survive regenerated sample bytes. */
const KNOWN_NAME_SIGNATURES: Array<{ pattern: RegExp; family: string }> = [
  { pattern: /sbi[_-]?account[_-]?statement.*\.pdf\.exe$/i, family: "Demo Trojan (finance lure + process injector)" },
];

interface MagicFamily {
  type: string;
  family: "pe" | "elf" | "zip" | "pdf" | "text" | "binary";
  extensions: string[];
}

const MAGIC_SIGNATURES: Array<{ hex: string; info: MagicFamily }> = [
  {
    hex: "4D5A",
    info: {
      type: "Windows PE Executable (MZ)",
      family: "pe",
      extensions: ["exe", "dll", "sys", "scr", "com", "cpl", "ocx", "efi", "bin"],
    },
  },
  {
    hex: "7F454C46",
    info: {
      type: "Linux ELF Binary",
      family: "elf",
      extensions: ["elf", "so", "bin", "o", "ko"],
    },
  },
  {
    hex: "504B0304",
    info: {
      type: "ZIP Archive / APK Package",
      family: "zip",
      extensions: ["zip", "apk", "jar", "docx", "xlsx", "pptx", "epub", "kra"],
    },
  },
  {
    hex: "25504446",
    info: {
      type: "PDF Document",
      family: "pdf",
      extensions: ["pdf"],
    },
  },
];

const DOCUMENT_EXTENSIONS = [
  "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg",
  "jpeg", "png", "gif", "csv", "zip", "rar", "7z",
];

const EXECUTABLE_EXTENSIONS = [
  "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "msi",
];

const INJECTION_APIS = [
  "VirtualAlloc",
  "VirtualAllocEx",
  "WriteProcessMemory",
  "CreateRemoteThread",
  "NtUnmapViewOfSection",
  "QueueUserAPC",
  "SetThreadContext",
];

const SPYWARE_APIS = [
  "SetWindowsHookEx",
  "GetAsyncKeyState",
  "GetKeyboardState",
  "GetKeyState",
  "keybd_event",
  "MapVirtualKey",
];

const DROPPER_STRINGS = [
  "cmd.exe",
  "powershell",
  "invoke-expression",
  "downloadstring",
  "certutil",
  "bitsadmin",
  "schtasks",
  "regsvr32",
  "wscript.shell",
];

function detectMagic(headerHex: string): MagicFamily {
  const hex = headerHex.toUpperCase();
  const match = MAGIC_SIGNATURES.find((sig) => hex.startsWith(sig.hex));
  if (match) return match.info;

  const bytes = hex.match(/.{2}/g) ?? [];
  const printable = bytes.every((pair) => {
    const value = Number.parseInt(pair, 16);
    return value === 0x09 || value === 0x0a || value === 0x0d || (value >= 0x20 && value <= 0x7e);
  });

  return {
    type: printable ? "ASCII / Plain Text" : "Unknown / Raw Binary",
    family: printable ? "text" : "binary",
    extensions: [],
  };
}

function matchList(haystack: string, needles: string[]): string[] {
  const lower = haystack.toLowerCase();
  return needles.filter((needle) => lower.includes(needle.toLowerCase()));
}

interface VirusTotalVerdict {
  checked: boolean;
  flagged: boolean;
  summary: string;
  engine: string;
}

async function lookupVirusTotal(sha256: string): Promise<VirusTotalVerdict> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return {
      checked: false,
      flagged: false,
      summary: "VIRUSTOTAL_API_KEY is not configured — local static engine used.",
      engine: "ZeroTrace Static Engine (local)",
    };
  }

  try {
    const response = await fetch(
      `https://www.virustotal.com/api/v3/files/${encodeURIComponent(sha256)}`,
      {
        headers: { "x-apikey": apiKey, accept: "application/json" },
        signal: AbortSignal.timeout(NETWORK_TIMEOUT_MS),
        cache: "no-store",
      },
    );

    if (response.status === 404) {
      return {
        checked: true,
        flagged: false,
        summary: "Hash not present in the VirusTotal corpus (unknown file).",
        engine: "VirusTotal v3 + ZeroTrace Static",
      };
    }

    if (!response.ok) {
      return {
        checked: false,
        flagged: false,
        summary: `VirusTotal returned HTTP ${response.status} — falling back to the local engine.`,
        engine: "ZeroTrace Static Engine (VT fallback)",
      };
    }

    const payload = (await response.json()) as {
      data?: {
        attributes?: {
          last_analysis_stats?: {
            malicious?: number;
            suspicious?: number;
            undetected?: number;
            harmless?: number;
          };
        };
      };
    };

    const stats = payload.data?.attributes?.last_analysis_stats;
    if (!stats) {
      return {
        checked: true,
        flagged: false,
        summary: "VirusTotal response contained no analysis stats.",
        engine: "VirusTotal v3 + ZeroTrace Static",
      };
    }

    const malicious = stats.malicious ?? 0;
    const suspicious = stats.suspicious ?? 0;
    const total =
      malicious + suspicious + (stats.undetected ?? 0) + (stats.harmless ?? 0);

    return {
      checked: true,
      flagged: malicious > 0 || suspicious >= 2,
      summary: `${malicious + suspicious}/${total} engines flagged this hash (${malicious} malicious, ${suspicious} suspicious).`,
      engine: "VirusTotal v3 + ZeroTrace Static",
    };
  } catch (error) {
    const reason = error instanceof Error ? error.message : "request failed";
    return {
      checked: false,
      flagged: false,
      summary: `VirusTotal unavailable (${reason}) — local engine used.`,
      engine: "ZeroTrace Static Engine (VT offline)",
    };
  }
}

function asString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function asNumber(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

export async function POST(request: Request) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "Malformed JSON body." }, { status: 400 });
  }

  if (typeof body !== "object" || body === null) {
    return Response.json({ error: "Empty scan payload." }, { status: 400 });
  }

  const raw = body as Record<string, unknown>;
  const name = asString(raw.name).trim();
  const sha256 = asString(raw.sha256).toUpperCase();
  const headerHex = asString(raw.headerHex).toUpperCase();
  const strings = asString(raw.strings);
  const size = asNumber(raw.size);
  const entropy = Math.max(0, Math.min(8, asNumber(raw.entropy)));

  if (!name) {
    return Response.json({ error: "File name is required." }, { status: 400 });
  }

  if (!/^[A-F0-9]{64}$/.test(sha256)) {
    return Response.json(
      { error: "A valid SHA-256 digest is required." },
      { status: 400 },
    );
  }

  const lowerName = name.toLowerCase();
  const segments = lowerName.split(".").filter(Boolean);
  const extension = segments.length > 1 ? segments[segments.length - 1] : "";
  const magic = detectMagic(headerHex);
  const checks: ScanCheck[] = [];
  let score = 0;

  const addCheck = (check: ScanCheck) => {
    checks.push(check);
    if (check.status === "FLAGGED") score += check.weight;
  };

  // 1 — Known signature database
  const hashHit = KNOWN_SHA256[sha256];
  const nameHit = KNOWN_NAME_SIGNATURES.find((sig) => sig.pattern.test(name));
  const signatureFamily = hashHit ?? nameHit?.family;
  addCheck({
    id: "known-signature",
    label: "Known Malware Signature Database",
    status: signatureFamily ? "FLAGGED" : "PASS",
    detail: signatureFamily
      ? `${hashHit ? "SHA-256" : "Filename"} matched: ${signatureFamily}.`
      : `No match for ${sha256.slice(0, 12)}… in the ZeroTrace signature set.`,
    weight: 40,
  });

  // 2 — Magic bytes vs. declared extension
  const disguisedDocument =
    magic.family === "pe"
      ? segments
          .slice(0, -1)
          .reverse()
          .find((segment) => DOCUMENT_EXTENSIONS.includes(segment))
      : undefined;
  const extensionMismatch =
    magic.family !== "text" &&
    magic.family !== "binary" &&
    !magic.extensions.includes(extension);
  const extensionConflict = Boolean(disguisedDocument) || extensionMismatch;
  const claimedExtension = disguisedDocument
    ? `.${disguisedDocument}`
    : `.${extension}`;

  addCheck({
    id: "magic-extension",
    label: "Magic Bytes vs. File Extension",
    status: extensionConflict ? "FLAGGED" : "PASS",
    detail: extensionConflict
      ? `Header ${headerHex.slice(0, 8)} identifies ${magic.type}, but the name claims ${claimedExtension}. Content and extension disagree.`
      : magic.family === "text" || magic.family === "binary"
        ? `Header ${headerHex.slice(0, 8)} has no executable magic bytes.`
        : `Header ${headerHex.slice(0, 8)} matches ${magic.type} and the .${extension} extension.`,
    weight: 30,
  });

  // 3 — True file type (informational, never scored)
  addCheck({
    id: "true-file-type",
    label: "True File Type Identification",
    status: "PASS",
    detail: `Resolved from magic bytes: ${magic.type}.`,
    weight: 0,
  });

  // 4 — Double extension trap
  const doubleExtension =
    segments.length >= 3 &&
    EXECUTABLE_EXTENSIONS.includes(extension) &&
    segments.slice(0, -1).some((segment) => DOCUMENT_EXTENSIONS.includes(segment));
  addCheck({
    id: "double-extension",
    label: "Double Extension Spoofing",
    status: doubleExtension ? "FLAGGED" : "PASS",
    detail: doubleExtension
      ? `"${name}" hides the real .${extension} handler behind a document-looking name.`
      : "File name exposes a single, unambiguous extension.",
    weight: 20,
  });

  // 5 — Shannon entropy
  const packed = entropy > 7.2;
  addCheck({
    id: "entropy",
    label: "Shannon Entropy (Packed / Encrypted)",
    status: packed ? "FLAGGED" : "PASS",
    detail: `${entropy.toFixed(2)} bits/byte (threshold: 7.20). ${
      packed
        ? "Near-random byte distribution — typical of a crypter, packer or compressed payload."
        : "Byte distribution is consistent with normal application or text data."
    }`,
    weight: 18,
  });

  // 6 — Process injection APIs
  const injectionHits = matchList(strings, INJECTION_APIS);
  addCheck({
    id: "process-injection",
    label: "Process Injection API Imports",
    status: injectionHits.length > 0 ? "FLAGGED" : "PASS",
    detail:
      injectionHits.length > 0
        ? `Found ${injectionHits.join(", ")} — used to write and execute code inside another process.`
        : "No memory-injection API names in the first 64 KB of strings.",
    weight: 30,
  });

  // 7 — Spyware / keylogger hooks
  const spywareHits = matchList(strings, SPYWARE_APIS);
  addCheck({
    id: "spyware-hooks",
    label: "Spyware / Keylogger Hooks",
    status: spywareHits.length > 0 ? "FLAGGED" : "PASS",
    detail:
      spywareHits.length > 0
        ? `Found ${spywareHits.join(", ")} — keyboard hook / keystate polling behaviour.`
        : "No keyboard hook or keystate polling APIs detected.",
    weight: 30,
  });

  // 8 — Dropper & shell execution strings
  const dropperHits = matchList(strings, DROPPER_STRINGS);
  const encodedCommand = /powershell/i.test(strings) && /-enc(odedcommand)?\b/i.test(strings);
  addCheck({
    id: "dropper-strings",
    label: "Dropper & Shell Execution Strings",
    status: dropperHits.length > 0 ? "FLAGGED" : "PASS",
    detail:
      dropperHits.length > 0
        ? `Shell tokens found: ${dropperHits.join(", ")}${
            encodedCommand ? " · base64 encoded command (-enc) present" : ""
          }.`
        : "No shell interpreter or download-and-execute strings found.",
    weight: 22,
  });

  // 9 — Optional VirusTotal v3
  const vt = await lookupVirusTotal(sha256);
  addCheck({
    id: "virustotal",
    label: "VirusTotal Reputation (API v3)",
    status: vt.flagged ? "FLAGGED" : "PASS",
    detail: vt.summary,
    weight: 30,
  });

  const finalScore = clampScore(score);
  const verdict = verdictFromScore(finalScore);

  let threatType: string;
  if (verdict === "SAFE") {
    threatType = "Clean / Benign File";
  } else if (injectionHits.length > 0 || signatureFamily?.includes("Trojan")) {
    threatType = "Trojan / Process Injector";
  } else if (spywareHits.length > 0) {
    threatType = "Spyware / Keylogger Hook";
  } else if (packed && verdict === "MALICIOUS") {
    threatType = "Packed Ransomware / Crypter";
  } else {
    threatType = "Malicious Payload";
  }

  const result: ScanResult = {
    targetType: "file",
    target: name,
    score: finalScore,
    verdict,
    threatType,
    metadata: {
      "True File Type": magic.type,
      "Declared Extension": extension ? `.${extension}` : "none",
      Size: formatBytes(size),
      "Shannon Entropy": `${entropy.toFixed(2)} / 8.00`,
      "Magic Bytes": headerHex.slice(0, 16) || "—",
      "Engine Source": vt.engine,
      "SHA-256": sha256,
      Sampled: `${formatBytes(asNumber(raw.sampledBytes))}${raw.truncated ? " (truncated)" : ""}`,
    },
    checks,
    scannedAt: new Date().toISOString(),
    engine: vt.engine,
  };

  return Response.json(result);
}
