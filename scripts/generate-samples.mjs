// Regenerates the harmless live-demo samples in ./test-samples
// No real malware, no EICAR string — just markers the ZeroTrace engine looks for.
import { randomInt } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = join(root, "test-samples");
mkdirSync(outDir, { recursive: true });

/* ------------------------------------------------------------------ 1. clean */
const notes = `ZeroTrace — Demo Test Notes
================================

Project: Unified URL & Malware Threat Scanner
Owner:   Security Operations (demo tenant)
Date:    2026-02-14

Meeting notes
-------------
- Weekly triage review moved to Thursday 10:00 IST.
- The scanner hashes files in the browser before upload, so the 4.5 MB
  serverless body limit is never reached.
- URL checks run DNS and TLS probes with a 3 second ceiling.
- Reminder: rotate the staging API keys before the customer demo.

TODO
----
[x] Bento-grid results layout
[x] Three one-click demo targets
[ ] Add PDF report export
[ ] Wire the ticketing webhook

This file is intentionally boring. It should score 0 / SAFE.
`;

/* -------------------------------------------------------------- 2. payload */
const trojanText = [
  "MZ",
  "This program cannot be run in DOS mode.",
  "",
  "SBI Account Statement 2026 - secure viewer bootstrap",
  "VirtualAlloc WriteProcessMemory CreateRemoteThread",
  "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
  "NtUnmapViewOfSection QueueUserAPC LoadLibraryA GetProcAddress",
  "This sample is synthetic and harmless. ZeroTrace demo only.",
  "",
].join("\r\n");

// 205 distinct byte values -> Shannon entropy ~= log2(205) ~= 7.68 bits/byte.
const ALPHABET_SIZE = 205;
const padding = Buffer.alloc(52 * 1024);
for (let i = 0; i < padding.length; i += 1) {
  padding[i] = 24 + randomInt(0, ALPHABET_SIZE);
}

const trojan = Buffer.concat([Buffer.from(trojanText, "latin1"), padding]);

/* -------------------------------------------------------------- 3. spyware */
const driver = `; keyboard_driver.bin — synthetic driver manifest (harmless)
[driver]
name = zt_keyboard_filter
description = Demo keyboard filter used to exercise the spyware heuristic

[imports]
user32.dll!SetWindowsHookExA
user32.dll!GetAsyncKeyState
user32.dll!GetKeyboardState
user32.dll!MapVirtualKeyA

[notes]
No executable code is present. These API names exist only so the ZeroTrace
signature engine can classify the sample as a keylogger hook.
`;

const entropy = (buf) => {
  const counts = new Array(256).fill(0);
  for (const byte of buf) counts[byte] += 1;
  let value = 0;
  for (const count of counts) {
    if (!count) continue;
    const p = count / buf.length;
    value -= p * Math.log2(p);
  }
  return value;
};

writeFileSync(join(outDir, "project_notes.txt"), notes, "utf8");
writeFileSync(join(outDir, "SBI_Statement_2026.pdf.exe"), trojan);
writeFileSync(join(outDir, "keyboard_driver.bin"), driver, "utf8");

console.log("Samples written to", outDir);
console.log("trojan entropy:", entropy(trojan).toFixed(2));
console.log("driver entropy:", entropy(Buffer.from(driver, "latin1")).toFixed(2));
console.log("notes entropy :", entropy(Buffer.from(notes, "latin1")).toFixed(2));
