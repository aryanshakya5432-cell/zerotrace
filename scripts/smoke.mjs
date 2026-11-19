// End-to-end smoke test against a running dev server (npm run dev).
// Mirrors the browser-side feature extraction in src/lib/file-slice.ts.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename, join } from "node:path";

const BASE = process.env.ZT_BASE ?? "http://localhost:3000";

const entropy = (bytes) => {
  const counts = new Array(256).fill(0);
  for (const byte of bytes) counts[byte] += 1;
  let value = 0;
  for (const count of counts) {
    if (!count) continue;
    const p = count / bytes.length;
    value -= p * Math.log2(p);
  }
  return Math.round(value * 100) / 100;
};

const stringsOf = (bytes) =>
  (new TextDecoder("latin1").decode(bytes).match(/[\x20-\x7E]{4,}/g) ?? [])
    .join(" ")
    .slice(0, 24000);

const slice = (path) => {
  const buffer = readFileSync(path);
  const head = buffer.subarray(0, 64 * 1024);
  return {
    name: basename(path),
    size: buffer.length,
    mimeType: "application/octet-stream",
    sha256: createHash("sha256").update(buffer).digest("hex").toUpperCase(),
    headerHex: buffer.subarray(0, 8).toString("hex").toUpperCase(),
    strings: stringsOf(head),
    entropy: entropy(buffer.subarray(0, 1024 * 1024)),
    sampledBytes: buffer.length,
    truncated: false,
  };
};

const post = async (path, body) => {
  const response = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json();
  return { status: response.status, payload };
};

const line = (label, { status, payload }) => {
  if (status !== 200) {
    console.log(`FAIL ${label} → HTTP ${status} ${JSON.stringify(payload)}`);
    return;
  }
  console.log(
    `OK   ${label} → ${payload.score}/100 ${payload.verdict} · ${payload.threatType} · ${payload.checks.filter((c) => c.status === "FLAGGED").length} flagged`,
  );
};

const urls = [
  ["safe url      ", { url: "https://github.com" }],
  ["phishing url  ", { url: "http://192.168.1.5/sbi-kyc-verify@secure-login.xyz" }],
  ["shortener     ", { url: "https://bit.ly/3xYzAbC" }],
  ["typosquat     ", { url: "https://amaz0n-login-verify.secure-update-bank.com/kyc" }],
  ["raw ip        ", { url: "http://45.13.220.9/payload" }],
];

for (const [label, body] of urls) {
  line(label, await post("/api/scan-url", body));
}

for (const file of [
  "test-samples/project_notes.txt",
  "test-samples/SBI_Statement_2026.pdf.exe",
  "test-samples/keyboard_driver.bin",
]) {
  line(basename(file).padEnd(30), await post("/api/scan-file", slice(join(process.cwd(), file))));
}

const bad = await post("/api/scan-file", { name: "x" });
console.log(`OK   validation    → HTTP ${bad.status} ${bad.payload.error}`);
