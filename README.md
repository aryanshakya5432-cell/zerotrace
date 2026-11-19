# ZeroTrace — Unified URL & Malware Threat Scanner

A single-box SOC console that scans **either** a URL **or** a file — no tabs, no mode switching.
Built with Next.js 16 (App Router), TypeScript, Tailwind CSS 4 and `lucide-react`, and shaped to
deploy to Vercel without touching the 4.5 MB serverless request-body limit.

```
┌──────────────────────────────────────────────────────────────┐
│  OMNI-SCANNER                                                │
│  [ https://example.com/login            ] [ Scan Target ]    │
│  ─────────────── OR DROP A FILE ───────────────              │
│  [   drag & drop .exe .apk .pdf .zip .txt .bin   ]           │
│  [ Safe URL ] [ Phishing Trap ] [ Trojan Payload ]           │
└──────────────────────────────────────────────────────────────┘
```

## Why it is Vercel-safe

The browser reads the file locally and sends **only a compact JSON feature slice** to
`/api/scan-file`:

| Feature | Limit |
| --- | --- |
| SHA-256 digest | full sample via Web Crypto |
| Magic header | first 8 bytes (hex) |
| Printable strings | first 64 KB, capped at 24 KB of JSON |
| Shannon entropy | first 1 MB, 0–8 bits/byte |
| Sample ceiling | 64 MB (marked `truncated` beyond that) |

The raw file never leaves the browser, so the request body is kilobytes, not megabytes.

Both route handlers opt into the Node runtime with a **10 s** ceiling:

```ts
export const runtime = "nodejs";
export const maxDuration = 10;
```

Every outbound call (DNS, TLS, VirusTotal) is capped at **3000 ms** with `Promise.race`,
`AbortSignal.timeout` and a manual socket timer.

## Scoring model

| Score | Verdict | Colour |
| --- | --- | --- |
| `< 20` | `SAFE` | emerald |
| `20 – 49` | `SUSPICIOUS` | amber |
| `>= 50` | `MALICIOUS` | rose |

### URL engine — `/api/scan-url`

1. Domain vs. raw IP literal
2. `@` credential-redirection trap
3. URL length above 54 characters
4. Subdomain depth (> 2 dots) and hyphen abuse
5. Known shorteners (`bit.ly`, `tinyurl.com`, `t.co`, `goo.gl`, `rb.gy`, `cutt.ly`)
6. Phishing / typosquat tokens (`login`, `verify`, `kyc`, `update`, `bank`, `sbi`, `hdfc`, `paytm`, `g00gle`, `amaz0n`)
7. Live DNS A-record resolution (`node:dns/promises`)
8. Live HTTPS/TLS certificate validation (`node:tls`)

Returns `targetType`, `target`, `score`, `verdict`, `threatType`, `metadata` (Domain, Resolved IP,
Protocol, SSL Status, URL Length) and the full `checks` array.

### File engine — `/api/scan-file`

1. Known signature database (SHA-256 + filename families)
2. Magic bytes (`4D5A` PE, `7F454C46` ELF, `504B0304` ZIP/APK, `25504446` PDF) vs. extension spoofing
3. True file-type identification
4. Double-extension trap (`.pdf.exe`)
5. Shannon entropy above `7.2` (packed / encrypted)
6. Process-injection APIs (`VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`, …)
7. Spyware hooks (`SetWindowsHookEx`, `GetAsyncKeyState`, …)
8. Dropper / shell strings (`powershell -enc`, `cmd.exe`, `certutil`, …)
9. Optional VirusTotal v3 lookup — used only when `VIRUSTOTAL_API_KEY` is set, otherwise the local
   static engine answers instantly

Classifications: `Trojan / Process Injector`, `Spyware / Keylogger Hook`,
`Packed Ransomware / Crypter`, `Malicious Payload`, `Clean / Benign File`.

## Demo targets

Three one-click buttons live inside the scanner card:

| Button | Target | Expected |
| --- | --- | --- |
| Safe URL | `https://github.com` | `0` / `SAFE` |
| Phishing Link Trap | `http://192.168.1.5/sbi-kyc-verify@secure-login.xyz` | `100` / `MALICIOUS` / Phishing |
| Trojan / Payload | `SBI_Account_Statement_2026.pdf.exe` (synthetic slice) | `100` / `MALICIOUS` / Trojan |

`test-samples/` also contains three harmless drag-and-drop files:

| File | Expected |
| --- | --- |
| `project_notes.txt` | `0` / `SAFE` |
| `SBI_Statement_2026.pdf.exe` | Magic spoof + injection APIs → `MALICIOUS` / Trojan |
| `keyboard_driver.bin` | Hook APIs → `SUSPICIOUS` / Spyware |

Regenerate them any time (entropy target `7.68` is reproduced deterministically):

```powershell
node scripts/generate-samples.mjs
```

No EICAR string is used anywhere, so Windows Defender should leave the samples alone.

## Local development

```powershell
npm install
copy .env.example .env.local   # optional — add VIRUSTOTAL_API_KEY to enable v3 lookups
npm run dev                    # http://localhost:3000
npm run build                  # production build (Vercel parity)
npm run lint
```

## Deploy to Vercel

1. Push the folder to a Git repository.
2. Import it into Vercel — the framework preset is detected automatically.
3. Optional: add `VIRUSTOTAL_API_KEY` under **Project → Settings → Environment Variables**.
4. Deploy. No extra configuration, no blob storage, no file uploads.

## Layout

```
src/
├── app/
│   ├── api/scan-url/route.ts     # 8 heuristics + live DNS/TLS
│   ├── api/scan-file/route.ts    # 9 static checks + optional VT v3
│   ├── globals.css               # obsidian/emerald theme + animations
│   ├── layout.tsx
│   └── page.tsx                  # hero, scanner, bento results, pipeline
├── components/
│   ├── omni-scanner.tsx          # unified URL/file box + demo buttons
│   ├── results-bento.tsx         # 3-card bento dashboard
│   ├── score-ring.tsx            # animated 0–100 risk ring
│   └── pipeline-section.tsx      # 4-step architecture section
└── lib/
    ├── file-slice.ts             # in-browser hashing / entropy / strings
    ├── risk.ts                   # score → verdict thresholds
    └── types.ts
```

> Heuristic demo engine — intended for presentations and triage UX, not a sandbox replacement.
> Files are never stored or executed.
