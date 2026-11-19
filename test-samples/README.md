# ZeroTrace demo samples

All four bytes of these files are synthetic. There is **no EICAR string** and no executable code,
so Windows Defender should leave them alone. They exist only to exercise the static engine during a
live presentation.

| File | What the engine sees | Expected verdict |
| --- | --- | --- |
| `project_notes.txt` | ASCII text, entropy ≈ 4.91, no magic bytes, no APIs | `0 / 100` · `SAFE` · Clean / Benign File |
| `SBI_Statement_2026.pdf.exe` | `4D5A` MZ header, `.pdf.exe` double extension, entropy `7.68`, `VirtualAlloc` / `WriteProcessMemory` / `CreateRemoteThread`, `powershell -enc` | `100 / 100` · `MALICIOUS` · Trojan / Process Injector |
| `keyboard_driver.bin` | Text manifest, entropy ≈ 4.83, `SetWindowsHookEx` + `GetAsyncKeyState` | `30 / 100` · `SUSPICIOUS` · Spyware / Keylogger Hook |

## Regenerate

```powershell
npm run samples
```

The generator recreates the entropy-`7.68` payload deterministically by drawing bytes from a
205-symbol alphabet (`log2(205) ≈ 7.68`). The SHA-256 signature shipped in
`src/app/api/scan-file/route.ts` matches the committed copy; regenerated copies are still caught by
the filename signature and by the behavioural checks.

## Scan them through the API

```powershell
npm run dev            # terminal 1
npm run smoke          # terminal 2
```
