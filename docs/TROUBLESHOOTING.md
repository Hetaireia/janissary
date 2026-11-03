# Troubleshooting

## Banner shows "ΓÇö" instead of "—" on Windows

**Symptom:** Running any JANISSARY subcommand prints a banner like
`JANISSARY ΓÇö differential DAST` instead of `JANISSARY — differential DAST`.
The three-character sequence `ΓÇö` appears wherever an em-dash should be.

**Cause:** The terminal's output codepage is a legacy DOS/Western codepage
(CP437, CP850, CP1252) that cannot render U+2014 (em-dash). JANISSARY's
source is UTF-8 and Python emits correct UTF-8 bytes; the mojibake happens
entirely at the terminal's decode step. Verify with:

    [Console]::OutputEncoding

If this reports `ibm437`, `ibm850`, `windows-1252`, or similar, that is
the display path, not the program. Confirmed on 2026-11-02: after
`[Console]::OutputEncoding = [System.Text.Encoding]::UTF8` and
`chcp 65001`, the same scan rendered `JANISSARY — differential DAST`
correctly with no code change.

**Fix (permanent, current PowerShell session):**

    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8

**Fix (permanent, all new sessions via `$PROFILE`):**

Add to `$PROFILE`:

    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8

**Fix (per-invocation, any shell):**

    chcp 65001

**Why this is not a JANISSARY bug:** the bytes written by the program are
correct UTF-8. The rendering failure is entirely in the terminal. Changing
JANISSARY's source to ASCII to work around one legacy codepage would
degrade output on the UTF-8 terminals that are now the default on Windows
10/11, macOS, and Linux.

**Reporting:** if `[Console]::OutputEncoding` is already UTF-8 and you
still see mojibake, that is a different bug — open an issue with the
output of `[Console]::OutputEncoding` and
`python -c "import sys; print(sys.stdout.encoding)"`.

## Intermittent 0xc0000005 / 0xc000001d crashes across unrelated CLI processes

**Symptom:** Windows Application Event Log shows repeated crash events
(Provider: Application Error, Event ID 1000) for multiple unrelated
executables within hours of each other — `git.exe`, `python.exe`,
`pwsh.exe`, `cscript.exe`, `schtasks.exe`, `curl.exe`, `opera.exe`,
`docker.exe`, `taskhostw.exe`, `LogonUI.exe`, `WerFault.exe`. Two
signatures dominate:

- `Exception code: 0xc0000005` (STATUS_ACCESS_VIOLATION), `Faulting
  module: unknown`, `StackHash_*`. Fault offsets consistently end in
  `44d0` across different processes.
- `Exception code: 0xc000001d` (STATUS_ILLEGAL_INSTRUCTION),
  `Faulting module: ntdll.dll`, fault offset `0x161d73`.

**Diagnosis 2026-11-02/03 (JANISSARY dev machine):** Windows 11 25H2
build 26200, Intel i5-1335U, BIOS Insyde F.17 (2026-03-24), KB5127690
installed 2026-10-14. Full WER dump analysis on `AppCrash_git.exe`
reports: crash occurs in the Windows loader phase — before the
application's entry point runs. `LoadedModule` list contains only
standard Windows modules and the application's own bundled DLLs. No
third-party injection DLL. AV inventory: Windows Defender only. HVCI
off. No pending reboot.

**Working conclusion:** OS-level instability on build 26200, plausibly
aggravated by the October 2026 cumulative update (KB5127690). Not a
JANISSARY bug and not a git-for-Windows bug — same signature hits
unrelated third-party binaries and Windows inbox tools.

**Recommended repair sequence (OS-level, highest value first):**

1. `DISM /Online /Cleanup-Image /RestoreHealth` then `sfc /scannow` in
   elevated PowerShell. Repairs Windows component store and system files.
2. `chkdsk C: /f` (requires reboot). Filesystem integrity.
3. If crashes persist: Windows Memory Diagnostic (`mdsched.exe`), two
   full passes. Rules in/out RAM instability.
4. If crashes persist: BIOS update to latest from OEM (check microcode
   bump). Mobile 13th-gen is less prone to Intel Vmin Shift than
   desktop, but the update is cheap.
5. If crashes persist: consider uninstalling KB5127690 via Settings →
   Windows Update → Update history → Uninstall updates.

**Workaround for this repo (unaffected by the crash):** when `git add`
no-ops silently or crashes, stage via:

    git hash-object -w --path=<file> -- <file>
    git update-index --add --cacheinfo "100644,<hash>,<file>"

`--path` is required — applies `.gitattributes` filters (LF/CRLF
normalization). `--add` is required for files not already tracked;
omit it for modifications.

**Observed during:** FN-16 follow-up work, 2026-11-02/03.
