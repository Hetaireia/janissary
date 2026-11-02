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
