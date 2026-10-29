# WORKFLOW — Verification and Execution Patterns

This document records process patterns that emerged from a multi-session Track C
measurement workstream. Each pattern addresses a specific failure that produced
a correction commit during that session. They are not theoretical.

## 1. Verify before you claim

**Rule:** No claim into `docs/`, no commit message, and no amendment entry
asserts a fact until the command that verifies that fact has run and its
output has been pasted back.

**What went wrong:** During the VAmPI workstream, four correction commits were
needed because claims were written into commits before the corresponding
verification was performed. Examples:

- `3f39ae6` claimed "measured first run: TP=0 FP=0 FN=0 TN=4" on VAmPI. The
  runner had a hardcoded `--app` choices list; VAmPI was never actually
  scanned. The numbers were trivially true on an empty findings set.
- `86c3116` claimed the VAmPI crash "reproduces when janissary is invoked
  directly". Three direct invocations immediately showed it did not.
- Commit `7023cf0` corrected the earlier over-claim about Nextcloud's
  `/` trial: three clean nulls + one abort-on-empty-response is not
  the same as four clean nulls.

**How to apply:** For any claim of the form "X works" / "X crashes" / "X is
vulnerable" / "X measured Y" — the command that produces the evidence must
run first, its output must be shown, and only then is the claim committed.

The specific failure mode this prevents: writing a commit message that says
"see score.json" when score.json was never created because the score command
silently failed.

## 2. File-based execution for complex commands

**Rule:** Any command over ~30 lines, or containing a `try`/`finally` block,
or containing a here-string, is written to a `.ps1` file first, parsed for
syntax, then executed from the file.

**What went wrong:** Throughout the session, direct-terminal execution of
multi-line scripts produced parser failures at exactly these boundaries:

- `} finally {` on its own line after a `try` block was parsed as two
  statements, not one.
- Here-strings containing `$(...)` or single quotes inside `try` blocks
  were mangled — the block boundaries ended up wrong and a `git commit`
  ran before the `git add` it was supposed to follow.
- A single stray `)` (leftover from a parenthesized concatenation pattern
  that had been removed) closed an array-literal expression early. The
  PowerShell parser reported "missing `}`" at a line 200 lines later,
  pointing at the wrong construct.

**How to apply:** Write the script in a single command that has no try/finally,
no here-strings containing user data, and no concatenation spanning multiple
lines. Run the syntax parse check inline before writing:

    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseInput(
        $content, [ref]$null, [ref]$errors) | Out-Null
    if ($errors.Count -eq 0) { ... } else { ... report each error ... }

Then run the file as a separate command:

    & 'C:\path\to\script.ps1' 2>&1 | Out-File -FilePath 'C:\path\to\out.txt' -Encoding UTF8
    Get-Content -LiteralPath 'C:\path\to\out.txt' -Raw

## 3. Out-File with explicit path, never Tee-Object with $env:TEMP

**Rule:** Output capture uses `Out-File` with an explicit absolute path under
the project directory. Never `Tee-Object`. Never `$env:TEMP`.

**What went wrong:** `Tee-Object -FilePath "$env:TEMP\out.txt"` succeeded in
writing the file, but a subsequent `Get-Content "$env:TEMP\out.txt"` in a new
command could not find it. `$env:TEMP` on this system resolves to a short path
(`C:\Users\M5E60~1\AppData\Local\Temp`) in some contexts and a long path
(`C:\Users\M5 E60\AppData\Local\Temp`) in others. Same folder, different
resolution, and PowerShell's handling of the tilde-collapsed path is not
consistent.

**How to apply:**

    & '.\script.ps1' 2>&1 | Out-File -FilePath 'C:\path\under\project\out.txt' -Encoding UTF8
    Get-Content -LiteralPath 'C:\path\under\project\out.txt' -Raw

The `-LiteralPath` on retrieval prevents wildcard expansion. The explicit
absolute path prevents env-var resolution surprise.

## 4. Cleanup before port check

**Rule:** In any "onboard a containerized app" script, the sequence is
remove-stale-container → check-port → pull → start. The port check comes
*after* cleanup, not before.

**What went wrong:** The first bWAPP onboarding script (`cmd-51`) put the port
check first. A leftover container from a prior attempt held port 8081. The
script aborted at the port check before the cleanup step could free the port.
Re-running the script did the same thing, forever.

**How to apply:** Every container onboarding script starts with:

    docker rm -f <container-name> 2>&1 | Out-Null
    # then
    check port

Not the other way around.

## 5. Three distinct outcomes: clean-null / abort / crash

**Rule:** When a scanner invocation produces zero findings, distinguish three
cases: (a) the scan completed and found nothing, (b) the scan aborted on
empty body or a defensive check, (c) the process crashed with a non-{0,1}
exit code.

**What went wrong:** The VAmPI crash (`exit 0xC0000005`) and the Nextcloud
`/` abort (`exit 2, "aborted: empty body"`) both produced zero findings. The
scorer counts zero findings as TN regardless of why. For VAmPI's crash, the
report initially said "4 clean TN" — one of which had actually crashed before
completing a scan. For Nextcloud, the report initially said "4 clean TN" — one
of which had aborted.

**How to apply:** Read the runner's per-case output. If any trial shows an exit
code other than 0 or 1, or shows `[!] aborted:` in stderr, do not count it as
a clean null result. It goes in the "abort-TN" bucket, which is documented
separately from "clean TN" in the amendment.

The scoring model may still count it as TN — that is a separate decision from
whether the trial completed. The count in the amendment log must reflect
which trials actually completed a differential scan.

## 6. Corrections are forward commits, never amendments

**Rule:** When a prior commit is discovered to have made a false claim, the
correction goes in a *new* commit that supersedes the earlier one. History
is not rewritten with `git reset`, `git rebase`, or `git commit --amend`.

**What went wrong:** Nothing went wrong — this rule was followed throughout.
But it's worth recording because the temptation to "just amend the message"
is real when the false claim is fresh.

**How to apply:** Commit messages and amendment entries remain in the history
even when they turn out to be wrong. The correction commit's message begins
with "fix(...)" and its body explicitly references the commit it supersedes.
Future readers can follow the chain: what was claimed, when, what the actual
evidence was, when the correction landed.

Four corrections in the VAmPI workstream (`3f39ae6 → 6f5a37c → 86c3116 →
490b667`) are all in the log, all traceable, none deleted. That is the
correct shape.

## 7. Verify shape before committing measurement results

**Rule:** Any commit that adds a `score.json` or amendment entry asserting a
measurement has a shape check first. The shape check verifies expected counts
before `git commit` is reached.

**What went wrong:** Not a specific failure, but the pattern prevented several.
In `cmd-43` (VAmPI) the shape check would have caught that TP and FP were both
zero on a run that was supposed to have findings. In `cmd-49` (Juice Shop) the
shape check caught the `tp=1 fn=1` anomaly before committing.

**How to apply:** Every onboarding/measurement script ends its pre-commit
verification section with:

    if ($s.cases -ne 4)       { fail }
    if ($s.vuln_cases -ne 2)  { fail }
    if ($s.safe_cases -ne 2)  { fail }
    if ($s.findings -eq 0)    { fail }  # where findings expected
    if (($s.tp + $s.fp + $s.fn + $s.tn) -ne 4) { fail }

Then only commit if the shape check passed. The commit path is guarded;
`git reset` on failure.

## 8. When you're wrong, write it down

**Rule:** If a command's output contradicts a claim in a prior commit or a
prior amendment entry, the correction goes into the amendment's log.
Not into a chat message. Not into a memory. Into the file that future
readers will consult.

**What went wrong:** Nothing specific. The pattern was followed consistently
throughout the VAmPI workstream, and the result is that `docs/AMENDMENT-24.md`
contains a complete and honest chain of what was claimed, what was discovered,
and what was corrected — including four commits' worth of retractions.

**How to apply:** The amendment log is append-only. Each entry that corrects
a prior one includes:
- A reference to the specific commit or entry being corrected
- What was claimed
- What was discovered (with evidence)
- What the corrected statement is
- Whether the correction invalidates a previously published number

Future sessions reading the amendment get the honest version of what
happened, not the optimistic one.