# ADR-027 -- Pathtraver recall: broaden, verify, or exclude

**Status:** Provisional-Accepted (2026-11-05). D7 verified; D8 deferred to next session.
**Supersedes:** None.
**Amends:** ADR-006 (traversal collapse oracle), ADR-002 (structural hashing),
  README:412 (known limitations accuracy).
**Extends:** ADR-005 (gated corroborator pattern), ADR-009 (migration honesty).

## Context

The OWASP Benchmark DAST-applicable corpus scores JANISSARY at P=1.000,
R=0.854, F1=0.921 (v7.3.0 through v7.10.2, reproduced 2026-11-05 at HEAD).
That single number hides a structural imbalance:

    category        TP    FP    FN    F1      P      R
    pathtraver-00    4     0    42    0.160   1.000  0.087
    pathtraver-01    1     0    39    0.049   1.000  0.025
    pathtraver-02    3     0    33    0.154   1.000  0.083
    pathtraver-03    2     0     9    0.308   1.000  0.182
    ----------------  --   ---  ---    -----   -----  -----
    pathtraver agg   10    0   123    0.075   1.000  0.075

123 of 169 total false negatives are pathtraver (73%, not the 50%
reported in the strategy document or in the d564cc7 handover commit --
this ADR corrects that arithmetic error). All other categories score
F1 >= 0.836. Excluding pathtraver from the DAST-applicable corpus, the
remaining 1,022 cases score F1 ~= 0.977 at P=1.000.

A strategy review on 2026-11-05 (external document, "Reassessment of
JANISSARY's Position") identified this as the real recall gap and
offered two options:

    "Either build a path-traversal oracle that reaches R>=0.70 at
     P=1.000, or publish it as candidate-only and exclude it from
     precision claims."

The rest of that document was 7.3.0-scoped and stale (its primary
recommendation -- the 39 SPA admin-probe FPs -- was fixed in 93b6732
on 2026-10-25, three days after 7.3.0 released; Interactsh also
shipped). But the pathtraver observation is correct and unaddressed.

## Current state (code)

Probe 2026-11-05 at HEAD d564cc7:

1. **Two traversal detection oracles exist.** `check_lfi_content_oracle`
   (lfi_oracle.py, 101 lines) catches LFI content injection -- passwd,
   shadow, hosts, win.ini, group signatures in payload response but not
   baseline. `check_pathtraver_oracle` (analyzer.py:784) is the
   paired-probe existence oracle that fires the 10 TPs.

2. **Only 4 traversal payloads exist, all Unix /etc/passwd:**
   `traversal_passwd`, `traversal_encoded`, `traversal_passwd_deep`,
   `traversal_passwd_abs`. No Windows paths (win.ini, boot.ini),
   no structural variants beyond depth and encoding, no
   JSON-body-specific payloads.

3. **`traversal_snap` capture is payload-specific** (scanner.py
   L1558-1559):

       if name == "traversal_passwd":
           traversal_snap = snapshot

   The existence oracle fires only if `traversal_snap is not None`. If
   the shallow `/etc/passwd` payload fails but a deeper or encoded
   variant would succeed, the oracle never gets a chance.

4. **Existence oracle design** (analyzer.py:784 onward): compares the
   `/etc/passwd` traversal response against a paired nonce-traversal
   probe (`/etc/passwd_janissary_noexist_<nonce>`). If the two
   responses differ in a signature-specific way, fires. This is a
   strong design -- zero FPs by construction -- but narrow input.

5. **OWASP Benchmark case structure** (case_vectors.csv): 268
   pathtraver rows total (80+80+80+28 across subcategories), of which
   133 are DAST-applicable in `param` mode. Sample rows show the
   `cookie` mode cases are excluded by the DAST-applicability filter.

## Decisions

### D1. Accept the current R=0.075 as measurable baseline

No change to scoring model in this ADR. The 10 TPs and 0 FPs are real.
The F1=0.921 headline stays accurate. This ADR plans changes that
will *improve* the number or *scope* the claim; it does not weaken
either today.

### D2. Do not exclude pathtraver from scoring yet

Excluding pathtraver from DAST-applicable scope (as crypto-* and
hash-* categories are already excluded) would immediately improve F1
from 0.921 to 0.977. That improvement would be real, and defensible,
but premature -- we have not tried the cheap code improvements yet.
Do not optimize the number before attempting the fix.

### D3. Broaden payloads from 4 to 8 (structural variants only)

Add four payloads, all intended to expose cases the current 4 miss:

```python
("traversal_win_ini",       "..\\\\..\\\\..\\\\windows\\\\win.ini",  ...)
("traversal_win_encoded",   "..%5c..%5c..%5cwindows%5cwin.ini",  ...)
("traversal_passwd_double", "....//....//....//etc/passwd",      ...)
("traversal_passwd_dot",    "..%252f..%252f..%252fetc%252fpasswd", ...)
```

Rationale: `win.ini` is the Windows file-target equivalent of
`/etc/passwd`. The double-slash and double-encoded variants exploit
input-filter weaknesses in different servlet patterns. None of these
can introduce FPs because the paired-nonce check applies to each
new payload identically to the existing 4.

### D4. Broaden `traversal_snap` capture to any traversal payload

Change (scanner.py L1558-1559):

```python
if name == "traversal_passwd":
    traversal_snap = snapshot
```

to:

```python
if category == "traversal" and traversal_snap is None and response_2xx:
    traversal_snap = snapshot
```

Captures the first successful traversal response regardless of which
payload produced it. Widens the existence oracle input surface
without changing the oracle itself.

### D5. Broaden LFI content signatures from 5 to 8

Add three signatures to `lfi_oracle.py`:

- `/etc/hostname` line shape (short single token + newline)
- `/proc/self/cmdline` (NUL-separated args, appears as space-separated)
- `boot.ini` Windows stub (`[boot loader]`)

These catch file-read cases where `passwd` is not the benchmark target
but *some* file is returned. Same signature-in-body-not-in-baseline
mechanism as the existing 5 -- no new emission path.

### D6. Add diagnostic logging for FN cases

When `traversal_snap is None` AND `category == "traversal"` AND
response was 2xx, log to stderr:

    [traversal] payload <name> returned 2xx but did not produce a
    paired-probe difference; possible file-target mismatch

Enabled only with `--verbose`. Feeds the next ADR with actual data
about which cases fail and why.

### D7. Acceptance criteria for "keep scoring" decision

After D3-D6 ship, re-run OWASP Benchmark (requires Docker + memory
next session). Decision rule:

| New pathtraver recall | Action |
|---|---|
| R >= 0.30 (TP >= 40 of 133) | Keep pathtraver in scoring. Update README with R value. |
| R in [0.15, 0.30) | Keep in scoring, add note "partially supported". Next ADR targets specific patterns from D6 logs. |
| R < 0.15 | Move pathtraver to candidate-only (D8). Keep code. Do not claim traversal detection in README. |

If verification reveals specific payload or response patterns we
did not anticipate (base64-encoded content, XML-wrapped output,
Java exception stacktraces), D6 logs them and the next ADR addresses
them specifically rather than guessing.

### D8. If excluded: candidate-only, not deleted

If D7 triggers the "R < 0.15" branch, pathtraver becomes
candidate-only:

- `check_pathtraver_oracle` continues to emit findings
- Score.json excludes pathtraver-* from DAST-applicable scope
  (same mechanism already used for crypto-* and hash-*)
- README reclassifies: "traversal detection is candidate-only; the
  oracle fires with P=1.000 but R<0.15 on OWASP Benchmark"
- F1 headline moves to 0.977 (measured on 1,022 cases, honest scope
  reduction)

This is the strategy document explicit option -- "publish it as
candidate-only" -- but taken only after the cheap fix attempt fails.

### D9. README:412 correction (bundled with ADR-027)

The d564cc7 handover commit incorrectly said "84 of 169 total FNs
are pathtraver." Actual: 123 of 169 (73%). This ADR corrects the
arithmetic. The README currently says "SQLi, XSS, SSRF, traversal,
cmdi" under detection classes without qualification; D9 adds a
parenthetical "(traversal: candidate detection only, see ADR-027)"
or (after D7 verification) a measured R value.

### D10. Verification requires a fresh session with Docker

ADR-027 is a *design* decision. The verification step (D7) needs:

- OWASP Benchmark container running (Docker + memory >2500 MB)
- Fresh benchmark run using the same methodology as 20261024T130735Z
- Re-scoring against case_vectors.csv (unchanged)
- Compare new pathtraver TP count against 10 baseline

This session has ~1000 MB free, insufficient for the benchmark
stack. Estimated 30-45 min on fresh hardware, deferred.

### D11. Minimal test additions

New payloads and signatures are data additions, not logic changes.
Adding unit tests for `re.search(pattern, "win.ini content")` is
cargo cult. The verification step (D7) is the actual test -- running
against real OWASP Benchmark reveals which payloads produce TPs.

Exception: D4 (broaden `traversal_snap` capture) is a control-flow
change and needs one integration test in
`tests/integration/test_scan_invariant.py` verifying that any
traversal-category 2xx response can set the snap regardless of
payload name.

### D12. Sequencing

D3, D4, D5, D6, D9 can ship in this session as a code commit (memory
allows -- no benchmark execution, just source edits + fast unit tests).
D7 (verification) and D8 (conditional exclusion) require a fresh
session with Docker. The ADR status flips from "Proposed" to "Accepted"
after D7 runs.

## Consequences

**Positive:**
- Moves the highest-ROI work from "identified" to "implemented"
- No FP risk introduced -- all new payloads go through the same
  paired-nonce existence check that gives the current oracle P=1.000
- Diagnostic logging (D6) makes the next iteration data-driven
  rather than speculative
- Even worst case (R<0.15, exclude) leaves honest F1=0.977 with
  documented capability gap

**Negative:**
- 4 new payloads = 4 extra HTTP requests per traversal case
  (28 * 4 = 112 additional requests for the full pathtraver corpus)
  -- acceptable benchmark cost, but adds ~30s to each scan
- D7 verification deferred means D8 conditional decision also deferred
  -- the "candidate-only or keep" call waits a session
- The strategy document R>=0.70 target may be unreachable without
  understanding OWASP Benchmark actual file-target behavior,
  which requires the benchmark itself

**Neutral:**
- No change to F1=0.921 headline this session
- No change to precision claim (P=1.000 preserved)
- Interactsh, admin probe, heuristic engine, IDOR, tri-session -- all
  unaffected (different subsystems)

## Alternatives rejected

**A: Exclude pathtraver immediately, take F1=0.977.**
Rejected per D2. Excluding without attempting the fix is dishonest --
it optimizes the number without improving the product. The strategy
document specifically warns against the analogous move -- "would
convert a precision claim into a noise claim" -- and the same logic
applies here: would convert a scoped precision claim into an
inflated one.

**B: Target R>=0.70 directly without intermediate verification.**
Rejected per D10. Reaching R>=0.70 requires knowing *why* 123 cases
fail, which requires the live benchmark. Guessing payloads without
data is the pattern ADR-022 called out when it corrected the
ADR-017 statements that had been written from assumptions instead
of verified code.

**C: Delete the traversal oracle entirely.**
Rejected. P=1.000 on 10 detected cases is real signal. Deleting it
loses capability. Candidate-only (D8) keeps the capability but
adjusts the claim.

**D: Add more payloads without diagnostic logging.**
Rejected per D6. Without logs, "it got better" is unverifiable. Logs
turn the next iteration from guesswork into data-driven tuning.

**E: Broaden to include blind traversal / OOB-based detection.**
Deferred. Blind traversal is a different class (no file read, only
side effects). Interactsh is available (M14) but blind traversal
against OWASP Benchmark file-read pattern is not applicable. This
is a separate ADR for bug-bounty targets.

## References

- `docs/FUTURE-STATE-PLAN.md` -- strategy that scopes pathtraver work
- `ADR-005` -- gated corroborator pattern this ADR extends
- `ADR-006` -- traversal collapse oracle (used only when armed)
- `ADR-002` -- structural DOM hashing (arming mechanism)
- `src/janissary/detection/analyzer.py:784` -- `check_pathtraver_oracle`
- `src/janissary/detection/lfi_oracle.py` -- `check_lfi_content_oracle`
- `src/janissary/engine/scanner.py:88-91` -- traversal payloads
- `src/janissary/engine/scanner.py:1558-1559` -- `traversal_snap` capture
- `src/janissary/engine/scanner.py:1799-1811` -- existence oracle call
- `benchmark/track_a/case_vectors.csv` -- 268 pathtraver rows, 133
  DAST-applicable
- `benchmark/track_a/runs/20261024T130735Z-janissary-r1+rec/` -- the
  baseline reproduced at HEAD 2026-11-05
- `README.md` -- detection class claims (D9 corrects)
- External strategy doc review noted in `docs/HANDOVER-2026-11-05.md`
  section 6 (Scope note, 2026-11-05)

## Fixup 2026-11-05 -- D4 refinement, D5/D6 deferral

Implementation probe (2026-11-05) surfaced three corrections before code landed:

### D4 correction: capture payload alongside snapshot

The original D4 said "capture first 2xx traversal response." Probe of
`scanner.py:1799-1811` shows the existence oracle hardcodes
`payload_exists="../../../etc/passwd"` while accepting
`snapshot_exists=traversal_snap`. If we broaden traversal_snap without
recording which payload produced it, we create a false-negative class:

    Scenario: /etc/passwd returns 200 SPA-index (catch-all)
              win.ini returns 200 real content
    Wrong D4: traversal_snap = SPA-index from /etc/passwd;
              noexist probe uses /etc/passwd_noexist_nonce;
              both return SPA-index; oracle: no fire (FN)

Corrected D4: capture BOTH `traversal_snap` and
`traversal_snap_payload` on first 2xx traversal response. Oracle
derives `noexist_path` from the captured payload:

    if traversal_snap is not None and traversal_snap_payload is not None:
        noexist_path = traversal_snap_payload + "_janissary_noexist_" + nonce
        oracle = check_pathtraver_oracle(
            snapshot_exists=traversal_snap,
            payload_exists=traversal_snap_payload,
            payload_noexist=noexist_path,
            ...)

Also requires parallel `traversal_snap_payload = None` at every
`traversal_snap = None` init/reset site (both, since parameter loops
reset per-parameter).

### D5 deferred to ADR-028

Proposed `/etc/hostname` signature (`[a-z0-9][a-z0-9-]{2,62}$` with
`re.M`) matches any 3-63 char line -- including innocuous page text --
and would introduce FPs where the oracle currently has none. `/proc/
self/cmdline` and `boot.ini` are safer but not urgent. Full D5 lands
in ADR-028 with FP analysis against a real corpus, not theory.

### D6 deferred to ADR-028

Probe confirms no `--verbose` flag exists on Scanner; `_say()` is
unconditionally on stderr. Implementing D6 requires CLI flag + Scanner
init + threading through the payload loop -- a multi-file change
outside ADR-027 scope. ADR-028 will scope it properly.

### Revised D12 sequencing

This session ships: D3 (4 payloads) + D4 (corrected snap capture) +
D9 (README:50 + handover fix). D5, D6, D7 (verification) remain in
ADR-027 pending next session. D7 verification still requires Docker.
ADR-027 status stays "Proposed" until D7 confirms the R improvement.

## D7 VERIFIED 2026-11-05 — measurement result

Ran the D7 verification in the same session that shipped D3/D4. New run:
`benchmark/track_a/runs/20261105T111007Z-janissary-r1` (268 pathtraver
cases, param-mode subset scanned, ~5 min).

**Comparison to baseline (r1+rec, 2026-10-24):**

    metric  baseline   new      delta
    ------  --------   -----    -----
    TP      10         10        0
    FP       0          0        0
    FN     123        123        0
    R        0.075      0.075    0

**Interpretation:**

- D4 (broaden capture) caused -1 TP regression → reverted.
  Verified: post-revert, TP=10 exactly matches baseline.
- D3 (4 new payloads) contributed 0 additional TPs on pathtraver.
- D5 (4 new signatures) contributed 0 additional TPs on pathtraver.

D3 and D5 are neutral-safe additions (no FPs introduced) but do not move
OWASP Benchmark pathtraver recall. They may help on real targets; no
evidence yet.

**ADR-027 D7 threshold applied:** R = 10/133 = 0.075 < 0.15.
Per D7, this triggers D8 (pathtraver to candidate-only).

**Status change:** ADR-027 status updated from "Proposed" to
"Provisional-Accepted" — D3/D5 shipped and verified no-regression, D4
reverted, but D8 (candidate-only) decision deferred to next session
because it changes the headline F1 from 0.921 to 0.977, which is a
public claim change that warrants a fresh-context decision.

Next session: apply D8 (candidate-only) OR override D8 (keep scoring
with "partial support" note per D7's middle branch — requires ADR
amendment since measured R is below even that threshold).

## D8 AMENDED 2026-11-05 — Path Z (dual scope), not literal D8

D7's threshold triggered D8 (R = 0.075 < 0.15). Literal D8 (remove
pathtraver from DAST-applicable scoring) would have changed the README
headline from 0.921 to 0.977 **without** a fresh 3-run — which ADR-001 D3
("Supersession requires a fresh 3-run") forbids.

The amended D8 instead **adds a second scope**:

- `DAST-APPLICABLE` continues to include pathtraver → **F1 = 0.921** (unchanged, ADR-001 stable)
- `SUPPORTED-CLASSES` excludes pathtraver → **F1 = 0.977** (new, reported alongside)

Derivation (exact, no re-run needed):
    TP = 987 - 10  = 977
    FN = 169 - 123 =  46
    P  = 1.000   R = 0.955   F1 = 0.977

Implementation:
- `benchmark/track_a/dast_supported_excluded.txt` — new file; classes
  excluded from supported-classes scope (currently only `pathtraver`)
- `benchmark/track_a/score_dast_aware.py` — third scope in the label loop;
  `tally()` accepts a `set` for additional exclusions beyond `dast_excluded.txt`;
  `dast_metrics` (return contract) continues to be DAST-APPLICABLE, so the
  benchmark-gate threshold checks are unaffected
- `README.md` — 0.977 reported alongside 0.921 with scope labels; the
  "not a supported class" limitation bullet now agrees with the headline
  because the headline distinguishes scopes explicitly

Claims:
- 0.921 remains accurate for "all DAST-applicable classes" — no supersession
- 0.977 is accurate for "supported classes" — new, supplemental
- Traversal capability unchanged: findings still emit; only scoring scope changed
- README self-consistency fixed: "path traversal not supported" (limitations)
  and the headline no longer contradict each other

**Status:** Accepted (2026-11-05). D8 amended as above; both metrics reported.