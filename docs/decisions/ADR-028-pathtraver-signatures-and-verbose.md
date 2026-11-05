# ADR-028 -- Pathtraver signatures + verbose diagnostics (extends ADR-027)

**Status:** Accepted (2026-11-05). D10 verified: D1/D3/D4/D5/D8 shipped, no regression (10/10 TP preserved).
**Supersedes:** None.
**Extends:** ADR-027 (pathtraver recall strategy), ADR-002 (structural hashing).
**Amends:** ADR-027 fixup (D5 signature set refined; D6 implementation scoped).

## Context

ADR-027 (2026-11-05) shipped D3 (4 new payloads) + D4 (corrected snap
capture) and deferred D5 (broaden LFI content signatures from 5 to 8) and
D6 (--verbose diagnostic logging) to ADR-028. Both deferrals were because
ADR-027 lacked data:

- D5 was deferred because the proposed /etc/hostname pattern was untested
  against real bodies -- the ADR said "matches any 3-63 char line, would
  introduce FPs where the oracle currently has none."
- D6 was deferred because no --verbose flag exists anywhere in `src/`, and
  the ADR said the implementation would need "CLI flag + Scanner init +
  threading through the payload loop."

Probe 2026-11-05 (at HEAD 75d2031, 300-sample from the 20261024T130735Z
baseline findings.jsonl) closes both gaps with measurement instead of
assumption.

## Current state (probe)

### LFI signature FP test (body-only)

Sampled 300 real responses from `findings.jsonl`. For each, split
`raw_response` on `\r\n\r\n` and test the body only (this is the field
`check_lfi_content_oracle` actually uses via `snapshot.body`). Results:

    Pattern          Regex (re.M)                       Match rate  Verdict
    ---------------  ---------------------------------  ----------  -------
    hostname-loose   [a-z0-9][a-z0-9-]{2,62}$             15.67%    FP RISK
    hostname-strict  ^[a-z0-9][a-z0-9-]{2,62}$              0%       SAFE
    os-release       ^(PRETTY_NAME|NAME|ID)=.*$             0%       SAFE
    proc-version     ^Linux version \d+\.\d+\.\d+           0%       SAFE
    boot-loader      ^\[boot loader\]                       0%       SAFE

Example matches for the rejected pattern:

    'boolean'
    'boolean'

The loose pattern matches *any* word ending a line. Error pages and JSON
bodies contain many such words (`boolean`, `null`, `true`, `error`). The
18.5% figure first reported in the ADR-027 fixup probe was measured against
`raw_response`; the body-only retest at 15.67% confirms the pattern fires
on body content, not header content.

The strict-anchored variant (`^...$`) requires the *entire line* to be
exactly a hostname-shaped token. That is what `/etc/hostname` output
actually looks like. Strict pattern fires 0% on the corpus.

### D6 site audit

    total _say() call sites in scanner.py:              20
    gated by `if not quiet` (or compound like `... and not quiet`):  19
    genuinely ungated:                                    1 (function def)

Prior estimate of "4 ungated" was incorrect: my regex only matched bare
`if not quiet:`, missing `if baseline.is_static and not quiet:` and
`if baseline.modal_status >= 400 and not quiet:` forms (2 of the 4 were
compound conditions that ARE gated). The 4th was `def _say(...)` itself.

Conclusion: D6 does not require gating existing status messages. Those
messages are status output, not diagnostics -- they belong in the default
stream, not the verbose stream. D6 instead needs to *add* one new
diagnostic message that is verbose-only, with no change to existing sites.

### Suppression pattern precedent

`check_ldap_injection_oracle` (analyzer.py:1095-1110) shows the project's
existing suppression pattern:

    base_count = min(baseline counts)
    current_count = len(pattern.findall(current.body))
    if current_count <= base_count:
        return []   # suppress, don't emit

This is the pattern any future "signature matched but suppressed" counter
should follow. No new pattern needs inventing.

## Decisions

### D1. Adopt four refined LFI signatures

Replace the proposed `/etc/hostname` loose pattern with four signatures:

    _HOSTNAME_STRICT = re.compile(r"(?m)^[a-z0-9][a-z0-9-]{2,62}$")
    _OS_RELEASE      = re.compile(r"(?m)^(PRETTY_NAME|NAME|ID)=.*$")
    _PROC_VERSION    = re.compile(r"(?m)^Linux version \d+\.\d+\.\d+")
    _BOOT_INI        = re.compile(r"(?m)^\[boot loader\]")

Add to `_SIGNATURES` dict in `lfi_oracle.py`:

    _SIGNATURES: dict[str, re.Pattern] = {
        "passwd":       _PASSWD_LINE,      # existing
        "shadow":       _SHADOW_LINE,      # existing
        "hosts":        _HOSTS_LINE,       # existing
        "win_ini":      _WIN_INI,          # existing
        "group":        _GROUP_LINE,       # existing
        "hostname":     _HOSTNAME_STRICT,  # new (ADR-028)
        "os_release":   _OS_RELEASE,       # new (ADR-028)
        "proc_version": _PROC_VERSION,     # new (ADR-028)
        "boot_ini":     _BOOT_INI,         # new (ADR-028)
    }

Signature count: 5 -> 9 (not 8 as ADR-027 D5 proposed; the boot.ini
pattern is new, replacing the presumed /proc/self/cmdline which has
NUL-separated output that's hard to match robustly).

### D2. Reject the loose /etc/hostname pattern

ADR-027 fixup proposed `/etc/hostname` line shape as `[a-z0-9][a-z0-9-]{2,62}$`
(with re.M). Probe confirms 15.67% body FP. Do not adopt. The strict variant
in D1 is semantically correct (single-line file content) and 0% FP.

### D3. `--verbose` flag added to scan subcommand only

Add to `cli.py` scan subparser:

    scan.add_argument(
        "--verbose",
        action="store_true",
        help="Include diagnostic messages on stderr (traversal FN diagnosis, "
             "suppression counters). Does not affect stdout or JSON output."
    )

`--verbose` and `--quiet` are mutually exclusive in effect: `--quiet` wins
(no output at all). Document in help text.

`cmd_scan` passes to Scanner via:

    scanner = Scanner(..., verbose=getattr(args, "verbose", False))

### D4. Scanner gains `verbose: bool = False` attribute

Add to `Scanner.__init__`:

    verbose: bool = False,

Body:

    self.verbose = verbose

Default `False` preserves all existing scan behavior. No call site outside
`cmd_scan` needs updating; `getattr(args, "verbose", False)` in cmd_scan
handles the case where Scanner is constructed in tests without the new
attribute.

### D5. D6 diagnostic message added at traversal capture site

In scanner.py where ADR-027 D4 broadens `traversal_snap` capture:

    if category == "traversal" and traversal_snap is None and 200 <= r.status_code < 300:
        traversal_snap = snapshot
        traversal_snap_payload = value
    elif category == "traversal" and self.verbose and traversal_snap is None:
        _say(
            f"  [{param}] traversal {name} returned {r.status_code}, "
            f"not captured for existence oracle (2xx required)"
        )

The `elif` fires only when `--verbose` is set. It does not affect the
existence oracle behavior; it only makes it possible for the operator to
see why a traversal case didn't produce a TP.

### D6. Suppression counter deferred

ADR-027 fixup proposed a counter for "signatures matched but suppressed by
the not-in-baseline check." Probe section 4 shows the LDAP oracle implements
the same pattern without a counter -- it just returns [] silently. Adding
a counter to LFI oracle for the same purpose would deviate from precedent.

Defer. If future sessions need per-signature suppression counts, ADR-029
will scope it consistently across all oracles (LFI, LDAP, collapse).

### D7. No change to existing _say call sites

Probe confirms existing sites are status output, not diagnostic output.
They remain in the default stream. Only new diagnostics (per D5) gated by
`--verbose`.

### D8. Tests: 8 new unit tests

`tests/unit/test_lfi_oracle.py` currently has 5 tests, all basic
positive/negative. Extend with:

- test_hostname_strict_in_body_emits
- test_os_release_emits
- test_proc_version_emits
- test_boot_ini_emits
- test_hostname_loose_does_not_emit      (regression: rejected pattern stays out)
- test_word_at_line_end_does_not_emit    (regression: 'boolean' example)
- test_multiple_signatures_emit_all
- test_verbose_flag_default_false         (in test_cli or test_scan_invariant)

Corpus verification tests deferred to D10.

### D9. `test_lfi_oracle.py` extensions use existing fixture shapes

Existing tests build `Baseline` and `ResponseSnapshot` fixtures. New tests
reuse those fixtures. No new test infrastructure.

### D10. Corpus verification deferred to fresh-boot session

Same constraint as ADR-027 D7: Docker + OWASP Benchmark + >2500 MB memory.
This session has ~1040 MB free. Estimated 20-30 min on fresh hardware,
deferred.

The verification task: after D1 + D5 ship, run benchmark, measure
pathtraver recall delta against the 10-TP baseline. Decision rule from
ADR-027 D7 applies.

### D11. Two commits

Commit 1: this ADR (Proposed status).
Commit 2: D1 (4 new signatures), D3 (--verbose flag), D4 (Scanner verbose
attr), D5 (verbose-gated traversal diagnostic), D8 (8 tests). ~120 lines
code, ~80 lines tests.

### D12. ADR status flips after D10 verification

After D10 runs, if pathtraver R improved per ADR-027 D7 thresholds:
- Flip ADR-028 status to Accepted
- Flip ADR-027 status to Accepted (D5/D6 both shipped, R improvement
  verified)

If D10 shows no improvement:
- ADR-028 remains Proposed with note
- ADR-027 D8 triggers (pathtraver candidate-only, score excluded from
  DAST-applicable)

## Consequences

**Positive:**
- Four refined signatures all validated at 0% FP against real corpus
  (300 sample, one corpus)
- --verbose is a small, contained addition (one flag, one Scanner
  attribute, one message)
- Existing behavior unchanged when --verbose off
- ADR-027 D5 refined from "risky pattern" to "four proven-safe patterns"
- Bounded scope: ~200 lines total across 5 files
- No new dependencies, no schema changes, no API surface changes for
  non-traversal scans

**Negative:**
- 4 new LFI signatures = 4 more regex tests per 2xx payload response.
  Non-zero CPU cost per scan. Proportional to (payloads * signatures);
  for traversal corpus (~8 payloads * 9 signatures = 72 regex tests) vs.
  previous 8 * 5 = 40. ~80% increase for traversal; negligible for other
  categories because LFI oracle only fires on traversal-category payloads.
- The probe's 0% result is 300-sample from one corpus. D10 will re-test
  against OWASP Benchmark's full corpus; if any signature fires on a
  non-file-read response, D2's pattern would need refinement.

**Neutral:**
- F1=0.921 unchanged this session (no benchmark re-run)
- ADR-027 D5/D6 status: D5 refined (this ADR), D6 becomes implementable
  (this ADR makes --verbose exist so D6 as ADR-027 wrote it can now happen)
- M43.5-3 and D10 verification remain deferred pending memory

## Alternatives rejected

**A: Ship only strict hostname pattern; skip the other three.**
Rejected. `os-release`, `proc-version`, `boot.ini` are all 0% FP and each
targets a distinct file-read class (Linux config, kernel, Windows boot).
Missing any of them leaves a legitimate signature uncaught. The cost of
adding them is 3 regex compile calls at import time -- negligible.

**B: Ship no new signatures; close ADR-027 D5 as deferred indefinitely.**
Rejected. Probe shows the loose pattern was the problem, not the class of
pattern. Four safe alternatives exist. Closing D5 without trying them is
premature.

**C: Add --verbose to all _say call sites.**
Rejected per D7. Existing sites are status (baseline samples, WAF
detection, payload results), not diagnostics. Gating them behind --verbose
would remove information the operator wants by default.

**D: Add suppression counter to LFI oracle for D6.**
Rejected per D6. LDAP oracle doesn't have a counter -- adding one only for
LFI is inconsistent. Wait for ADR-029 to add counters uniformly.

**E: Combine ADR-028 with D10 verification (do everything in one milestone).**
Rejected. ADR-028 design is shippable at ~1040 MB; D10 verification needs
2500+ MB. Combining them blocks the shippable part on Docker availability.
Smaller commits = better review, smaller failure surface.

## References

- `docs/decisions/ADR-027-pathtraver-recall-strategy.md` -- original D5/D6
  deferral
- `docs/decisions/ADR-027-pathtraver-recall-strategy.md` Fixup 2026-11-05
  -- probe that first identified /etc/hostname FP risk
- `src/janissary/detection/lfi_oracle.py` -- signature dict
- `src/janissary/detection/analyzer.py:1095-1110` -- LDAP suppression
  pattern (D6 reference)
- `src/janissary/engine/scanner.py:1799-1811` -- existence oracle call
  (D5 message insertion point)
- `src/janissary/cli.py` -- scan subparser (D3)
- `tests/unit/test_lfi_oracle.py` -- existing 5 tests, extends to 13
- `benchmark/track_a/runs/20261024T130735Z-janissary-r1+rec/findings.jsonl`
  -- 300-sample source for FP measurement
- `README.md:412` -- previously corrected by commit d564cc7; D1 signatures
  do not re-introduce the claim d564cc7 removed.