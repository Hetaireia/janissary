# ADR-004 — Structural arming and root signature

**Status:** Accepted (2026-10-25). Phase 1.3b.
**Supersedes:** the "currently 5" sample-size figure in ADR-002 §"Integration point: baseline phase".
**Depends on:** ADR-002 (DOM structural hashing), ADR-001 (benchmark methodology).

## Context

ADR-002 establishes a SimHash-based structural corroborator. Phase 1.3a shipped
the primitives (`engine/dom_hash.py`); Phase 1.3b ships the arming logic that
decides, per target, whether the gate is active. Three points in ADR-002 were
underspecified and must be pinned before 1.3b code is written:

1. **Sample size.** ADR-002 says "N baseline requests (currently 5,
   `--baseline-count 5`)". The code (`Scanner.baseline_count = 10`, floor 3 via
   `max(3, baseline_count)`) uses a different default and a different name.
2. **Root signature canonicalization.** ADR-002 says "SHA-256 of the first 4 KB
   of the canonicalized root page body" without defining "canonicalized" or
   "root".
3. **Disabled-gate behaviour.** ADR-002 says "A disabled gate defaults to
   today's behaviour; it does not block the scan." The exact contract — what
   "today's behaviour" means once 1.3c wires the gate in — must be recorded.

## Decision

### D1. Reuse baseline snapshots in place; add zero requests

Arming consumes `Baseline.snapshots` exactly as `Scanner.collect_baseline`
already produces them. No parallel baseline pass.

- Preserves the three `assert len(scanner._recorded_calls) == scanner.baseline_count`
  assertions in `tests/unit/test_scanner_baseline.py` at :76, :88, :104.
- Avoids doubling baseline-phase time.
- Fixes the arming sample size at whatever `baseline_count` produces (default 10,
  floor 3). The stale "5" in ADR-002 is superseded.

### D2. Minimum arming sample size = 3

Matches the existing `Scanner.baseline_count` floor. Fewer than 3 HTML samples
cannot distinguish "structurally stable" from "lucky coincidence". Conservative
by construction (ADR-002 §Success criteria: "Precision wins ties").

### D3. Root signature canonicalization = `normalize_body`, truncated to 4 KB

    root_signature = sha256(
        normalize_body(body).encode("utf-8", errors="ignore")[:4096]
    ).hexdigest()

`normalize_body` is the existing canonicalizer that already backs
`ResponseSnapshot.fingerprint` and `Baseline.is_stable_body`. Reusing it:

- Keeps one definition of "canonical body" in the codebase.
- Preserves reflected parameter values (ADR-002 §Combined signal requirement:
  "contains the injected parameter value reflected in text"). This is a hard
  requirement for 1.3c's discard path.
- Truncation to 4096 **bytes** is applied **after** normalization.

A regression test (`test_root_signature_changes_when_reflected_value_changes`)
fails if a future `normalize_body` change over-strips reflected content. That
failure blocks 1.3c.

### D4. Root sample selection = unique mode of `.fingerprint`

Among HTML baseline samples, take the mode of `ResponseSnapshot.fingerprint`
(SHA-256 of normalized body). If exactly one fingerprint appears ≥ 2 times, use
the first snapshot with that fingerprint as the root sample. If no unique mode
exists (all distinct, or top-two tie), `root_signature = None`.

`root_signature = None` **does not unarm the gate.** It only denies the 1.3c
discard path for that target. A target can be `armed=True, root_signature=None`
(structurally stable, textually unstable) and the gate behaves as
"structurally close ⇒ still emit" without a text cross-check.

### D5. Disabled gate = pass-through (contract for 1.3c)

When `armed == False`, 1.3c must produce output **identical** to pre-1.3b
behaviour: no suppression, no path redirection, no additional findings. This is
enforced in 1.3c by a regression test that diffs `armed=False` runs against a
pre-1.3b reference artifact.

In 1.3b this contract is vacuously satisfied: `scanner.py` is not modified, and
`baseline_struct.compute_arming_state` has no production callers.

### D6. Arming predicate

Given HTML baseline samples:

| Condition (checked top-to-bottom)         | `reason`                     | `armed` |
|-------------------------------------------|------------------------------|---------|
| 0 HTML samples                            | `UNARMED_NO_HTML_SAMPLES`    | False   |
| 1 or 2 HTML samples                       | `UNARMED_INSUFFICIENT_SAMPLES`| False  |
| Any sample has `shingle_count == 0`       | `UNARMED_EMPTY_SKELETON`     | False   |
| Max pairwise Hamming > 3                  | `UNARMED_DISPERSION`         | False   |
| Otherwise                                 | `ARMED`                      | True    |

- "HTML sample" means `content_type` media type is `text/html`
  (parameters stripped, lowercased; `text/html; charset=UTF-8` matches).
- Hamming distance uses `dom_hash.hamming` on 64-bit SimHash values.
- `root_signature` is populated per D4 independently of `armed`.

**Note on `UNARMED_EMPTY_SKELETON`.** Lexbor's HTML5 parser auto-inserts
`html`, `head`, and `body` for any input string, so `shingle_count == 0` is
unreachable via valid HTML — the smallest possible skeleton is
`["html", "head", "body"]` (3 tokens → 1 shingle). This check is therefore
**defensive**: it fires only if `extract_skeleton` ever returns fewer than
`SHINGLE_SIZE` tokens (empty input, or a future change to `SHINGLE_SIZE` /
`extract_skeleton`). The test path uses a monkeypatched `dom_fingerprint`
returning `StructuralFingerprint(shingle_count=0)` directly, since no HTML
fixture can trigger it. Documented here so future maintainers do not
mistake the guard for dead code.

## Consequences

- **1.3b** ships `engine/baseline_struct.py` with `compute_arming_state`,
  `BaselineArmingState`, `ArmingReason`. 15 unit tests. No `scanner.py` change.
  Test count: 458 → 473.
- **1.3c** wires `compute_arming_state` into `scan()` (one call per parameter
  after `collect_baseline`), adds an `arming` field to `ScanSummary`, and adds
  the mandatory 3-run F1 rerun per handover §7.
- **1.3d** consumes `fingerprints` and `root_signature` for the `>20` collapse
  path.
- **1.3e** writes regression tests including the `armed=False` pass-through
  contract from D5.

## Alternatives considered and rejected

- **Parallel baseline pass at N=5.** Breaks the `_recorded_calls == baseline_count`
  asserts, doubles target load, and is not meaningfully more robust at N=5 vs N=10.
- **Root signature = SHA-256 of the first baseline body, unconditionally.**
  Fails to distinguish canonical from noise on rotating home pages.
- **Root signature = SHA-256 of the skeleton only.** Contradicts ADR-002
  §Combined signal requirement: the signature must change when reflected text
  changes.
- **Minimum sample size = 5.** Conflicts with `Scanner.baseline_count` floor of 3;
  unarming at N=4 discards usable signal.
- **Sub-amendment to ADR-002.** The decisions touch cross-cutting concerns
  (sample sizing, disabled-gate contract) referenced by 1.3c/1.3d/1.3e; a
  standalone ADR is the lighter-weight discovery surface.

## References

- ADR-002 §"Integration point: baseline phase"
- ADR-002 §"Combined signal requirement"
- `src/janissary/detection/analyzer.py` (`ResponseSnapshot`, `Baseline`,
  `normalize_body`)
- `src/janissary/engine/scanner.py` (`collect_baseline`, `baseline_count`)
