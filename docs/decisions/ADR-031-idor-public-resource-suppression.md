# ADR-031 — IDOR public-resource suppression: triage as the control

**Status:** Accepted (2026-11-14)
**Parent:** ADR-024 (IDOR candidate probe), ADR-016 (verified/discovery vocabulary)
**Backlog:** JAN-L06b
**Scope:** Decision only. No code in this ADR.

## Problem

IDOR candidate detection (`--idor`, M42, ADR-024) requires two identities and emits `unproven` candidates. `is_idor_candidate` (`src/janissary/detection/idor.py:79`) compares A-status, B-status, and body equality-or-5pct-length only. It carries no public/private resource signal, so a 200/200 matching-body response emits an `unproven` candidate whether the resource is legitimately public or an IDOR.

`test_run_idor_public_resource_shape_emits_unproven_not_verified` (`91e9281`) pins this behaviour: the detector reports and defers to analyst triage. JAN-L06b asks whether that deferral is the intended control or a gap to be closed by suppressing public resources before emission.

Three designs were considered:

1. **`public_resources` pattern list** on the target spec, checked before emission. Requires per-target configuration; misses undeclared public resources; trades false negatives for fewer false positives.
2. **Response-header heuristic** (`Cache-Control: public`, absent `Vary`). Requires no configuration; spoofable; trades false positives for false negatives and would be wrong in both directions on some targets.
3. **No code change** — analyst triage is the intended control, documented as such.

## Decision

Adopt option (iii). IDOR candidate detection remains candidate-only and `unproven`. Public resources surface as candidates and are resolved by analyst triage. No suppression heuristic is added.

## Consequences

- The `unproven` boundary stays honest: the detector never claims certainty it does not have.
- Public resources appear as candidates and cost triage time. This is the accepted cost, not an unmeasured side effect.
- Options (i) and (ii) remain available if triage volume becomes a measured problem on a specific target. Neither is foreclosed; this ADR records the current decision, not a permanent prohibition.
- The five authorisation-boundary integration tests (`91e9281`) continue to pin the emission shape and remain the contract.

## Alternatives rejected

- **(i) and (ii)**: both introduce a heuristic that is wrong in one direction on some inputs, replacing an honest `unproven` with an unverifiable suppression. Without a measured triage-volume problem to solve, the trade is not justified. A suppression that is wrong in either direction is worse than the honest `unproven` boundary.
- **Deferring the decision**: JAN-L06b's closure criterion is a recorded design decision. Leaving it unrecorded keeps L06b open indefinitely and leaves the `unproven` behaviour undocumented as intent.